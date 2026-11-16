import { DnsError, InvalidQueryError, NoServerError } from '../errors';
import type { ServerFailure } from '../errors';
import { exchange, hasTransportOptions } from '../exchange';
import type { ExchangeResult } from '../exchange';
import { classCode, RECORD_CLASSES } from '../protocol/classes';
import { DEFAULT_UDP_PAYLOAD_SIZE } from '../protocol/edns';
import { RCODES } from '../protocol/header';
import { typeCode } from '../protocol/types';
import { decodeRecords } from '../records/decode';
import type { DnsRecord, KnownRecordType, RecordOf } from '../records/types';
import { createTransports, defaultTransports } from '../transports/index';
import type { Transports } from '../transports/index';
import { now } from '../transports/runtime';
import { systemServers } from '../transports/system';
import type { OnEvent, Server, TransportOptions } from '../transports/types';
import { toHex } from '../wire/bytes';
import type { Message } from '../wire/message';
import { comparableName, toAsciiName } from '../wire/names';
import { dnssecResponse, Validator } from '../dnssec/validate';
import type { TrustAnchor } from '../dnssec/types';
import { buildAnswer } from './answer';
import type { Answer, QuerySettings } from './answer';
import { resolveCache } from './cache';
import type { Cache, CacheOption } from './cache';
import { createKeyedLimiter, createLimiter } from './limiter';
import type { KeyedLimiter, Limiter } from './limiter';

// the ordinary resolver: it asks recursive resolvers, the way `dig` and `node:dns` do.
// On top of a single query it adds what a program that resolves names all day wants:
// several servers with failover, a cache that honours TTLs, and one query on the wire
// for any number of callers asking the same thing at the same moment

export interface ResolverOptions extends TransportOptions, QuerySettings {
  // the resolvers to ask, in order of preference. Default: the ones this machine is set
  // up to use, where the runtime can read them
  servers?: readonly (string | Server)[];
  // false for no cache, a cache of your own, or settings for the default one (1000
  // entries)
  cache?: CacheOption<CachedResponse>;
  // the longest an answer is kept, in seconds, whatever its TTL says. Default one day
  maxTtl?: number;
  // how many queries may be in flight at once, to all servers together. Default: no limit
  concurrency?: number;
  // how many queries may be in flight to one server at once. Default 16; Infinity for no
  // limit
  serverConcurrency?: number;
  // malformed record data is an error. By default such a record comes back in the
  // generic form
  strict?: boolean;
  onEvent?: OnEvent;
  // sockets and connections to share with other resolvers. The resolver does not close
  // a set it was given
  transports?: Transports;
  // check each answer's DNSSEC chain from the trust anchors down, and say what came of it
  // in `answer.security`. Queries are then sent with DO and CD set, so the answer's
  // `answers` holds its signatures too. Default false
  validate?: boolean;
  // the trust anchors validation starts from. Default: IANA's root trust anchors
  trustAnchors?: readonly TrustAnchor[];
}

export interface ResolverQueryOptions extends QuerySettings {
  // ask this server and no other, for this query only. The answer is not taken from the
  // cache or put in it
  server?: string | Server;
  signal?: AbortSignal;
}

// what the cache holds: a response, and when it arrived
export interface CachedResponse {
  result: ExchangeResult;
  attempts: number;
  receivedAt: Date;
}

const DEFAULT_MAX_TTL = 86_400;
// queries in flight to one server at once
const DEFAULT_SERVER_CONCURRENCY = 16;
// a response that says the server could not or would not do the work: another may
const TRY_NEXT = new Set<number>([RCODES.SERVFAIL, RCODES.NOTIMP, RCODES.REFUSED]);

// how long a response may be cached, in seconds. Zero for one that should not be
export function cacheLifetime(message: Message): number {
  if (message.flags.tc) return 0;
  if (message.rcode === RCODES.NOERROR && message.answers.length > 0) {
    return Math.min(...message.answers.map(record => record.ttl));
  }
  if (message.rcode === RCODES.NOERROR || message.rcode === RCODES.NXDOMAIN) {
    // a negative answer lives for the smaller of the SOA's TTL and its minimum field
    // (RFC 2308 §5); with no SOA there is nothing to say how long
    const soa = decodeRecords(
      message.authorities.filter(record => record.type === 6),
      { lenient: true }
    ).find((record): record is Extract<DnsRecord, { type: 'SOA' }> => record.type === 'SOA');
    return soa ? Math.min(soa.ttl, soa.minimum) : 0;
  }
  return 0;
}

export class Resolver {
  private readonly options: ResolverOptions;
  private readonly cache: Cache<CachedResponse> | undefined;
  private readonly limit: Limiter;
  private readonly limitServer: KeyedLimiter;
  private readonly transports: Transports;
  private readonly ownsTransports: boolean;
  private readonly inFlight = new Map<string, Promise<CachedResponse>>();
  private system: Promise<string[]> | undefined;
  private readonly validator: Validator | undefined;

  constructor(options: ResolverOptions = {}) {
    this.options = options;
    this.cache = resolveCache(options.cache);
    this.limit = createLimiter(options.concurrency ?? Infinity);
    this.limitServer = createKeyedLimiter(options.serverConcurrency ?? DEFAULT_SERVER_CONCURRENCY);
    this.ownsTransports = !options.transports && hasTransportOptions(options);
    this.transports =
      options.transports ?? (this.ownsTransports ? createTransports(options) : defaultTransports());
    if (options.validate) {
      this.validator = new Validator({
        trustAnchors: options.trustAnchors,
        ...(options.cache === false && { maxZones: 0 }),
      });
    }
  }

  // ask a question. The answer carries the response code, so a name that does not exist
  // or has no records of the type is an answer with nothing in `records`, not an error.
  // An error means no usable response arrived at all
  query<Type extends KnownRecordType>(
    name: string,
    type: Type,
    options?: ResolverQueryOptions
  ): Promise<Answer<RecordOf<Type>>>;
  query(name: string, type: string | number, options?: ResolverQueryOptions): Promise<Answer>;
  async query(
    name: string,
    type: string | number,
    options: ResolverQueryOptions = {}
  ): Promise<Answer> {
    if (!this.validator) return this.lookup(name, type, options);
    // the data and every record of the chain are asked for with their signatures, and with
    // Checking Disabled, so a validating resolver upstream hands over what is broken
    // instead of answering SERVFAIL
    const dnssec = { dnssecOk: true, checkingDisabled: true };
    const answer = await this.lookup(name, type, { ...options, ...dnssec });
    // a server asked to recurse owes the whole answer, the target of every alias included
    const recursive = (options.recursionDesired ?? this.options.recursionDesired) !== false;
    answer.security = await this.validator.validate(
      [{ ...dnssecResponse(answer.message, answer.query.name, typeCode(type)), recursive }],
      async (chainName, chainType) =>
        (
          await this.lookup(chainName, chainType, {
            ...dnssec,
            ...(options.server !== undefined && { server: options.server }),
            signal: options.signal,
          })
        ).message
    );
    return answer;
  }

  // forget every cached answer and every zone validation has judged
  clearCache(): void {
    this.cache?.clear();
    this.validator?.clear();
  }

  private async lookup(
    name: string,
    type: string | number,
    options: ResolverQueryOptions
  ): Promise<Answer> {
    const { strict } = this.options;
    const { server, signal, ...settings } = options;

    if (server !== undefined) {
      const started = now();
      const result = await this.ask(name, type, [server], settings, signal);
      return buildAnswer(result.result, {
        strict,
        attempts: result.attempts,
        elapsed: now() - started,
      });
    }

    const key = this.cache || !signal ? this.keyFor(name, type, settings) : undefined;
    const cached = key ? this.cache?.get(key) : undefined;
    if (cached) {
      return buildAnswer(cached.result, {
        strict,
        cached: true,
        age: Math.floor((Date.now() - cached.receivedAt.getTime()) / 1000),
        elapsed: 0,
        attempts: 0,
        timestamp: new Date(cached.receivedAt),
      });
    }

    const started = now();
    // callers asking the same thing at the same moment share one query. One that brings
    // a signal asks for itself, so that aborting it stops only its own
    let pending = key && !signal ? this.inFlight.get(key) : undefined;
    if (!pending) {
      pending = this.servers().then(servers => this.ask(name, type, servers, settings, signal));
      if (key && !signal) {
        const shared = pending;
        this.inFlight.set(key, shared);
        const forget = () => {
          if (this.inFlight.get(key) === shared) this.inFlight.delete(key);
        };
        shared.then(forget, forget);
      }
      if (key && this.cache) {
        const { cache } = this;
        const maxTtl = this.options.maxTtl ?? DEFAULT_MAX_TTL;
        pending.then(
          response => {
            const lifetime = Math.min(cacheLifetime(response.result.message), maxTtl);
            if (lifetime > 0) cache.set(key, response, lifetime * 1000);
          },
          () => undefined
        );
      }
    }
    const response = await pending;
    return buildAnswer(response.result, {
      strict,
      attempts: response.attempts,
      elapsed: now() - started,
      timestamp: new Date(response.receivedAt),
    });
  }

  // close the sockets and connections this resolver opened, and empty its cache. A
  // resolver that shares the process-wide set, or was given one, leaves it open
  close(): void {
    this.clearCache();
    if (this.ownsTransports) this.transports.close();
  }

  // ---- inside

  // what makes two questions the same question: the name, the type and class, and the
  // settings that change what comes back. Those are the header flags, EDNS on or off with
  // its options and UDP payload size, whether a truncated UDP answer is asked again over
  // TCP, and the transport and port
  private keyFor(name: string, type: string | number, settings: QuerySettings): string | undefined {
    const merged = { ...this.options, ...settings };
    try {
      return [
        comparableName(toAsciiName(name)),
        typeCode(type),
        classCode(RECORD_CLASSES.IN),
        (merged.recursionDesired ?? true) ? 'rd' : '',
        merged.checkingDisabled ? 'cd' : '',
        merged.authenticData ? 'ad' : '',
        merged.dnssecOk ? 'do' : '',
        merged.edns === false ? 'noedns' : '',
        // options such as a client subnet change the answer as much as the name does
        (merged.ednsOptions ?? []).map(option => `${option.code}=${toHex(option.data)}`).join(','),
        // a smaller buffer can be truncated where a larger one is not
        merged.edns === false ? '' : (merged.udpPayloadSize ?? DEFAULT_UDP_PAYLOAD_SIZE),
        // without the fallback, a truncated UDP answer is what comes back
        merged.tcpFallback === false ? 'notcp' : '',
        merged.transport ?? '',
        merged.port ?? '',
      ].join('|');
    } catch {
      // not a question that can be asked: the query itself will say why
      return undefined;
    }
  }

  private servers(): Promise<readonly (string | Server)[]> {
    if (this.options.servers?.length) return Promise.resolve(this.options.servers);
    this.system ??= systemServers();
    return this.system.then(servers => {
      if (servers.length === 0) {
        throw new NoServerError(
          'No DNS servers to ask: none were given and this runtime has none to read'
        );
      }
      return servers;
    });
  }

  // ask each server in turn until one gives a usable response
  private async ask(
    name: string,
    type: string | number,
    servers: readonly (string | Server)[],
    settings: QuerySettings,
    signal: AbortSignal | undefined
  ): Promise<CachedResponse> {
    const merged = { ...this.options, ...settings };
    // with somewhere else to turn, less patience with any one server
    const retries = merged.retries ?? (servers.length > 1 ? 1 : undefined);
    let attempts = 0;
    let lastResult: ExchangeResult | undefined;
    let lastError: DnsError | undefined;
    const failures: ServerFailure[] = [];

    for (const [index, server] of servers.entries()) {
      const isLast = index === servers.length - 1;
      try {
        const result = await this.limit(() =>
          this.limitServer(serverKey(server), () =>
            exchange({ name, type }, server, {
              transport: merged.transport,
              port: merged.port,
              recursionDesired: merged.recursionDesired,
              checkingDisabled: merged.checkingDisabled,
              authenticData: merged.authenticData,
              dnssecOk: merged.dnssecOk,
              udpPayloadSize: merged.udpPayloadSize,
              ednsOptions: merged.ednsOptions,
              edns: merged.edns,
              timeout: merged.timeout,
              tcpFallback: merged.tcpFallback,
              ...(retries !== undefined && { retries }),
              transports: this.transports,
              onEvent: this.options.onEvent,
              signal,
            })
          )
        );
        attempts += result.attempts;
        if (!TRY_NEXT.has(result.message.rcode) || isLast) {
          return { result, attempts, receivedAt: new Date() };
        }
        lastResult = result;
      } catch (error) {
        // a question that cannot be asked will not get better elsewhere, and neither
        // will one the caller has given up on
        if (signal?.aborted || !(error instanceof DnsError) || error instanceof InvalidQueryError) {
          throw error;
        }
        failures.push({ server: error.server ?? serverKey(server), error });
        lastError = error;
      }
    }
    // every server failed: the last response says more than the last error does
    if (lastResult) return { result: lastResult, attempts, receivedAt: new Date() };
    if (lastError) {
      lastError.failures ??= failures;
      throw lastError;
    }
    throw new NoServerError('No DNS servers to ask');
  }
}

// a server as the key its queries are counted under
function serverKey(server: string | Server): string {
  if (typeof server === 'string') return server;
  return (
    server.url ?? (server.port === undefined ? server.address : `${server.address}#${server.port}`)
  );
}
