import { DnsError, InvalidQueryError, NoServerError, TimeoutError } from '../errors';
import type { ServerFailure } from '../errors';
import {
  checkEdnsSettings,
  DEFAULT_RETRIES,
  DEFAULT_TIMEOUT,
  exchange,
  transportsFor,
} from '../exchange';
import type { ExchangeResult } from '../exchange';
import { classCode, RECORD_CLASSES } from '../protocol/classes';
import { DEFAULT_UDP_PAYLOAD_SIZE } from '../protocol/edns';
import { RCODES } from '../protocol/header';
import { typeCode, typeName } from '../protocol/types';
import { decodeRecords } from '../records/decode';
import type { DnsRecord, KnownRecordType, RecordOf } from '../records/types';
import type { Transports } from '../transports/index';
import { toEndpoint } from '../transports/endpoint';
import { now } from '../transports/runtime';
import { systemServers } from '../transports/system';
import type { OnEvent, Server, TransportOptions } from '../transports/types';
import { toHex } from '../wire/bytes';
import type { Message } from '../wire/message';
import { comparableName, toAsciiName } from '../wire/names';
import { dnssecResponse, requireEdns, Validator } from '../dnssec/validate';
import type { TrustAnchor } from '../dnssec/types';
import { aliasTarget, buildAnswer, matchingRecords, negativeLifetime } from './answer';
import type { Answer, QuerySettings } from './answer';
import { MAX_NEGATIVE_TTL, MAX_TTL, resolveCache } from './cache';
import type { Cache, CacheOption } from './cache';
import { createKeyedLimiter, createLimiter } from './limiter';
import type { KeyedLimiter, Limiter } from './limiter';

/** the options of a `Resolver`. The query settings among them can also be given to one `query()` */
export interface ResolverOptions extends TransportOptions, QuerySettings {
  /**
   * the resolvers to ask, in order of preference. Default: the ones this machine is set
   * up to use, where the runtime can read them
   */
  servers?: readonly (string | Server)[];
  /**
   * false for no cache, a cache of your own, or settings for the default one (1000
   * entries)
   */
  cache?: CacheOption<CachedResponse>;
  /** how many queries may be in flight at once, to all servers together. Default: no limit */
  concurrency?: number;
  /**
   * how many queries may be in flight to one server at once. Default 16; Infinity for no
   * limit
   */
  serverConcurrency?: number;
  /**
   * how long one answer may take altogether, in milliseconds, every server, attempt and
   * TCP fallback included, and time spent waiting for a turn under `concurrency` or
   * `serverConcurrency`. With `validate`, the queries for the chain share it with the
   * data. Default 10000
   */
  totalTimeout?: number;
  /**
   * malformed record data is an error. By default such a record comes back in the
   * generic form
   */
  strict?: boolean;
  /** told of every exchange, retry, fallback to TCP and proxy connection, as it happens */
  onEvent?: OnEvent;
  /**
   * sockets and connections to share with other resolvers. The resolver does not close
   * a set it was given
   */
  transports?: Transports;
  /**
   * check each answer's DNSSEC chain from the trust anchors down, and say what came of it
   * in `answer.security`. Queries are then sent with DO and CD set, so the answer's
   * `answers` holds its signatures too. Default false
   */
  validate?: boolean;
  /** the trust anchors validation starts from. Default: IANA's root trust anchors */
  trustAnchors?: readonly TrustAnchor[];
}

/** what one `Resolver.query()` takes: the query settings, for this query alone, and these */
export interface ResolverQueryOptions extends QuerySettings {
  /**
   * ask this server and no other, for this query only. The answer is not taken from the
   * cache or put in it
   */
  server?: string | Server;
  /** in place of the resolver's `totalTimeout`, for this query */
  totalTimeout?: number;
  /** abandons the query when aborted; it rejects with the signal's reason */
  signal?: AbortSignal;
}

/** what the cache holds: a response, and when it arrived */
export interface CachedResponse {
  result: ExchangeResult;
  attempts: number;
  receivedAt: Date;
}

// queries in flight to one server at once
const DEFAULT_SERVER_CONCURRENCY = 16;
// how long one answer may take altogether
const DEFAULT_TOTAL_TIMEOUT = 10_000;
// the longest a timer can be set for; anything longer fires at once
const MAX_TIMER = 2_147_483_647;
// a response that says the server could not or would not do the work: another may
const TRY_NEXT = new Set<number>([RCODES.SERVFAIL, RCODES.NOTIMP, RCODES.REFUSED]);

// how long a response may be cached, in seconds. Zero for one that should not be
export function cacheLifetime(message: Message): number {
  if (message.flags.tc) return 0;
  if (message.rcode !== RCODES.NOERROR && message.rcode !== RCODES.NXDOMAIN) return 0;
  const answers = decodeRecords(message.answers);
  const [question] = message.questions;
  if (message.rcode === RCODES.NOERROR && answers.length > 0) {
    // records that answer the question: they live as long as the shortest TTL. Only an
    // alias chain, with nothing of the type at its end, is a negative answer as well
    const answered =
      !question || matchingRecords(question.name, typeName(question.type), answers).length > 0;
    if (answered) return Math.min(...answers.map(record => record.ttl));
  }
  if (!question) return 0;
  // a negative answer lives as long as the answer's `negativeTtl` says, and at most an hour;
  // with no SOA for the name there is nothing to say how long
  const authorities = decodeRecords(message.authorities.filter(record => record.type === 6));
  const lifetime = negativeLifetime(aliasTarget(question.name, answers), answers, authorities);
  return Math.min(lifetime ?? 0, MAX_NEGATIVE_TTL);
}

/**
 * the ordinary resolver: it asks recursive resolvers, the way `dig` and `node:dns` do. On top of a
 * single query it adds what a program that resolves names all day wants: several servers with
 * failover, a cache that honours TTLs, and one query on the wire for any number of callers asking
 * the same thing at the same moment
 *
 * Without `servers` it asks the ones this machine is set up to use. See docs/resolvers.md.
 */
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
    checkEdnsSettings(options);
    // a server that cannot be read is refused now: on a query it would stop the failover
    // to the servers after it
    for (const server of options.servers ?? []) {
      toEndpoint(server, options.transport ?? 'udp', options.port);
    }
    this.options = options;
    this.cache = resolveCache(options.cache);
    this.limit = createLimiter(options.concurrency ?? Infinity);
    this.limitServer = createKeyedLimiter(options.serverConcurrency ?? DEFAULT_SERVER_CONCURRENCY);
    const { transports, owned } = transportsFor(options);
    this.transports = transports;
    this.ownsTransports = owned;
    if (options.validate) {
      requireEdns(options.edns);
      this.validator = new Validator({
        trustAnchors: options.trustAnchors,
        ...(options.cache === false && { maxZones: 0 }),
      });
    }
  }

  /**
   * ask a question. The answer carries the response code, so a name that does not exist
   * or has no records of the type is an answer with nothing in `records`, not an error.
   * An error means no usable response arrived at all
   */
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
    checkEdnsSettings(options, this.options);
    if (!this.validator) return this.lookup(name, type, options);
    requireEdns(options.edns);
    // one deadline for the data and the chain together
    const totalTimeout =
      options.totalTimeout ?? this.options.totalTimeout ?? this.defaultTotalTimeout(options);
    const deadline = now() + totalTimeout;
    // the data and every record of the chain are asked for with their signatures, and with
    // Checking Disabled, so a validating resolver upstream hands over what is broken
    // instead of answering SERVFAIL
    const dnssec = { dnssecOk: true, checkingDisabled: true };
    const answer = await this.lookup(name, type, { ...options, ...dnssec, totalTimeout });
    // a server asked to recurse owes the whole answer, the target of every alias included
    const recursive = (options.recursionDesired ?? this.options.recursionDesired) !== false;
    // the chain goes where the data query went, the same way: the same server, transport,
    // port, timeouts and EDNS settings, with header flags of its own
    const {
      recursionDesired: _recursionDesired,
      authenticData: _authenticData,
      ...sameWay
    } = options;
    // the chain gets what the data left. When that runs out, the query times out as one
    // whose data took too long does, as it does with the caller's own abort
    const budget = new AbortController();
    const timedOut = () => budget.abort(totalTimeoutError(name, type, totalTimeout));
    const forward = () => budget.abort(options.signal?.reason);
    if (options.signal?.aborted) forward();
    else options.signal?.addEventListener('abort', forward, { once: true });
    const left = deadline - now();
    if (left <= 0) timedOut();
    const timer = left > 0 && left <= MAX_TIMER ? setTimeout(timedOut, left) : undefined;
    try {
      answer.security = await this.validator.validate(
        [{ ...dnssecResponse(answer.message, answer.query.name, typeCode(type)), recursive }],
        async (chainName, chainType) => {
          if (budget.signal.aborted) throw budget.signal.reason;
          try {
            const chainOptions = {
              ...sameWay,
              ...dnssec,
              totalTimeout: Math.max(1, deadline - now()),
            };
            return (await this.lookup(chainName, chainType, chainOptions)).message;
          } catch (error) {
            // running out of time always rejects the query, never leaves a link undecided
            if (!budget.signal.aborted && now() >= deadline) timedOut();
            if (budget.signal.aborted) throw budget.signal.reason;
            throw error;
          }
        },
        budget.signal
      );
    } finally {
      clearTimeout(timer);
      options.signal?.removeEventListener('abort', forward);
    }
    return answer;
  }

  /** forget every cached answer and every zone validation has judged */
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
    const { server, signal, totalTimeout: perQuery, ...settings } = options;
    const totalTimeout =
      perQuery ?? this.options.totalTimeout ?? this.defaultTotalTimeout(settings);

    if (server !== undefined) {
      const started = now();
      const result = await this.ask(name, type, [server], settings, signal, totalTimeout);
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
    const response = await this.shared(name, type, key, settings, signal, totalTimeout);
    return buildAnswer(response.result, {
      strict,
      attempts: response.attempts,
      elapsed: now() - started,
      timestamp: new Date(response.receivedAt),
    });
  }

  /**
   * close the sockets and connections this resolver opened, and empty its cache. A
   * resolver that shares the process-wide set, or was given one, leaves it open
   */
  close(): void {
    this.clearCache();
    if (this.ownsTransports) this.transports.close();
  }

  // ---- inside

  // callers asking the same thing at the same moment share one query. One that brings a
  // signal asks for itself, so that aborting it stops only its own. One that joins gives up
  // at its own deadline, and when the shared query runs out of time before that, joins or
  // starts the next shared query with what is left of its own
  private shared(
    name: string,
    type: string | number,
    key: string | undefined,
    settings: QuerySettings,
    signal: AbortSignal | undefined,
    totalTimeout: number
  ): Promise<CachedResponse> {
    const deadline = now() + totalTimeout;
    const joined = key && !signal ? this.inFlight.get(key) : undefined;
    if (joined) {
      const rest = (error: unknown) => {
        const left = deadline - now();
        if (!(error instanceof TimeoutError) || left <= 0) throw error;
        return this.shared(name, type, key, settings, signal, left);
      };
      return withinDeadline(joined.catch(rest), deadline, () =>
        totalTimeoutError(name, type, totalTimeout)
      );
    }
    const pending = this.servers().then(servers =>
      this.ask(name, type, servers, settings, signal, totalTimeout)
    );
    if (key && !signal) {
      this.inFlight.set(key, pending);
      const forget = () => {
        if (this.inFlight.get(key) === pending) this.inFlight.delete(key);
      };
      pending.then(forget, forget);
    }
    if (key && this.cache) {
      const { cache } = this;
      pending.then(
        response => {
          const lifetime = Math.min(cacheLifetime(response.result.message), MAX_TTL);
          if (lifetime > 0) cache.set(key, response, lifetime * 1000);
        },
        () => undefined
      );
    }
    return pending;
  }

  // the budget of a query that sets none: ten seconds, or, where a timeout or retries is
  // set, as long as one server's attempts take, so a default never cuts them short
  private defaultTotalTimeout(settings: QuerySettings): number {
    const merged = { ...this.options, ...settings };
    if (merged.timeout === undefined && merged.retries === undefined) return DEFAULT_TOTAL_TIMEOUT;
    return Math.max(
      DEFAULT_TOTAL_TIMEOUT,
      (merged.timeout ?? DEFAULT_TIMEOUT) * ((merged.retries ?? DEFAULT_RETRIES) + 1)
    );
  }

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

  // ask the servers until one gives a usable response. One server is asked as `exchange`
  // asks, its retries sent again from the same socket so that a late answer to an earlier
  // copy still counts. Several are asked a round at a time: each once, in order, before
  // any is asked again, as glibc and c-ares do, so a dead first server costs one timeout,
  // not all of them. All of it within `totalTimeout`
  private async ask(
    name: string,
    type: string | number,
    servers: readonly (string | Server)[],
    settings: QuerySettings,
    signal: AbortSignal | undefined,
    totalTimeout: number
  ): Promise<CachedResponse> {
    const merged = { ...this.options, ...settings };
    const deadline = now() + totalTimeout;
    const wait = { signal, deadline, expired: () => totalTimeoutError(name, type, totalTimeout) };
    const single = servers.length === 1;
    // with somewhere else to turn, less patience with any one server
    const rounds = single ? 1 : (merged.retries ?? 1) + 1;
    let attempts = 0;
    let lastResult: ExchangeResult | undefined;
    let lastError: DnsError | undefined;
    const failures: ServerFailure[] = [];
    // the servers still worth asking: not those that answered, or failed in a way that
    // asking again will not mend
    let left = [...servers];

    rounds: for (let round = 0; round < rounds && left.length > 0; round++) {
      for (const server of left) {
        if (now() >= deadline) break rounds;
        try {
          const result = await this.limit(
            () =>
              this.limitServer(
                serverKey(server),
                () =>
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
                    totalTimeout: Math.max(1, deadline - now()),
                    tcpFallback: merged.tcpFallback,
                    ...(single
                      ? merged.retries !== undefined && { retries: merged.retries }
                      : { retries: 0 }),
                    transports: this.transports,
                    onEvent: this.options.onEvent,
                    signal,
                  }),
                wait
              ),
            wait
          );
          attempts += result.attempts;
          if (!TRY_NEXT.has(result.message.rcode)) {
            return { result, attempts, receivedAt: new Date() };
          }
          lastResult = result;
          left = left.filter(other => other !== server);
        } catch (error) {
          // a question that cannot be asked will not get better elsewhere, and neither
          // will one the caller has given up on
          if (
            signal?.aborted ||
            !(error instanceof DnsError) ||
            error instanceof InvalidQueryError
          ) {
            throw error;
          }
          failures.push({ server: error.server ?? serverKey(server), error });
          lastError = error;
          if (!error.retryable) left = left.filter(other => other !== server);
        }
      }
    }
    // every server failed: the last response says more than the last error does
    if (lastResult) return { result: lastResult, attempts, receivedAt: new Date() };
    const error =
      lastError ?? (now() >= deadline ? totalTimeoutError(name, type, totalTimeout) : undefined);
    if (error) {
      error.failures ??= failures;
      throw error;
    }
    throw new NoServerError('No DNS servers to ask');
  }
}

// the error for a query that ran out of its `totalTimeout`
function totalTimeoutError(
  name: string,
  type: string | number,
  totalTimeout: number
): TimeoutError {
  const typeText = typeName(typeCode(type));
  return new TimeoutError(`No answer for ${name} ${typeText} within ${totalTimeout} ms`, {
    query: name,
    type: typeText,
  });
}

// a shared query as one caller waits for it: rejected with `expired()` at the caller's
// deadline, while the query itself goes on for the others
function withinDeadline<T>(work: Promise<T>, deadline: number, expired: () => Error): Promise<T> {
  const left = deadline - now();
  if (left > MAX_TIMER) return work;
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(expired()), Math.max(0, left));
    work.then(
      value => {
        clearTimeout(timer);
        resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timer);
        reject(error);
      }
    );
  });
}

// a server as the key its queries are counted under
function serverKey(server: string | Server): string {
  if (typeof server === 'string') return server;
  return (
    server.url ?? (server.port === undefined ? server.address : `${server.address}#${server.port}`)
  );
}
