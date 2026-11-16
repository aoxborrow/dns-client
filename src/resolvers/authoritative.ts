import {
  DnsError,
  errorData,
  InvalidQueryError,
  InvalidResponseError,
  TimeoutError,
} from '../errors';
import type { ServerFailure } from '../errors';
import { exchange, hasTransportOptions, presentName } from '../exchange';
import type { ExchangeResult } from '../exchange';
import { RCODES, rcodeName } from '../protocol/header';
import { typeCode, typeName } from '../protocol/types';
import { decodeRecords } from '../records/decode';
import type { DnsRecord, KnownRecordType, RecordOf } from '../records/types';
import { isIp, isIpv4, isIpv6, normalizeAddress } from '../transports/endpoint';
import { createTransports, defaultTransports } from '../transports/index';
import type { Transports } from '../transports/index';
import { now } from '../transports/runtime';
import type { OnEvent, TransportOptions } from '../transports/types';
import { canonicalName, comparableName, isSubdomain, parentName, toAsciiName } from '../wire/names';
import { dnssecResponse, Validator } from '../dnssec/validate';
import type { DnssecResponse } from '../dnssec/judge';
import type { TrustAnchor } from '../dnssec/types';
import { aliasTarget, buildAnswer } from './answer';
import type { Answer, QuerySettings, TraceHop } from './answer';
import { createKeyedLimiter, createLimiter, createPacer } from './limiter';
import type { KeyedLimiter, Limiter } from './limiter';
import { ROOT_HINTS } from './root-hints';
import type { NameserverHint } from './root-hints';

// the resolver that asks nobody to resolve for it. It starts at the root servers and
// follows the referrals down, asking each zone's own nameservers, until one of them
// answers with authority. This is what a recursive resolver does behind the scenes, done
// in the open: the answer comes with every server that was asked on the way.
//
// it is slower than asking a resolver that has it all cached, and it is the only way to
// see what a zone's own servers say right now

export interface AuthoritativeResolverOptions
  extends TransportOptions, Omit<QuerySettings, 'recursionDesired' | 'transport'> {
  // UDP falls back to TCP for a truncated answer. Default UDP
  transport?: 'udp' | 'tcp';
  // where to start. Default: the thirteen root servers
  rootServers?: readonly NameserverHint[];
  // which of a nameserver's addresses to use. Default both, IPv4 first: a server's IPv6
  // address is tried only once each of the zone's servers has been tried at its first
  // address, so a host with no IPv6 route does not wait out a timeout at every step
  addressFamily?: 'ipv4' | 'ipv6' | 'both';
  // when a name is an alias for a name in another zone, resolve that one too and return
  // the whole chain. Off by default: the answer is then what the zone's server said, the
  // alias and nothing more. Covers CNAME and DNAME
  followCnames?: boolean;
  // how long an alias chain may be. Default 8
  maxAliases?: number;
  // how many servers may be asked on the way to one answer, nameserver address lookups
  // included. Default 40
  maxHops?: number;
  // how long one answer may take altogether, in milliseconds. `timeout` is the patience
  // with one server; a zone whose servers all stay silent would otherwise cost that for
  // each address of each of them. The last server a zone has left to ask is given the
  // rest of this, shared among its attempts, since there is no next one to save it for.
  // Default 10000
  totalTimeout?: number;
  // addresses for nameservers by name, used before asking for them. Also what puts a
  // name beside an address in the trace
  hosts?: Readonly<Record<string, string | readonly string[]>>;
  // the order servers are tried in. Default: a random order, drawn afresh each time, so
  // the load falls on all of a zone's servers and one slow server is not always first.
  // Give one to fix the order: it is called with the root servers, with a zone's
  // nameservers and with one nameserver's addresses, and returns the same items in the
  // order to try them. With `addressFamily: 'both'` the IPv4 addresses still come first,
  // each family in the order returned
  serverOrder?: ServerOrder;
  // how many queries may be in flight to one server address at once. Default 8; Infinity
  // for no limit
  serverConcurrency?: number;
  // find a nameserver's addresses some other way before it is resolved from the root: a
  // local cache, another resolver. `timeout` is what is left of the total timeout, in
  // milliseconds, and `signal` is the query's, for a lookup that should not outlast
  // either. Return nothing, or nothing of the address family asked for, to leave it to
  // the resolver
  resolveNameserver?: (
    name: string,
    limits: { timeout: number; signal?: AbortSignal }
  ) => Promise<readonly string[] | undefined> | readonly string[] | undefined;
  // remember delegations and nameserver addresses between queries, for as long as their
  // TTLs allow. Default true. With false every query starts again from the root
  cache?: boolean;
  // the least time between two queries to the same server, in milliseconds. Default 0
  serverDelay?: number;
  // how many queries may be in flight at once, to all servers together. Default: no limit
  concurrency?: number;
  // malformed record data is an error. By default such a record comes back in the
  // generic form
  strict?: boolean;
  onEvent?: OnEvent;
  // sockets and connections to share with other resolvers. The resolver does not close
  // a set it was given
  transports?: Transports;
  // check each answer's DNSSEC chain from the trust anchors down, and say what came of it
  // in `answer.security`. Queries are then sent with DO set, so the answer's `answers`
  // holds its signatures too. Validated key sets are kept by zone for as long as their
  // TTLs allow, unless `cache` is false. Default false
  validate?: boolean;
  // the trust anchors validation starts from. Default: IANA's root trust anchors
  trustAnchors?: readonly TrustAnchor[];
}

// what `serverOrder` is asked to put in order, and what it is given for each:
//   roots        the root servers' names, or the address of one given without a name
//   nameservers  a zone's nameservers' names, as the delegation wrote them
//   addresses    one nameserver's addresses
export type ServerOrderKind = 'roots' | 'nameservers' | 'addresses';
export type ServerOrder = (items: readonly string[], kind: ServerOrderKind) => readonly string[];

export interface AuthoritativeQueryOptions extends Omit<
  QuerySettings,
  'recursionDesired' | 'transport'
> {
  transport?: 'udp' | 'tcp';
  totalTimeout?: number;
  signal?: AbortSignal;
}

interface Nameserver {
  // canonical name, or '' where only an address is known
  name: string;
  // the name as the delegation wrote it, where its letter case differs
  written?: string;
  // the addresses that came with the name: glue, or a root hint. Without them the name
  // is looked up when the server is needed, and what is found is kept in `Knowledge`
  // for as long as its own TTL says
  addresses?: string[];
}

interface ZoneCut {
  // canonical name
  zone: string;
  // the name as the referral wrote it, where its letter case differs
  written?: string;
  servers: Nameserver[];
  // milliseconds since the epoch
  expires: number;
}

// what is known about the tree: which servers answer for which zones, and where
// nameservers live
interface Knowledge {
  cuts: Map<string, ZoneCut>;
  addresses: Map<string, { addresses: string[]; expires: number }>;
}

// one call to `query`, and everything it does on the way
interface Run {
  knowledge: Knowledge;
  settings: QuerySettings;
  signal: AbortSignal | undefined;
  // when the whole query gives up, on the clock `now()` reads, and the time it was given
  deadline: number;
  totalTimeout: number;
  // a timer the walk set for what was left of its time has run out
  expired: boolean;
  // servers asked so far, against `maxHops`
  hops: number;
  attempts: number;
  // nameserver names being looked up right now, to notice a lookup that needs itself
  resolving: Set<string>;
  // nameserver addresses looked up during this call, found or not, so no name is looked
  // up twice for one answer
  lookedUp: Map<string, string[]>;
  // every server that gave nothing usable, for the error a walk that fails throws
  failures: ServerFailure[];
}

// the default order: random, a fresh shuffle every time (Fisher-Yates)
const randomOrder: ServerOrder = items => {
  const out = [...items];
  for (let index = out.length - 1; index > 0; index--) {
    const other = Math.floor(Math.random() * (index + 1));
    [out[index], out[other]] = [out[other], out[index]];
  }
  return out;
};

// `items` in the order `serverOrder` gave their keys. Anything it left out goes last, in
// the order it came, and anything it made up is ignored
function inOrder<T>(items: readonly T[], keys: readonly string[], ordered: readonly string[]): T[] {
  const left = items.map((item, index) => ({ item, key: keys[index], taken: false }));
  const out: T[] = [];
  for (const key of ordered) {
    const found = left.find(entry => !entry.taken && entry.key === key);
    if (!found) continue;
    found.taken = true;
    out.push(found.item);
  }
  for (const entry of left) if (!entry.taken) out.push(entry.item);
  return out;
}

const DEFAULT_MAX_HOPS = 40;
const DEFAULT_TOTAL_TIMEOUT = 10_000;
// queries in flight to one server address at once
const DEFAULT_SERVER_CONCURRENCY = 8;
// the most addresses the resolver keeps a nameserver's name for, for the trace and the
// answer's `serverName`. Past it the least recently learned are forgotten
const MAX_NAMES = 10_000;
// the patience with one server when the caller names none: the same as `exchange` has
const DEFAULT_TIMEOUT = 5000;
const DEFAULT_MAX_ALIASES = 8;
// how deep nameserver lookups may nest: a nameserver whose own nameserver needs looking up
const MAX_NESTING = 4;
// addresses from the caller's `resolveNameserver` come with no TTL, so are kept this
// long, in seconds
const SUPPLIED_ADDRESS_TTL = 3600;

// rcodes that mean this server is not going to help with this zone: ask its neighbour
const LAME = new Set<number>([RCODES.SERVFAIL, RCODES.REFUSED, RCODES.NOTIMP, RCODES.NOTAUTH]);

type Outcome =
  | { kind: 'answer' }
  | { kind: 'alias'; target: string }
  | { kind: 'referral'; cut: ZoneCut }
  // `loop`: the server sent the question sideways or back up, not an error code
  | { kind: 'lame'; reason: string; loop?: boolean };

export class AuthoritativeResolver {
  private readonly options: AuthoritativeResolverOptions;
  private readonly limit: Limiter;
  private readonly limitServer: KeyedLimiter;
  private readonly pace: (server: string) => Promise<void>;
  private readonly transports: Transports;
  private readonly ownsTransports: boolean;
  private readonly knowledge: Knowledge = { cuts: new Map(), addresses: new Map() };
  private readonly root: Nameserver[];
  // address -> name, for the trace: those the resolver was given, kept for its life, and
  // those it learned on the way, bounded and forgotten by `clearCache()`
  private readonly givenNames = new Map<string, string>();
  private readonly names = new Map<string, string>();
  private readonly hosts = new Map<string, string[]>();
  private readonly validator: Validator | undefined;

  constructor(options: AuthoritativeResolverOptions = {}) {
    this.options = options;
    this.limit = createLimiter(options.concurrency ?? Infinity);
    this.limitServer = createKeyedLimiter(options.serverConcurrency ?? DEFAULT_SERVER_CONCURRENCY);
    this.pace = createPacer(options.serverDelay ?? 0);
    this.ownsTransports = !options.transports && hasTransportOptions(options);
    this.transports =
      options.transports ?? (this.ownsTransports ? createTransports(options) : defaultTransports());

    for (const [name, addresses] of Object.entries(options.hosts ?? {})) {
      const list = [addresses].flat().map(normalizeAddress);
      this.hosts.set(canonicalName(name), list);
      for (const address of list) this.givenNames.set(address, givenName(name));
    }
    this.root = (options.rootServers ?? ROOT_HINTS).map(hint => {
      const name = hint.name ? canonicalName(hint.name) : '';
      const written = hint.name ? givenName(hint.name) : '';
      const addresses = this.usable([hint.ipv4, hint.ipv6].filter(isString).map(normalizeAddress));
      for (const address of addresses) if (written) this.givenNames.set(address, written);
      return { name, ...(written !== name && { written }), addresses };
    });
    if (options.validate) {
      this.validator = new Validator({
        trustAnchors: options.trustAnchors,
        ...(options.cache === false && { maxZones: 0 }),
      });
    }
  }

  // resolve from the root. As with `Resolver`, a name that does not exist is an answer,
  // not an error; an error means no server gave a usable response
  query<Type extends KnownRecordType>(
    name: string,
    type: Type,
    options?: AuthoritativeQueryOptions
  ): Promise<Answer<RecordOf<Type>>>;
  query(name: string, type: string | number, options?: AuthoritativeQueryOptions): Promise<Answer>;
  async query(
    name: string,
    type: string | number,
    options: AuthoritativeQueryOptions = {}
  ): Promise<Answer> {
    const follow = this.options.followCnames === true;
    if (!this.validator) return this.walk(name, type, options, follow);
    // every response on the way is judged, the aliases followed included
    const responses: DnssecResponse[] = [];
    const answer = await this.walk(name, type, { ...options, dnssecOk: true }, follow, responses);
    // the chain's records are asked for as they are: no alias is followed. They go the way
    // the data query went: the same transport, port, timeouts and EDNS settings
    const {
      checkingDisabled: _checkingDisabled,
      authenticData: _authenticData,
      ...sameWay
    } = options;
    answer.security = await this.validator.validate(
      responses,
      async (chainName, chainType) =>
        (await this.walk(chainName, chainType, { ...sameWay, dnssecOk: true }, false)).message,
      options.signal
    );
    return answer;
  }

  // resolve from the root, following aliases when `follow`, and keep each response that
  // ended a walk in `responses`
  private async walk(
    name: string,
    type: string | number,
    options: AuthoritativeQueryOptions,
    follow: boolean,
    responses?: DnssecResponse[]
  ): Promise<Answer> {
    const { signal, totalTimeout: perQuery, ...settings } = options;
    const totalTimeout = perQuery ?? this.options.totalTimeout ?? DEFAULT_TOTAL_TIMEOUT;
    const started = now();
    // the name as the caller wrote it, for the answer, and as it is compared and sent
    let shown: string;
    let asked: string;
    try {
      shown = presentName(toAsciiName(name));
      asked = comparableName(shown);
    } catch (cause) {
      throw new InvalidQueryError(cause instanceof Error ? cause.message : String(cause), {
        cause,
      });
    }
    const typeText = typeName(typeCode(type));

    const run: Run = {
      knowledge:
        this.options.cache === false ? { cuts: new Map(), addresses: new Map() } : this.knowledge,
      settings: { ...settings },
      signal,
      deadline: started + totalTimeout,
      totalTimeout,
      expired: false,
      hops: 0,
      attempts: 0,
      resolving: new Set(),
      lookedUp: new Map(),
      failures: [],
    };

    const trace: TraceHop[] = [];
    const aliases: DnsRecord[] = [];
    const maxAliases = this.options.maxAliases ?? DEFAULT_MAX_ALIASES;
    const visited = new Set([asked]);
    let current = asked;
    for (;;) {
      const { result, outcome } = await this.resolve(run, current, typeText, trace, 0).catch(
        (error: unknown) => {
          // a walk that fails still says how far it got, and what went wrong on the way
          if (error instanceof DnsError) {
            error.trace ??= trace;
            if (run.failures.length > 0) error.failures ??= run.failures;
          }
          throw error;
        }
      );
      responses?.push(dnssecResponse(result.message, current, typeCode(typeText)));
      if (outcome.kind !== 'alias' || !follow) {
        return buildAnswer(result, {
          strict: this.options.strict,
          name: shown,
          before: aliases,
          trace,
          // the name of the nameserver that was asked: two names can share an address
          serverName:
            trace.filter(hop => hop.server === result.server).at(-1)?.serverName ??
            this.nameOf(normalizeAddress(result.server)),
          elapsed: now() - started,
          attempts: run.attempts,
        });
      }
      // keep the alias records, and start again from the name they point at
      aliases.push(
        ...decodeRecords(result.message.answers, { lenient: !this.options.strict }).filter(
          record => record.type === 'CNAME' || record.type === 'DNAME'
        )
      );
      // `visited` holds the name asked about and every alias target followed so far
      if (visited.size > maxAliases) {
        throw new InvalidResponseError(`Alias chain for ${asked} is longer than ${maxAliases}`, {
          query: asked,
          type: typeText,
        });
      }
      if (visited.has(outcome.target)) {
        throw new InvalidResponseError(`Alias loop: ${asked} leads back to ${outcome.target}`, {
          query: asked,
          type: typeText,
        });
      }
      visited.add(outcome.target);
      current = outcome.target;
    }
  }

  // forget every delegation, nameserver address and nameserver name learned so far, and
  // every zone validation has judged
  clearCache(): void {
    this.knowledge.cuts.clear();
    this.knowledge.addresses.clear();
    this.names.clear();
    this.validator?.clear();
  }

  // close the sockets and connections this resolver opened. A resolver that shares the
  // process-wide set, or was given one, leaves it open
  close(): void {
    this.clearCache();
    if (this.ownsTransports) this.transports.close();
  }

  // ---- inside

  // the addresses of a nameserver this resolver is willing to use, in the order given
  private usable(addresses: readonly string[]): string[] {
    const family = this.options.addressFamily ?? 'both';
    // only addresses: anything else here would be read as a name, or a host and a port
    if (family === 'ipv4') return addresses.filter(isIpv4);
    if (family === 'ipv6') return addresses.filter(isIpv6);
    return addresses.filter(address => isIpv4(address) || isIpv6(address));
  }

  // a nameserver's addresses in the order to try them: the caller's order, or a random
  // one, with IPv4 first
  private orderAddresses(addresses: readonly string[]): string[] {
    const ordered = inOrder(addresses, addresses, this.order(addresses, 'addresses'));
    return [...ordered.filter(isIpv4), ...ordered.filter(address => !isIpv4(address))];
  }

  // a zone's servers in the order to try them
  private orderServers(cut: ZoneCut): Nameserver[] {
    const keys = cut.servers.map(
      server => server.written ?? (server.name || server.addresses?.[0] || '')
    );
    return inOrder(
      cut.servers,
      keys,
      this.order(keys, cut.servers === this.root ? 'roots' : 'nameservers')
    );
  }

  private order(items: readonly string[], kind: ServerOrderKind): readonly string[] {
    if (items.length < 2) return items;
    return (this.options.serverOrder ?? randomOrder)(items, kind);
  }

  // the name a nameserver was known by at an address
  private nameOf(address: string): string | undefined {
    return this.names.get(address) ?? this.givenNames.get(address);
  }

  // remember a nameserver's name at an address. The most recent is kept, and the oldest
  // forgotten past `MAX_NAMES`
  private learnName(address: string, name: string): void {
    this.names.delete(address);
    this.names.set(address, name);
    if (this.names.size > MAX_NAMES) this.names.delete(this.names.keys().next().value as string);
  }

  // the deepest zone already known to hold the name, and its servers
  private closestCut(run: Run, name: string): ZoneCut {
    for (let zone = name; ; zone = parentName(zone)) {
      const cut = run.knowledge.cuts.get(zone);
      if (cut && cut.expires > Date.now()) return cut;
      if (cut) run.knowledge.cuts.delete(zone);
      if (zone === '.') break;
    }
    return { zone: '.', servers: this.root, expires: Infinity };
  }

  // follow referrals from the closest known zone until a server answers for the name.
  // `nesting` is how many nameserver lookups deep this is
  private async resolve(
    run: Run,
    name: string,
    type: string,
    trace: TraceHop[] | undefined,
    nesting: number
  ): Promise<{ result: ExchangeResult; outcome: Outcome }> {
    const maxHops = this.options.maxHops ?? DEFAULT_MAX_HOPS;
    // a DS RRset is the parent's: the question goes to the zone above the name, even when
    // the name's own zone is already known (RFC 4035 §4.2)
    let cut = this.closestCut(run, type === 'DS' && name !== '.' ? parentName(name) : name);

    for (;;) {
      // ask the zone's servers in turn until one gives something to go on
      let step: { result: ExchangeResult; outcome: Outcome } | undefined;
      let firstError: DnsError | undefined;
      let lastLame: ExchangeResult | undefined;
      const refusals = new Set<number>();
      let loop: string | undefined;
      // the nameserver the time ran out at, for the error
      let stalled: Nameserver | undefined;

      // each of the zone's servers is asked at its first address before any is asked at a
      // second. A server that cannot be reached at one address may be at another, but the
      // zone's next server is the better bet, and with a total timeout it may be the only
      // one left time for: a dead dual-stack server would otherwise spend it on both its
      // addresses. A server's addresses are looked up when it is first needed
      const turns = this.orderServers(cut).map(server => ({
        server,
        addresses: undefined as string[] | undefined,
        done: false,
      }));
      servers: for (let round = 0; turns.some(turn => !turn.done); round++) {
        for (const [position, turn] of turns.entries()) {
          if (turn.done) continue;
          // out of time: what the zone's servers have said so far is all there will be
          if (outOfTime(run)) {
            stalled = turn.server;
            break servers;
          }
          const { server } = turn;
          turn.addresses ??= this.orderAddresses(await this.addressesOf(run, server, nesting));
          // finding the address may have been what took the time
          if (outOfTime(run)) {
            stalled = server;
            break servers;
          }
          const address = turn.addresses[round];
          if (address === undefined) {
            turn.done = true;
            continue;
          }
          if (++run.hops > maxHops) {
            throw new InvalidResponseError(
              `Gave up resolving ${name} after asking ${maxHops} servers`,
              { query: name, type }
            );
          }
          const timestamp = new Date();
          const hopStarted = now();
          const hop: TraceHop = {
            server: address,
            ...(server.name && { serverName: server.written ?? server.name }),
            zone: cut.written ?? cut.zone,
            name,
            type,
            elapsed: 0,
            timestamp,
          };
          trace?.push(hop);
          // the last the zone has left to ask gets the rest of the walk's time, not the
          // patience with one server: that patience is there to leave time for the next, and
          // there is no next. Only on the walk itself: a nameserver lookup's time belongs to
          // the zone that sent for it, whose other servers may still need it
          const last = nesting === 0 && lastToAsk(turns, position, round);
          try {
            const result = await this.ask(run, name, type, address, last);
            const outcome = this.read(result, name, type, cut.zone);
            Object.assign(hop, {
              transport: result.transport,
              rcode: result.message.rcode,
              rcodeName: rcodeName(result.message.rcode),
              bytes: result.bytes.length,
              elapsed: now() - hopStarted,
              ...(outcome.kind === 'referral' && {
                referral: outcome.cut.written ?? outcome.cut.zone,
              }),
            });
            if (outcome.kind === 'lame') {
              hop.error = {
                name: 'InvalidResponseError',
                message: outcome.reason,
                retryable: false,
              };
              run.failures.push({
                server: address,
                error: new InvalidResponseError(outcome.reason, {
                  server: address,
                  query: name,
                  type,
                  transport: result.transport,
                  ...(!outcome.loop && { rcode: result.message.rcode }),
                }),
              });
              if (outcome.loop) {
                loop = outcome.reason;
                turn.done = true;
                continue;
              }
              lastLame = result;
              // two of a zone's servers refusing the same way is the zone's answer. A
              // type an operator will not serve (RRSIG, ANY) is refused by every one of
              // its servers, and asking all eight costs more than the rare third opinion
              // is worth
              const rcode = result.message.rcode;
              if (rcode !== 0 && refusals.has(rcode)) break servers;
              refusals.add(rcode);
              // it answered, so it can be reached, and its other addresses are the same
              // server with the same thing to say: on to the zone's next nameserver
              turn.done = true;
              continue;
            }
            step = { result, outcome };
            break servers;
          } catch (error) {
            hop.elapsed = now() - hopStarted;
            // a question that cannot be asked, or a caller who has given up
            if (
              run.signal?.aborted ||
              !(error instanceof DnsError) ||
              error instanceof InvalidQueryError
            ) {
              throw error;
            }
            hop.error = errorData(error);
            run.failures.push({ server: address, error });
            firstError ??= error;
          }
        }
      }

      if (!step) {
        // nobody in the zone helped. An error response is still what its servers said,
        // and is returned as the answer; with only failures, the first is thrown, from the
        // server that would have answered. The others are in the trace
        if (lastLame) return { result: lastLame, outcome: { kind: 'answer' } };
        if (loop) throw new InvalidResponseError(`Referral loop: ${loop}`, { query: name, type });
        if (firstError) throw firstError;
        if (outOfTime(run)) {
          const at = stalled && (stalled.written ?? (stalled.name || stalled.addresses?.[0]));
          throw new TimeoutError(`No answer for ${name} ${type} within ${run.totalTimeout} ms`, {
            ...(at && { server: at }),
            query: name,
            type,
          });
        }
        throw new InvalidResponseError(
          `No usable nameserver address for ${cut.zone === '.' ? 'the root' : cut.zone}`,
          { query: name, type }
        );
      }
      if (step.outcome.kind !== 'referral') return step;

      cut = step.outcome.cut;
      // a delegation with a TTL of zero is used for this walk and not kept
      if (cut.expires > Date.now()) run.knowledge.cuts.set(cut.zone, cut);
    }
  }

  // what a response means for the walk
  private read(result: ExchangeResult, name: string, type: string, zone: string): Outcome {
    const { message } = result;
    if (message.rcode === RCODES.NXDOMAIN) return { kind: 'answer' };
    if (LAME.has(message.rcode)) {
      return { kind: 'lame', reason: `${result.server} answered ${rcodeName(message.rcode)}` };
    }
    if (message.rcode !== RCODES.NOERROR) return { kind: 'answer' };

    const lenient = { lenient: true };
    if (message.answers.length > 0) {
      // records from a server without authority for them, beside a delegation further
      // down, are a referral: the child zone is asked, not taken at the parent's word
      if (!message.flags.aa) {
        const referral = this.referral(result, name, zone);
        if (referral?.kind === 'referral') return referral;
      }
      const answers = decodeRecords(message.answers, lenient);
      // records of the type asked for, at the name or at the end of its aliases
      if (type === 'ANY' || type === 'CNAME' || type === 'DNAME') return { kind: 'answer' };
      const owner = aliasTarget(name, answers);
      const answered = answers.some(
        record => record.type === type && canonicalName(record.name) === owner
      );
      // an alias whose target this server did not answer for: it lives somewhere else
      if (!answered && owner !== name) return { kind: 'alias', target: owner };
      return { kind: 'answer' };
    }

    // no answer: a referral names the servers of a zone further down
    return this.referral(result, name, zone) ?? { kind: 'answer' };
  }

  // the delegation in a response's authority section, or undefined when it has none: no
  // NS records, or a server authoritative for what it answered
  private referral(result: ExchangeResult, name: string, zone: string): Outcome | undefined {
    const { message } = result;
    const lenient = { lenient: true };
    const authorities = decodeRecords(message.authorities, lenient);
    const delegations = authorities.filter(
      (record): record is Extract<DnsRecord, { type: 'NS' }> => record.type === 'NS'
    );
    if (delegations.length === 0 || message.flags.aa) return undefined;

    const child = canonicalName(delegations[0].name);
    const childWritten = presentName(delegations[0].name);
    const below = child !== zone && isSubdomain(child, zone) && isSubdomain(name, child);
    if (!below) {
      // a referral sideways or back up leads nowhere, or round in a circle
      return {
        kind: 'lame',
        reason: `${result.server} referred ${name} to ${child}, which is not below ${zone}`,
        loop: true,
      };
    }

    const glue = decodeRecords(message.additionals, lenient);
    // names are compared in their canonical form and shown as the zone wrote them
    const written = new Map<string, string>();
    for (const record of delegations) {
      const target = canonicalName(record.target);
      if (record.target !== target && !written.has(target)) written.set(target, record.target);
    }
    const servers: Nameserver[] = delegations
      .filter(record => canonicalName(record.name) === child)
      .map(record => canonicalName(record.target))
      .filter((target, index, all) => all.indexOf(target) === index)
      .map(target => {
        // glue is taken only for a nameserver inside the zone of the server that sent it,
        // which holds authority for that name (RFC 2181 §5.4.1). An address for a name
        // elsewhere is ignored, and the name is looked up as if it came with none. The
        // delegated zone alone would be too narrow: the root's glue for the servers of com,
        // named under net, could then never be used
        const inBailiwick = isSubdomain(target, zone);
        const addresses = glue
          .filter(
            (record): record is Extract<DnsRecord, { type: 'A' | 'AAAA' }> =>
              inBailiwick &&
              (record.type === 'A' || record.type === 'AAAA') &&
              canonicalName(record.name) === target
          )
          .map(record => normalizeAddress(record.address));
        const shown = written.get(target);
        for (const address of addresses) this.learnName(address, shown ?? target);
        const usable = this.usable(addresses);
        // without usable glue the address is looked up when the server is first needed
        return {
          name: target,
          ...(shown && { written: shown }),
          ...(usable.length > 0 && { addresses: usable }),
        };
      });

    const ttl = Math.min(...delegations.map(record => record.ttl));
    return {
      kind: 'referral',
      cut: {
        zone: child,
        ...(childWritten !== child && { written: childWritten }),
        servers,
        expires: Date.now() + ttl * 1000,
      },
    };
  }

  // a nameserver's addresses: from the referral's glue, the host map, what was learned
  // earlier, or by resolving its name from the root like any other
  private async addressesOf(run: Run, server: Nameserver, nesting: number): Promise<string[]> {
    if (server.addresses) return server.addresses;
    const { name } = server;
    if (isIp(name)) return this.usable([normalizeAddress(name)]);

    const known = this.hosts.get(name);
    if (known) return this.usable(known);
    // what was learned is checked against its own TTL every time: a nameserver's address
    // can change long before the delegation naming it runs out
    const learned = run.knowledge.addresses.get(name);
    if (learned && learned.expires > Date.now()) return learned.addresses;
    const tried = run.lookedUp.get(name);
    if (tried) return tried;

    // a nameserver that can only be found by asking itself, or a chain of them too deep
    // to be worth following, is skipped: the zone's other servers may do
    if (run.resolving.has(name) || nesting >= MAX_NESTING) return [];
    run.resolving.add(name);
    try {
      // the caller's own way of finding it comes first
      const lookup = this.options.resolveNameserver;
      if (lookup) {
        // no more than the walk has left
        const supplied = await withRest(run, async timeout =>
          lookup(server.written ?? name, { timeout, ...(run.signal && { signal: run.signal }) })
        );
        const normalized = (supplied ?? []).map(normalizeAddress);
        const usable = this.usable(normalized);
        // nothing usable, as when every address is of a family not asked for, is the same
        // as nothing at all: the name is looked up below, and nothing is kept
        if (usable.length > 0) {
          for (const address of normalized) this.learnName(address, server.written ?? name);
          run.knowledge.addresses.set(name, {
            addresses: usable,
            expires: Date.now() + SUPPLIED_ADDRESS_TTL * 1000,
          });
          run.lookedUp.set(name, usable);
          return usable;
        }
        // the lookup took the rest of the time: there is none left to look further
        if (outOfTime(run)) return [];
      }
      const family = this.options.addressFamily ?? 'both';
      const types = family === 'ipv4' ? ['A'] : family === 'ipv6' ? ['AAAA'] : ['A', 'AAAA'];
      const found: string[] = [];
      let ttl = Infinity;
      for (const type of types) {
        try {
          const { result } = await this.resolve(run, name, type, undefined, nesting + 1);
          for (const record of decodeRecords(result.message.answers, { lenient: true })) {
            if (record.type === 'A' || record.type === 'AAAA') {
              found.push(normalizeAddress(record.address));
              ttl = Math.min(ttl, record.ttl);
            }
          }
        } catch (error) {
          if (run.signal?.aborted || !(error instanceof DnsError)) throw error;
          // this nameserver cannot be found; another may be
        }
      }
      for (const address of found) this.learnName(address, server.written ?? name);
      const addresses = this.usable(found);
      // only what was found is kept past this call. A lookup that failed, or found
      // nothing, is tried again by the next query
      if (addresses.length > 0 && ttl > 0) {
        run.knowledge.addresses.set(name, { addresses, expires: Date.now() + ttl * 1000 });
      }
      run.lookedUp.set(name, addresses);
      return addresses;
    } finally {
      run.resolving.delete(name);
    }
  }

  // one question to one server, the way an authoritative server is asked: no recursion.
  // `last`: nobody else is left to ask, so the server may take the rest of the time
  private async ask(
    run: Run,
    name: string,
    type: string,
    address: string,
    last = false
  ): Promise<ExchangeResult> {
    const merged = { ...this.options, ...run.settings };
    const patience = merged.timeout ?? DEFAULT_TIMEOUT;
    // the zone has other servers to turn to, so less patience with each
    const retries = merged.retries ?? 1;
    await this.pace(address);
    const result = await this.limit(() =>
      this.limitServer(address, () =>
        withRest(run, left =>
          // as an object, so that the address is taken whole and nothing in it is read as a
          // port: the port is the resolver's to choose
          exchange(
            { name, type },
            { address },
            {
              transport: merged.transport,
              port: merged.port,
              recursionDesired: false,
              checkingDisabled: merged.checkingDisabled,
              authenticData: merged.authenticData,
              dnssecOk: merged.dnssecOk,
              udpPayloadSize: merged.udpPayloadSize,
              ednsOptions: merged.ednsOptions,
              edns: merged.edns,
              // the last server to ask has what is left shared among its attempts, and never
              // less than any other server would have had
              timeout: last ? restOfTime(left, patience, retries) : patience,
              // no longer than what is left of the time for the whole query, retries and a
              // TCP fallback included
              totalTimeout: left,
              tcpFallback: merged.tcpFallback,
              retries,
              transports: this.transports,
              onEvent: this.options.onEvent,
              signal: run.signal,
            }
          )
        )
      )
    );
    run.attempts += result.attempts;
    return result;
  }
}

const isString = (value: string | undefined): value is string => typeof value === 'string';

// a name the caller gave for a server, as it is shown. One that cannot be written is
// shown in its canonical form rather than refused here: asking for it is what fails
function givenName(name: string): string {
  try {
    return presentName(name);
  } catch {
    return canonicalName(name);
  }
}

// nobody is left in the zone to ask after this server at this address: it has no address
// after this one, and every other server has refused, referred the walk round in a loop,
// or has no address left to try. Those asked before it this round would next be asked at their following
// address, those after it at this round's. A server not yet looked up may have addresses,
// so it counts as one left to ask
function lastToAsk(
  turns: readonly { addresses: string[] | undefined; done: boolean }[],
  position: number,
  round: number
): boolean {
  return turns.every((turn, index) => {
    if (turn.done && index !== position) return true;
    if (turn.addresses === undefined) return false;
    const next = index <= position ? round + 1 : round;
    return turn.addresses.length <= next;
  });
}

// the patience with the last server a zone has to ask: the rest of the walk's time, shared
// among its attempts, and never less than the patience with any other server. Whole
// milliseconds, for the error that names it
function restOfTime(left: number, patience: number, retries: number): number {
  if (!Number.isFinite(left)) return patience;
  return Math.min(MAX_TIMER, Math.max(patience, Math.floor(left / (retries + 1))));
}

// the longest a timer can be set for; anything longer fires at once
const MAX_TIMER = 2_147_483_647;

// the walk is out of time: the clock has reached the deadline, or a call given the rest of
// the time has run it out
function outOfTime(run: Run): boolean {
  return run.expired || now() >= run.deadline;
}

// make a call capped at what is left of the walk's time, and time it from the walk as well.
// A timer can fire a few milliseconds early by the clock, so a call that ran out the rest of
// the time can end with the clock still short of the deadline, and the walk would carry on
// with what looks left and fail some other way than by running out of time
async function withRest<T>(run: Run, call: (left: number) => Promise<T>): Promise<T> {
  const left = Math.max(1, run.deadline - now());
  if (left > MAX_TIMER) return call(left);
  // set just before the call sets its own, for the same time, so it fires first
  const timer = setTimeout(() => {
    run.expired = true;
  }, left);
  try {
    return await call(left);
  } finally {
    clearTimeout(timer);
  }
}
