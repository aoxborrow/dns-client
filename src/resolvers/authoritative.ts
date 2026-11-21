import {
  DnsError,
  errorData,
  InvalidQueryError,
  InvalidResponseError,
  TimeoutError,
} from '../errors';
import type { ServerFailure } from '../errors';
import { exchange, hasTransportOptions, presentName, tcpFallbackFailure } from '../exchange';
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
import {
  canonicalName,
  comparableName,
  isSubdomain,
  parentName,
  splitName,
  toAsciiName,
} from '../wire/names';
import { dnssecResponse, Validator } from '../dnssec/validate';
import type { DnssecResponse } from '../dnssec/judge';
import type { TrustAnchor } from '../dnssec/types';
import { aliasTarget, buildAnswer } from './answer';
import type { Answer, QuerySettings, TraceHop } from './answer';
import { createKeyedLimiter, createLimiter, createPacer } from './limiter';
import type { KeyedLimiter, Limiter, Pacer } from './limiter';
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
  // With `validate`, the queries for the chain share it with the data. Default 10000
  totalTimeout?: number;
  // addresses for nameservers by name, used before asking for them. Also what puts a
  // name beside an address in the trace
  hosts?: Readonly<Record<string, string | readonly string[]>>;
  // how many queries may be in flight to one server address at once. Default 8; Infinity
  // for no limit
  serverConcurrency?: number;
  // remember delegations between queries, for as long as their TTLs allow, and for no
  // longer than the resolver lives. A query then starts at the deepest zone it knows, and
  // its trace starts there too. Queries running at the same time that need the same
  // delegation share one referral: the others wait for the one asking, at the root, a
  // top-level domain or a zone already seen to give referrals. Default true. With false every query starts again from the root, and its trace is the whole path
  cache?: boolean;
  // remember the addresses of nameservers that came without glue between queries, for as
  // long as their TTLs allow, even with `cache` false: a later query that meets the same
  // nameserver asks it straight away instead of looking it up again. Lookups of one
  // nameserver made by queries running at the same time are shared. Default true
  nameserverCache?: boolean;
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

export interface AuthoritativeQueryOptions extends Omit<
  QuerySettings,
  'recursionDesired' | 'transport'
> {
  transport?: 'udp' | 'tcp';
  totalTimeout?: number;
  signal?: AbortSignal;
  // told of every query this one sends, nameserver lookups included, beside the
  // resolver's own `onEvent`: what tells the queries of one call apart from those of
  // others running at the same time
  onEvent?: OnEvent;
  // where this query starts, in place of the root servers: a server to ask first and
  // follow the referrals of. Nameservers that come without an address are still looked
  // up from the root servers, and the delegations found on the way are not kept for
  // other queries
  startAt?: readonly NameserverHint[];
  // walk from the root servers whatever delegations the resolver remembers, asking every
  // server on the way, so the trace is the whole path. What the walk learns is still kept
  // for other queries, and other queries that need a delegation it is fetching wait for
  // it. Nameserver addresses still come from `nameserverCache`. Default false
  fromRoot?: boolean;
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

// what is known about the tree: which servers answer for which zones and how zones answer
// (kept unless `cache` is false), and where nameservers live (kept unless
// `nameserverCache` is false)
interface Knowledge {
  cuts: Map<string, ZoneCut>;
  // zones whose servers have referred a question further down ('refers'), the ones worth
  // waiting at for another walk's referral, or have answered with authority for a name
  // more than one label below the zone ('answers'), which is kept once seen: such a zone
  // answers for names under it itself, whatever it delegates
  zones: Map<string, 'refers' | 'answers'>;
  addresses: Map<string, { addresses: string[]; expires: number }>;
}

// one call to `query`, and everything it does on the way
interface Run {
  knowledge: Knowledge;
  settings: QuerySettings;
  signal: AbortSignal | undefined;
  onEvent: OnEvent | undefined;
  // the servers the walk starts at, when not the root servers
  start: Nameserver[] | undefined;
  // the walk itself ignores the delegations already known (the query's `fromRoot`)
  fromRoot: boolean;
  // `knowledge.cuts` is the resolver's, so what this run asks may be what another needs
  shared: boolean;
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

// what a nameserver lookup found. `cutShort`: it ran out of time or was stopped before it
// could finish, so finding nothing says nothing about the nameserver
interface LookupResult {
  addresses: string[];
  cutShort: boolean;
  // the servers that failed while the lookup asked its way to the addresses
  failures?: ServerFailure[];
}

// a nameserver lookup queries share while it lasts, and how many are waiting on it
interface SharedLookup {
  name: string;
  done: Promise<LookupResult>;
  stop: AbortController;
  waiting: number;
}

// a zone's servers being asked about a name, by `stepDown`: whatever delegation comes back
// is in the resolver's knowledge by the time `done` settles
interface Fetch {
  done: Promise<void>;
}

// the order servers are tried in: random, a fresh shuffle every time (Fisher-Yates), so
// the load falls on all of a zone's servers and one slow server is not always first
function shuffled<T>(items: readonly T[]): T[] {
  const out = [...items];
  for (let index = out.length - 1; index > 0; index--) {
    const other = Math.floor(Math.random() * (index + 1));
    [out[index], out[other]] = [out[other], out[index]];
  }
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

// rcodes that mean this server is not going to help with this zone: ask its neighbour
const LAME = new Set<number>([RCODES.SERVFAIL, RCODES.REFUSED, RCODES.NOTIMP, RCODES.NOTAUTH]);

// a response that gave the walk something to go on, and what it means
interface Step {
  result: ExchangeResult;
  outcome: Outcome;
}

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
  private readonly pace: Pacer;
  private readonly transports: Transports;
  private readonly ownsTransports: boolean;
  private readonly knowledge: Knowledge = {
    cuts: new Map(),
    zones: new Map(),
    addresses: new Map(),
  };
  // nameserver lookups in flight, by canonical name, for queries that meet the same
  // nameserver at the same time to share
  private readonly lookups = new Map<string, SharedLookup>();
  // zones being asked right now about names on the way to a delegation, for a walk that
  // needs the same one to wait for it rather than ask the same servers again
  private readonly fetches = new Map<string, Fetch>();
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
    this.root = this.nameservers(options.rootServers ?? ROOT_HINTS, (address, name) =>
      this.givenNames.set(address, name)
    );
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
    // one deadline for the data and the chain together
    const totalTimeout = options.totalTimeout ?? this.options.totalTimeout ?? DEFAULT_TOTAL_TIMEOUT;
    const deadline = now() + totalTimeout;
    // every response on the way is judged, the aliases followed included
    const responses: DnssecResponse[] = [];
    const answer = await this.walk(
      name,
      type,
      { ...options, totalTimeout, dnssecOk: true },
      follow,
      responses
    );

    // the chain gets what the data left. When that runs out, the query times out as one
    // whose data took too long does: the chain queries still out are abandoned, and
    // validation rejects with a TimeoutError, as it does with the caller's own abort
    const budget = new AbortController();
    const timedOut = () =>
      budget.abort(
        new TimeoutError(
          `No validated answer for ${name} ${typeName(typeCode(type))} within ${totalTimeout} ms`,
          {
            query: name,
            type: typeName(typeCode(type)),
          }
        )
      );
    const forward = () => budget.abort(options.signal?.reason);
    if (options.signal?.aborted) forward();
    else options.signal?.addEventListener('abort', forward, { once: true });
    const left = deadline - now();
    if (left <= 0) timedOut();
    const timer = left > 0 && left <= MAX_TIMER ? setTimeout(timedOut, left) : undefined;

    // the chain's records are asked for as they are: no alias is followed. They go the way
    // the data query went: the same transport, port, timeouts and EDNS settings. They start
    // from the delegations already known, `fromRoot` or not, since their traces are not shown
    const {
      checkingDisabled: _checkingDisabled,
      authenticData: _authenticData,
      fromRoot: _fromRoot,
      ...sameWay
    } = options;
    try {
      answer.security = await this.validator.validate(
        responses,
        async (chainName, chainType) => {
          if (budget.signal.aborted) throw budget.signal.reason;
          const chainOptions = {
            ...sameWay,
            dnssecOk: true,
            totalTimeout: Math.max(1, deadline - now()),
            signal: budget.signal,
          };
          try {
            return (await this.walk(chainName, chainType, chainOptions, false)).message;
          } catch (error) {
            // the walk's own deadline is the budget's, and either may fire first: running
            // out of time always rejects the query, never leaves a link undecided
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

  // resolve from the root, following aliases when `follow`, and keep each response that
  // ended a walk in `responses`
  private async walk(
    name: string,
    type: string | number,
    options: AuthoritativeQueryOptions,
    follow: boolean,
    responses?: DnssecResponse[]
  ): Promise<Answer> {
    const { signal, totalTimeout: perQuery, onEvent, startAt, fromRoot, ...settings } = options;
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

    const start =
      startAt && this.nameservers(startAt, (address, at) => this.learnName(address, at));
    // a walk from somewhere other than the root keeps what it finds to itself
    const shared = this.options.cache !== false && !start;
    const run: Run = {
      knowledge: {
        cuts: shared ? this.knowledge.cuts : new Map<string, ZoneCut>(),
        zones: shared ? this.knowledge.zones : new Map<string, 'refers' | 'answers'>(),
        addresses:
          this.options.nameserverCache === false
            ? new Map<string, { addresses: string[]; expires: number }>()
            : this.knowledge.addresses,
      },
      settings: { ...settings },
      signal,
      onEvent,
      start,
      fromRoot: fromRoot === true,
      shared,
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
    this.knowledge.zones.clear();
    this.knowledge.addresses.clear();
    this.names.clear();
    this.validator?.clear();
  }

  // close the sockets and connections this resolver opened. A resolver that shares the
  // process-wide set, or was given one, leaves it open
  close(): void {
    // a lookup some query is still waiting on ends with the resolver
    for (const lookup of this.lookups.values()) lookup.stop.abort();
    this.lookups.clear();
    this.fetches.clear();
    this.clearCache();
    if (this.ownsTransports) this.transports.close();
  }

  // ---- inside

  // servers given by name and address, as the zone's servers a walk starts at. `remember`
  // is told each address's name, for the trace
  private nameservers(
    hints: readonly NameserverHint[],
    remember: (address: string, name: string) => void
  ): Nameserver[] {
    return hints.map(hint => {
      const name = hint.name ? canonicalName(hint.name) : '';
      const written = hint.name ? givenName(hint.name) : '';
      const addresses = this.usable([hint.ipv4, hint.ipv6].filter(isString).map(normalizeAddress));
      for (const address of addresses) if (written) remember(address, written);
      return { name, ...(written !== name && { written }), addresses };
    });
  }

  // the addresses of a nameserver this resolver is willing to use, in the order given
  private usable(addresses: readonly string[]): string[] {
    const family = this.options.addressFamily ?? 'both';
    // only addresses: anything else here would be read as a name, or a host and a port
    if (family === 'ipv4') return addresses.filter(isIpv4);
    if (family === 'ipv6') return addresses.filter(isIpv6);
    return addresses.filter(address => isIpv4(address) || isIpv6(address));
  }

  // a nameserver's addresses in the order to try them: random, with IPv4 first
  private orderAddresses(addresses: readonly string[]): string[] {
    const ordered = shuffled(addresses);
    return [...ordered.filter(isIpv4), ...ordered.filter(address => !isIpv4(address))];
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
    return this.rootCut();
  }

  private rootCut(): ZoneCut {
    return { zone: '.', servers: this.root, expires: Infinity };
  }

  // say that this run is about to ask a zone's servers about a name, for walks that need
  // the same delegation to wait for. Returns what to call once the answer is in the
  // knowledge, or undefined when another run is asking already, this one keeps what it
  // learns to itself, or the name is one the zone may answer for itself. A name one label
  // below the zone is such a name, except at the root or a top-level domain, whose servers
  // all but always refer it on: the questions about www.example.com and example.com that
  // a site lookup asks together then share com's referral
  private startFetch(run: Run, zone: string, name: string): (() => void) | undefined {
    if (!run.shared) return undefined;
    const { key, deeper } = stepDown(zone, name);
    if (!(deeper || isTopLevel(zone)) || this.fetches.has(key)) return undefined;
    let finish!: () => void;
    const fetch: Fetch = { done: new Promise<void>(resolve => (finish = resolve)) };
    this.fetches.set(key, fetch);
    return () => {
      if (this.fetches.get(key) === fetch) this.fetches.delete(key);
      finish();
    };
  }

  // whether a zone's servers hand out referrals, so that waiting for another walk's question
  // to them may bring back a delegation: the root and the top-level domains do, and so does
  // a zone this resolver has seen give one and not seen answer for a name further down
  // itself. Most other zones answer for the names under them, and waiting there would only
  // cost the waiter time
  private refers(run: Run, zone: string): boolean {
    return isTopLevel(zone) || run.knowledge.zones.get(zone) === 'refers';
  }

  // remember how a zone answered a question about a name, for `refers`
  private learnZone(run: Run, zone: string, name: string, step: Step | undefined): void {
    if (!step || run.knowledge.zones.get(zone) === 'answers') return;
    if (step.outcome.kind === 'referral') run.knowledge.zones.set(zone, 'refers');
    else if (step.result.message.flags.aa && stepDown(zone, name).deeper) {
      run.knowledge.zones.set(zone, 'answers');
    }
  }

  // wait for another run's fetch no longer than this walk has left, and no longer than its
  // caller is willing to wait. However it ends, the walk then carries on with what is known
  private async awaitFetch(run: Run, fetch: Fetch): Promise<void> {
    if (run.signal?.aborted) throw run.signal.reason;
    await withRest(
      run,
      left =>
        new Promise<void>((resolve, reject) => {
          const timer = left <= MAX_TIMER ? setTimeout(resolve, left) : undefined;
          const abort = () => reject(run.signal?.reason);
          run.signal?.addEventListener('abort', abort, { once: true });
          void fetch.done.then(() => {
            clearTimeout(timer);
            run.signal?.removeEventListener('abort', abort);
            resolve();
          });
        })
    );
  }

  // follow referrals from the closest known zone until a server answers for the name.
  // `nesting` is how many nameserver lookups deep this is. `first`: an address to ask
  // before the zone's other servers, where it is one of them
  private async resolve(
    run: Run,
    name: string,
    type: string,
    trace: TraceHop[] | undefined,
    nesting: number,
    first?: string
  ): Promise<Step> {
    const maxHops = this.options.maxHops ?? DEFAULT_MAX_HOPS;
    // a DS RRset is the parent's: the question goes to the zone above the name, even when
    // the name's own zone is already known (RFC 4035 §4.2)
    const owner = type === 'DS' && name !== '.' ? parentName(name) : name;
    // the walk itself starts where the caller said, when it said, and at the root when it
    // is `fromRoot`; a nameserver lookup starts at the deepest zone known, or the root
    const fromRoot = nesting === 0 && run.fromRoot;
    let cut =
      run.start && nesting === 0
        ? { zone: '.', servers: run.start, expires: Infinity }
        : fromRoot
          ? this.rootCut()
          : this.closestCut(run, owner);
    // the zones this walk has already waited at, so it waits at each at most once
    const waited = new Set<string>();

    for (;;) {
      // another run is asking this zone's servers about a name on the same way down: wait
      // for the delegation it brings back rather than ask them the same thing. Only the walk
      // itself waits, never a nameserver lookup, which may be what that run is waiting on.
      // Whatever came of it, a delegation further down is taken up, and otherwise the walk
      // asks for itself: another run's failure or timeout is not this one's. It waits only
      // at a zone that hands out referrals
      const down = stepDown(cut.zone, name);
      const pending =
        run.shared &&
        nesting === 0 &&
        !fromRoot &&
        down.deeper &&
        !waited.has(cut.zone) &&
        this.refers(run, cut.zone)
          ? this.fetches.get(down.key)
          : undefined;
      if (pending) {
        waited.add(cut.zone);
        await this.awaitFetch(run, pending);
        const closer = this.closestCut(run, owner);
        if (closer.zone !== cut.zone && isSubdomain(closer.zone, cut.zone)) {
          cut = closer;
          continue;
        }
      }
      const finishFetch = this.startFetch(run, cut.zone, name);

      // ask the zone's servers in turn until one gives something to go on
      let step: Step | undefined;
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
      try {
        const order = shuffled(cut.servers);
        const ahead = first ? order.findIndex(server => server.addresses?.includes(first)) : -1;
        if (ahead > 0) order.unshift(...order.splice(ahead, 1));
        const turns = order.map(server => ({
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
              // truncated over UDP, and TCP failed. A delegation in what did arrive is
              // followed, and the zone's own answer is the answer, TC and all. Anything
              // else gives nothing to go on: the server failed the way its TCP retry did
              const tcpFailure = tcpFallbackFailure(result);
              if (
                tcpFailure &&
                !result.message.flags.aa &&
                (outcome.kind === 'answer' || outcome.kind === 'alias')
              ) {
                throw tcpFailure;
              }
              Object.assign(hop, {
                transport: result.transport,
                rcode: result.message.rcode,
                rcodeName: rcodeName(result.message.rcode),
                bytes: result.bytes.length,
                elapsed: now() - hopStarted,
                ...(outcome.kind === 'referral' && {
                  referral: outcome.cut.written ?? outcome.cut.zone,
                }),
                ...(result.tcpFallbackError && { tcpFallbackError: result.tcpFallbackError }),
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
        // a delegation with a TTL of zero is used for this walk and not kept, and so is one
        // from a truncated referral whose TCP retry failed: it may name only some of the
        // zone's servers. A delegation that is kept is kept before the runs waiting on this
        // one are told, so they find it; when there is none they ask for themselves
        this.learnZone(run, cut.zone, name, step);
        if (
          step?.outcome.kind === 'referral' &&
          !step.result.tcpFallbackError &&
          step.outcome.cut.expires > Date.now()
        ) {
          run.knowledge.cuts.set(step.outcome.cut.zone, step.outcome.cut);
        }
      } finally {
        finishFetch?.();
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

    if (this.options.nameserverCache === false) return this.lookUpHere(run, server, nesting);
    for (;;) {
      // another query is looking this nameserver up already: its answer is this one's too.
      // Only the walk itself waits on another query's lookup, never a lookup: a lookup that
      // waited could end up waiting on one that waits on it
      let lookup = this.lookups.get(name);
      if (lookup && nesting > 0) return this.lookUpHere(run, server, nesting);
      lookup ??= this.startLookup(run, server, nesting);
      const { addresses, cutShort, failures } = await this.join(run, lookup);
      // each walk that waited lists what went wrong on the way, as its own lookup would have
      if (failures?.length) run.failures.push(...failures);
      // the lookup ran out of its own time, or this walk ran out of its own: one with time
      // left looks again rather than take someone else's deadline as the answer
      if (cutShort && addresses.length === 0 && !outOfTime(run)) continue;
      run.lookedUp.set(name, addresses);
      return addresses;
    }
  }

  // look a nameserver up on this walk's own time, for this walk alone
  private async lookUpHere(run: Run, server: Nameserver, nesting: number): Promise<string[]> {
    run.resolving.add(server.name);
    try {
      return await this.lookUp(run, server, nesting);
    } finally {
      run.resolving.delete(server.name);
    }
  }

  // look a nameserver up for every query that meets it while the lookup lasts. It has a
  // whole query's time of its own, from now, however little the query that started it has
  // left: a query that joins later may have more. It stops when the last query waiting on
  // it gives up, and when the resolver is closed
  private startLookup(starter: Run, server: Nameserver, nesting: number): SharedLookup {
    const { name } = server;
    const totalTimeout = Math.max(
      starter.totalTimeout,
      this.options.totalTimeout ?? DEFAULT_TOTAL_TIMEOUT
    );
    const stop = new AbortController();
    const run: Run = {
      // what the starter knows and how it asks, and the starter hears of the queries sent
      ...starter,
      signal: stop.signal,
      start: undefined,
      deadline: now() + totalTimeout,
      totalTimeout,
      expired: false,
      attempts: 0,
      resolving: new Set([...starter.resolving, name]),
      lookedUp: new Map(starter.lookedUp),
      // its own, since it can outlive the starter, whose error may already carry its list
      failures: [],
    };
    const hopsBefore = run.hops;
    const lookup: SharedLookup = {
      done: (async () => {
        try {
          const addresses = await this.lookUp(run, server, nesting);
          return {
            addresses,
            cutShort: outOfTime(run) || stop.signal.aborted,
            failures: run.failures,
          };
        } catch (error) {
          // stopped: by the resolver closing, or with nobody left waiting
          if (stop.signal.aborted) return { addresses: [], cutShort: true, failures: run.failures };
          throw error;
        } finally {
          // the servers it asked count against the query that started it, as its own would
          starter.attempts += run.attempts;
          starter.hops += run.hops - hopsBefore;
          if (this.lookups.get(name)?.stop === stop) this.lookups.delete(name);
        }
      })(),
      name,
      stop,
      waiting: 0,
    };
    // nobody may be waiting to hear that it failed
    lookup.done.catch(() => undefined);
    this.lookups.set(name, lookup);
    return lookup;
  }

  // wait for a shared lookup no longer than this walk has left, and no longer than its
  // caller is willing to wait. The lookup stops when the last walk waiting on it leaves
  private async join(run: Run, lookup: SharedLookup): Promise<LookupResult> {
    if (run.signal?.aborted) throw run.signal.reason;
    lookup.waiting++;
    try {
      return await withRest(
        run,
        left =>
          new Promise<LookupResult>((resolve, reject) => {
            const timer =
              left <= MAX_TIMER
                ? setTimeout(() => resolve({ addresses: [], cutShort: true }), left)
                : undefined;
            const abort = () => reject(run.signal?.reason);
            run.signal?.addEventListener('abort', abort, { once: true });
            lookup.done.then(resolve, reject).finally(() => {
              clearTimeout(timer);
              run.signal?.removeEventListener('abort', abort);
            });
          })
      );
    } finally {
      if (--lookup.waiting === 0) {
        lookup.stop.abort();
        if (this.lookups.get(lookup.name) === lookup) this.lookups.delete(lookup.name);
      }
    }
  }

  // resolve a nameserver's addresses from the root, and keep what was found
  private async lookUp(run: Run, server: Nameserver, nesting: number): Promise<string[]> {
    const { name } = server;
    const family = this.options.addressFamily ?? 'both';
    const types = family === 'ipv4' ? ['A'] : family === 'ipv6' ? ['AAAA'] : ['A', 'AAAA'];
    const found: string[] = [];
    let ttl = Infinity;
    // the server that answered for one family is asked first for the next. The order puts a
    // dead server of the nameserver's zone first as often for the second question as for the
    // first, and waiting for it twice can be all the time the walk waiting on this lookup has
    let answered: string | undefined;
    for (const type of types) {
      try {
        const { result } = await this.resolve(run, name, type, undefined, nesting + 1, answered);
        answered = result.server;
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
              onEvent: eventsTo(this.options.onEvent, run.onEvent),
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

// what a zone's servers are asked about, as far as the delegation they refer it to goes:
// the name one label below the zone on the way to it, so questions about www.example.com
// and example.com both ask the root about com. `deeper`: the name lies below that one, so
// the servers can only refer it on. A name one label below the zone may be answered by the
// zone itself, and waiting for another question about it would most often be for nothing
function stepDown(zone: string, name: string): { key: string; deeper: boolean } {
  const labels = splitName(name);
  const below = zone === '.' ? 0 : splitName(zone).length;
  const next = labels.length > below ? labels.slice(labels.length - below - 1).join('.') : name;
  return { key: `${zone} ${next}`, deeper: labels.length > below + 1 };
}

// the root or a top-level domain
const isTopLevel = (zone: string): boolean => zone === '.' || splitName(zone).length === 1;

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

// one listener that tells both, either of which may be missing
function eventsTo(first: OnEvent | undefined, second: OnEvent | undefined): OnEvent | undefined {
  if (!first || !second) return first ?? second;
  return event => {
    first(event);
    second(event);
  };
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
