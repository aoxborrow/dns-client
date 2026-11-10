import {
  DnsError,
  errorData,
  InvalidQueryError,
  InvalidResponseError,
  TimeoutError,
} from '../errors';
import { exchange, hasTransportOptions } from '../exchange';
import type { ExchangeResult } from '../exchange';
import { RCODES, rcodeName } from '../protocol/header';
import { typeCode, typeName } from '../protocol/types';
import { parseIpv4, parseIpv6 } from '../records/addresses';
import { decodeRecords } from '../records/decode';
import type { DnsRecord, KnownRecordType, RecordOf } from '../records/types';
import { isIp, isIpv4, isIpv6, normalizeAddress } from '../transports/endpoint';
import { createTransports, defaultTransports } from '../transports/index';
import type { Transports } from '../transports/index';
import { now } from '../transports/runtime';
import type { OnEvent, TransportOptions } from '../transports/types';
import { canonicalName, compareNames, isSubdomain, parentName, toAsciiName } from '../wire/names';
import { buildAnswer } from './answer';
import type { Answer, QuerySettings, TraceHop } from './answer';
import { createLimiter, createPacer } from './limiter';
import type { Limiter } from './limiter';
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
  // which of a nameserver's addresses to use. Default IPv4 only: a host with no IPv6
  // route would otherwise wait out a timeout at every step
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
  // each address of each of them. Default 30000
  totalTimeout?: number;
  // addresses for nameservers by name, used before asking for them. Also what puts a
  // name beside an address in the trace
  hosts?: Readonly<Record<string, string | readonly string[]>>;
  // the order a zone's nameservers are tried in, as a comparator over their names.
  // Default: canonical DNS name order, which is the same on every run
  nameserverOrder?: (a: string, b: string) => number;
  // the order one nameserver's addresses are tried in, within a family. Default: by the
  // address as a number, which is the same on every run whatever order they arrived in
  addressOrder?: (a: string, b: string) => number;
  // find a nameserver's addresses some other way before it is resolved from the root: a
  // local cache, another resolver. Return nothing to leave it to the resolver
  resolveNameserver?: (
    name: string
  ) => Promise<readonly string[] | undefined> | readonly string[] | undefined;
  // remember delegations and nameserver addresses between queries, for as long as their
  // TTLs allow. Default true. With false every query starts again from the root
  cache?: boolean;
  // the least time between two queries to the same server, in milliseconds. Default 0
  serverDelay?: number;
  // how many queries may be in flight at once. Default: no limit
  concurrency?: number;
  // malformed record data is an error. By default such a record comes back in the
  // generic form
  strict?: boolean;
  onEvent?: OnEvent;
  // sockets and connections to share with other resolvers. The resolver does not close
  // a set it was given
  transports?: Transports;
}

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
  // undefined until looked up; empty when the lookup found none
  addresses?: string[];
}

interface ZoneCut {
  zone: string;
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
  // servers asked so far, against `maxHops`
  hops: number;
  attempts: number;
  // nameserver names being looked up right now, to notice a lookup that needs itself
  resolving: Set<string>;
}

// two addresses of one family by their value
function compareAddresses(a: string, b: string): number {
  const x = parseIpv4(a) ?? parseIpv6(a.split('%')[0]);
  const y = parseIpv4(b) ?? parseIpv6(b.split('%')[0]);
  if (!x || !y || x.length !== y.length) return 0;
  for (let index = 0; index < x.length; index++) {
    if (x[index] !== y[index]) return x[index] - y[index];
  }
  return 0;
}

const DEFAULT_MAX_HOPS = 40;
const DEFAULT_TOTAL_TIMEOUT = 30_000;
// the patience with one server when the caller names none: the same as `exchange` has
const DEFAULT_TIMEOUT = 5000;
const DEFAULT_MAX_ALIASES = 8;
// how deep nameserver lookups may nest: a nameserver whose own nameserver needs looking up
const MAX_NESTING = 4;
// a delegation with no TTL to go by is kept this long, in seconds
const DEFAULT_CUT_TTL = 3600;

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
  private readonly pace: (server: string) => Promise<void>;
  private readonly transports: Transports;
  private readonly ownsTransports: boolean;
  private readonly knowledge: Knowledge = { cuts: new Map(), addresses: new Map() };
  private readonly root: Nameserver[];
  // address -> name, for the trace
  private readonly names = new Map<string, string>();
  private readonly hosts = new Map<string, string[]>();

  constructor(options: AuthoritativeResolverOptions = {}) {
    this.options = options;
    this.limit = createLimiter(options.concurrency ?? Infinity);
    this.pace = createPacer(options.serverDelay ?? 0);
    this.ownsTransports = !options.transports && hasTransportOptions(options);
    this.transports =
      options.transports ?? (this.ownsTransports ? createTransports(options) : defaultTransports());

    for (const [name, addresses] of Object.entries(options.hosts ?? {})) {
      const list = [addresses].flat().map(normalizeAddress);
      this.hosts.set(canonicalName(name), list);
      for (const address of list) this.names.set(address, canonicalName(name));
    }
    this.root = (options.rootServers ?? ROOT_HINTS).map(hint => {
      const name = hint.name ? canonicalName(hint.name) : '';
      const addresses = this.usable([hint.ipv4, hint.ipv6].filter(isString).map(normalizeAddress));
      for (const address of addresses) if (name) this.names.set(address, name);
      return { name, addresses };
    });
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
    const { signal, totalTimeout: perQuery, ...settings } = options;
    const totalTimeout = perQuery ?? this.options.totalTimeout ?? DEFAULT_TOTAL_TIMEOUT;
    const started = now();
    let asked: string;
    try {
      asked = canonicalName(toAsciiName(name));
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
      hops: 0,
      attempts: 0,
      resolving: new Set(),
    };

    const trace: TraceHop[] = [];
    const aliases: DnsRecord[] = [];
    const maxAliases = this.options.maxAliases ?? DEFAULT_MAX_ALIASES;
    const visited = new Set([asked]);
    let current = asked;
    for (;;) {
      const { result, outcome } = await this.resolve(run, current, typeText, trace, 0).catch(
        (error: unknown) => {
          // a walk that fails still says how far it got
          if (error instanceof DnsError) error.trace ??= trace;
          throw error;
        }
      );
      if (outcome.kind !== 'alias' || this.options.followCnames !== true) {
        return buildAnswer(result, {
          strict: this.options.strict,
          name: asked,
          before: aliases,
          trace,
          // the name of the nameserver that was asked: two names can share an address
          serverName:
            trace.filter(hop => hop.server === result.server).at(-1)?.serverName ??
            this.names.get(normalizeAddress(result.server)),
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

  // forget every delegation and nameserver address learned so far
  clearCache(): void {
    this.knowledge.cuts.clear();
    this.knowledge.addresses.clear();
  }

  // close the sockets and connections this resolver opened. A resolver that shares the
  // process-wide set, or was given one, leaves it open
  close(): void {
    this.clearCache();
    if (this.ownsTransports) this.transports.close();
  }

  // ---- inside

  // the addresses of a nameserver this resolver is willing to use
  private usable(addresses: readonly string[]): string[] {
    const family = this.options.addressFamily ?? 'ipv4';
    const order = this.options.addressOrder ?? compareAddresses;
    const v4 = addresses.filter(isIpv4).sort(order);
    // only addresses: anything else here would be read as a name, or a host and a port
    const v6 = addresses.filter(isIpv6).sort(order);
    if (family === 'ipv4') return v4;
    if (family === 'ipv6') return v6;
    return [...v4, ...v6];
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
    let cut = this.closestCut(run, name);

    for (;;) {
      // ask the zone's servers in turn until one gives something to go on
      let step: { result: ExchangeResult; outcome: Outcome } | undefined;
      let firstError: DnsError | undefined;
      let lastLame: ExchangeResult | undefined;
      const refusals = new Set<number>();
      let loop: string | undefined;

      servers: for (const server of cut.servers) {
        if (now() >= run.deadline) break;
        const addresses = await this.addressesOf(run, server, nesting);
        for (const address of addresses) {
          // out of time: what the zone's servers have said so far is all there will be
          if (now() >= run.deadline) break servers;
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
            zone: cut.zone,
            name,
            type,
            elapsed: 0,
            timestamp,
          };
          trace?.push(hop);
          try {
            const result = await this.ask(run, name, type, address);
            const outcome = this.read(result, name, type, cut.zone);
            Object.assign(hop, {
              transport: result.transport,
              rcode: result.message.rcode,
              rcodeName: rcodeName(result.message.rcode),
              bytes: result.bytes.length,
              elapsed: now() - hopStarted,
              ...(outcome.kind === 'referral' && { referral: outcome.cut.zone }),
            });
            if (outcome.kind === 'lame') {
              hop.error = {
                name: 'InvalidResponseError',
                message: outcome.reason,
                retryable: false,
              };
              if (outcome.loop) {
                loop = outcome.reason;
                continue servers;
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
              continue servers;
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
        if (now() >= run.deadline) {
          throw new TimeoutError(`No answer for ${name} ${type} within ${run.totalTimeout} ms`, {
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
      run.knowledge.cuts.set(cut.zone, cut);
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
      const answers = decodeRecords(message.answers, lenient);
      // records of the type asked for, at the name or at the end of its aliases
      if (type === 'ANY' || type === 'CNAME' || type === 'DNAME') return { kind: 'answer' };
      let owner = name;
      for (let i = 0; i <= answers.length; i++) {
        const alias = answers.find(
          record => record.type === 'CNAME' && canonicalName(record.name) === owner
        );
        if (!alias || alias.type !== 'CNAME') break;
        owner = canonicalName(alias.target);
      }
      const answered = answers.some(
        record => record.type === type && canonicalName(record.name) === owner
      );
      // an alias whose target this server did not answer for: it lives somewhere else
      if (!answered && owner !== name) return { kind: 'alias', target: owner };
      return { kind: 'answer' };
    }

    // no answer: a referral names the servers of a zone further down
    const authorities = decodeRecords(message.authorities, lenient);
    const delegations = authorities.filter(
      (record): record is Extract<DnsRecord, { type: 'NS' }> => record.type === 'NS'
    );
    if (delegations.length === 0 || message.flags.aa) return { kind: 'answer' };

    const child = canonicalName(delegations[0].name);
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
      .sort(this.options.nameserverOrder ?? compareNames)
      .map(target => {
        const addresses = glue
          .filter(
            (record): record is Extract<DnsRecord, { type: 'A' | 'AAAA' }> =>
              (record.type === 'A' || record.type === 'AAAA') &&
              canonicalName(record.name) === target
          )
          .map(record => normalizeAddress(record.address));
        const shown = written.get(target);
        for (const address of addresses) this.names.set(address, shown ?? target);
        const usable = this.usable(addresses);
        // without usable glue the address is looked up when the server is first needed
        return {
          name: target,
          ...(shown && { written: shown }),
          ...(usable.length > 0 && { addresses: usable }),
        };
      });

    const ttl = Math.min(...delegations.map(record => record.ttl)) || DEFAULT_CUT_TTL;
    return {
      kind: 'referral',
      cut: { zone: child, servers, expires: Date.now() + ttl * 1000 },
    };
  }

  // a nameserver's addresses: from the referral's glue, the host map, what was learned
  // earlier, or by resolving its name from the root like any other
  private async addressesOf(run: Run, server: Nameserver, nesting: number): Promise<string[]> {
    if (server.addresses) return server.addresses;
    const { name } = server;
    if (isIp(name)) return this.usable([normalizeAddress(name)]);

    const known = this.hosts.get(name);
    if (known) return (server.addresses = this.usable(known));
    const learned = run.knowledge.addresses.get(name);
    if (learned && learned.expires > Date.now()) return (server.addresses = learned.addresses);

    // a nameserver that can only be found by asking itself, or a chain of them too deep
    // to be worth following, is skipped: the zone's other servers may do
    if (run.resolving.has(name) || nesting >= MAX_NESTING) return [];
    run.resolving.add(name);
    try {
      // the caller's own way of finding it comes first
      if (this.options.resolveNameserver) {
        const supplied = await this.options.resolveNameserver(server.written ?? name);
        if (supplied?.length) {
          const normalized = supplied.map(normalizeAddress);
          for (const address of normalized) this.names.set(address, server.written ?? name);
          const usable = this.usable(normalized);
          run.knowledge.addresses.set(name, {
            addresses: usable,
            expires: Date.now() + DEFAULT_CUT_TTL * 1000,
          });
          return (server.addresses = usable);
        }
      }
      const family = this.options.addressFamily ?? 'ipv4';
      const types = family === 'ipv4' ? ['A'] : family === 'ipv6' ? ['AAAA'] : ['A', 'AAAA'];
      const found: string[] = [];
      let ttl = DEFAULT_CUT_TTL;
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
      for (const address of found) this.names.set(address, server.written ?? name);
      const addresses = this.usable(found);
      if (addresses.length > 0) {
        run.knowledge.addresses.set(name, { addresses, expires: Date.now() + ttl * 1000 });
      }
      return (server.addresses = addresses);
    } finally {
      run.resolving.delete(name);
    }
  }

  // one question to one server, the way an authoritative server is asked: no recursion
  private async ask(
    run: Run,
    name: string,
    type: string,
    address: string
  ): Promise<ExchangeResult> {
    const merged = { ...this.options, ...run.settings };
    await this.pace(address);
    const result = await this.limit(() =>
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
          // no longer than what is left of the time for the whole query
          timeout: Math.max(1, Math.min(merged.timeout ?? DEFAULT_TIMEOUT, run.deadline - now())),
          tcpFallback: merged.tcpFallback,
          // the zone has other servers to turn to, so less patience with each
          retries: merged.retries ?? 1,
          transports: this.transports,
          onEvent: this.options.onEvent,
          signal: run.signal,
        }
      )
    );
    run.attempts += result.attempts;
    return result;
  }
}

const isString = (value: string | undefined): value is string => typeof value === 'string';
