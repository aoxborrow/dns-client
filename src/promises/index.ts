// @aoxborrow/dns/promises: the `node:dns/promises` API over the library's `Resolver`.
// The same functions, a `Resolver` class, the same return shapes and errors shaped like
// Node's, so code written for `node:dns/promises` changes only its import. Node only: it
// reads the hosts file and the machine's DNS settings.
//
// `connectLookup` is `lookup` in the callback form `net.connect`, `tls.connect`,
// `http.Agent` and undici's `connect` option take.
//
// not here: `lookupService` (it needs the system's service database), `setLocalAddress`,
// and the hosts file for anything but `lookup`, as in Node
import { ParseError } from '../errors';
import { reverseIp } from '../records/addresses';
import type { DnsRecord, KnownRecordType } from '../records/types';
import { Resolver as LibraryResolver } from '../resolvers/index';
import type { ResolverOptions as LibraryResolverOptions } from '../resolvers/index';
import { hasTransportOptions } from '../exchange';
import { createTransports, defaultTransports } from '../transports/index';
import type { Transports } from '../transports/index';
import { configuredServers } from '../transports/host';
import type { Server } from '../transports/types';
import { argumentError, checkHostname, failureCode, nodeError, rcodeError } from './errors';
import type { NodeDnsError } from './errors';
import { ipFamily, lookupAddresses, lookupSettings } from './lookup';
import type {
  LookupAddress,
  LookupAllOptions,
  LookupOneOptions,
  LookupOptions,
  ResultOrder,
} from './lookup';
import { toAnyList, toCaa, toMx, toNaptr, toSoa, toSrv, toTlsa } from './records';
import type {
  AnyRecord,
  CaaRecord,
  MxRecord,
  NaptrRecord,
  RecordWithTtl,
  SoaRecord,
  SrvRecord,
  TlsaRecord,
} from './records';

export type * from './records';
export type { NodeDnsError } from './errors';
export type {
  LookupAddress,
  LookupAllOptions,
  LookupOneOptions,
  LookupOptions,
  ResultOrder,
} from './lookup';
export { ADDRCONFIG, ALL, V4MAPPED } from './lookup';

// Node's error codes, under Node's names
export const NODATA = 'ENODATA';
export const FORMERR = 'EFORMERR';
export const SERVFAIL = 'ESERVFAIL';
export const NOTFOUND = 'ENOTFOUND';
export const NOTIMP = 'ENOTIMP';
export const REFUSED = 'EREFUSED';
export const BADNAME = 'EBADNAME';
export const BADRESP = 'EBADRESP';
export const CONNREFUSED = 'ECONNREFUSED';
export const TIMEOUT = 'ETIMEOUT';
export const CANCELLED = 'ECANCELLED';

// the library's resolver options, and Node's `timeout` (milliseconds per attempt, as in
// the library) and `tries` (attempts per server). `maxTimeout` is not supported
export interface ResolverOptions extends LibraryResolverOptions {
  tries?: number;
}

export interface ResolveOptions {
  ttl: boolean;
}

export interface ResolveWithTtlOptions extends ResolveOptions {
  ttl: true;
}

export type LookupCallback = (
  error: Error | null,
  address: string | LookupAddress[],
  family?: number
) => void;

// `syscall` in Node's errors, per record type
const SYSCALLS: Record<string, string> = {
  A: 'queryA',
  AAAA: 'queryAaaa',
  ANY: 'queryAny',
  CAA: 'queryCaa',
  CNAME: 'queryCname',
  MX: 'queryMx',
  NAPTR: 'queryNaptr',
  NS: 'queryNs',
  PTR: 'queryPtr',
  SOA: 'querySoa',
  SRV: 'querySrv',
  TLSA: 'queryTlsa',
  TXT: 'queryTxt',
};

let defaultOrder: ResultOrder = 'verbatim';

export function getDefaultResultOrder(): ResultOrder {
  return defaultOrder;
}

export function setDefaultResultOrder(order: ResultOrder): void {
  if (!['ipv4first', 'ipv6first', 'verbatim'].includes(order)) {
    throw argumentError(`The argument 'order' is invalid. Received ${String(order)}`);
  }
  defaultOrder = order;
}

// a server as Node writes it: `1.1.1.1`, `1.1.1.1:5353`, `2001:db8::1`, `[2001:db8::1]:5353`,
// read with Node's own rules. Port 0 and ports above 65535 are refused, where Node accepts
// them and then fails an assertion in c-ares
function parseServer(text: string): Server {
  const fail = () => argumentError(`Invalid IP address: ${text}`, 'ERR_INVALID_IP_ADDRESS');
  let address = text;
  let port: number | undefined;
  if (!ipFamily(text)) {
    const bracketed = /^\[([^[\]]*)\](?::(\d+))?/.exec(text);
    const split = /(^.+?)(?::(\d+))?$/.exec(text);
    if (bracketed && ipFamily(bracketed[1])) {
      address = bracketed[1];
      port = bracketed[2] === undefined ? undefined : Number(bracketed[2]);
    } else if (split && ipFamily(split[1])) {
      address = split[1];
      port = split[2] === undefined ? undefined : Number(split[2]);
    } else throw fail();
  }
  if (port !== undefined && (port < 1 || port > 0xffff)) throw fail();
  return port === undefined || port === 53 ? { address } : { address, port };
}

function formatServer(server: Server): string {
  if (server.port === undefined || server.port === 53) return server.address;
  return server.address.includes(':')
    ? `[${server.address}]:${server.port}`
    : `${server.address}:${server.port}`;
}

export class Resolver {
  readonly #options: ResolverOptions;
  readonly #transports: Transports;
  readonly #ownsTransports: boolean;
  #resolver: LibraryResolver;
  #servers: Server[] | undefined;
  // rejecters of the calls in progress, for `cancel()`
  readonly #pending = new Set<(code: string) => void>();

  constructor(options: ResolverOptions = {}) {
    if (options.tries !== undefined && (!Number.isInteger(options.tries) || options.tries < 1)) {
      throw argumentError(`The property 'options.tries' must be >= 1. Received ${options.tries}`);
    }
    // Node's -1 is "the default"
    const timeout = options.timeout === -1 ? undefined : options.timeout;
    this.#options = {
      ...options,
      timeout,
      ...(options.tries !== undefined && { retries: options.tries - 1 }),
    };
    // one set of sockets for the resolver's life, so changing servers keeps them
    this.#ownsTransports = !options.transports && hasTransportOptions(options);
    this.#transports =
      options.transports ??
      (this.#ownsTransports ? createTransports(options) : defaultTransports());
    this.#servers = options.servers?.map(server =>
      typeof server === 'string' ? parseServer(server) : server
    );
    this.#resolver = this.#make();
  }

  // the servers asked, in Node's format. The machine's own until `setServers` is called
  getServers(): string[] {
    return this.#servers ? this.#servers.map(formatServer) : configuredServers();
  }

  setServers(servers: readonly string[]): void {
    if (!Array.isArray(servers)) {
      throw argumentError(
        'The "servers" argument must be an instance of Array.',
        'ERR_INVALID_ARG_TYPE'
      );
    }
    const parsed = servers.map(server => parseServer(checkHostname(server, 'servers')));
    const previous = this.#resolver;
    this.#servers = parsed;
    this.#resolver = this.#make();
    // the old resolver's cache is for the old servers
    previous.close();
  }

  // every call in progress rejects with ECANCELLED. What was already sent is still
  // answered, into the cache
  cancel(): void {
    for (const reject of [...this.#pending]) reject('ECANCELLED');
  }

  // closes the sockets this resolver opened and empties its cache. Not in Node, whose
  // resolvers need no closing; neither do these, whose sockets never keep a process alive
  close(): void {
    this.#resolver.close();
    if (this.#ownsTransports) this.#transports.close();
  }

  resolve(hostname: string): Promise<string[]>;
  resolve(hostname: string, rrtype: 'A' | 'AAAA' | 'CNAME' | 'NS' | 'PTR'): Promise<string[]>;
  resolve(hostname: string, rrtype: 'ANY'): Promise<AnyRecord[]>;
  resolve(hostname: string, rrtype: 'CAA'): Promise<CaaRecord[]>;
  resolve(hostname: string, rrtype: 'MX'): Promise<MxRecord[]>;
  resolve(hostname: string, rrtype: 'NAPTR'): Promise<NaptrRecord[]>;
  resolve(hostname: string, rrtype: 'SOA'): Promise<SoaRecord>;
  resolve(hostname: string, rrtype: 'SRV'): Promise<SrvRecord[]>;
  resolve(hostname: string, rrtype: 'TLSA'): Promise<TlsaRecord[]>;
  resolve(hostname: string, rrtype: 'TXT'): Promise<string[][]>;
  resolve(
    hostname: string,
    rrtype: string
  ): Promise<
    | string[]
    | CaaRecord[]
    | MxRecord[]
    | NaptrRecord[]
    | SoaRecord
    | SrvRecord[]
    | TlsaRecord[]
    | string[][]
    | AnyRecord[]
  >;
  resolve(hostname: string, rrtype = 'A'): Promise<unknown> {
    switch (rrtype) {
      case 'A':
        return this.resolve4(hostname);
      case 'AAAA':
        return this.resolve6(hostname);
      case 'ANY':
        return this.resolveAny(hostname);
      case 'CAA':
        return this.resolveCaa(hostname);
      case 'CNAME':
        return this.resolveCname(hostname);
      case 'MX':
        return this.resolveMx(hostname);
      case 'NAPTR':
        return this.resolveNaptr(hostname);
      case 'NS':
        return this.resolveNs(hostname);
      case 'PTR':
        return this.resolvePtr(hostname);
      case 'SOA':
        return this.resolveSoa(hostname);
      case 'SRV':
        return this.resolveSrv(hostname);
      case 'TLSA':
        return this.resolveTlsa(hostname);
      case 'TXT':
        return this.resolveTxt(hostname);
      default:
        if (typeof rrtype !== 'string') {
          throw argumentError(
            `The "rrtype" argument must be of type string. Received type ${typeof rrtype}`,
            'ERR_INVALID_ARG_TYPE'
          );
        }
        throw argumentError(`The argument 'rrtype' is invalid. Received '${String(rrtype)}'`);
    }
  }

  resolve4(hostname: string): Promise<string[]>;
  resolve4(hostname: string, options: ResolveWithTtlOptions): Promise<RecordWithTtl[]>;
  resolve4(hostname: string, options: ResolveOptions): Promise<string[] | RecordWithTtl[]>;
  resolve4(hostname: string, options?: ResolveOptions): Promise<string[] | RecordWithTtl[]> {
    return this.#addresses(hostname, 'A', options);
  }

  resolve6(hostname: string): Promise<string[]>;
  resolve6(hostname: string, options: ResolveWithTtlOptions): Promise<RecordWithTtl[]>;
  resolve6(hostname: string, options: ResolveOptions): Promise<string[] | RecordWithTtl[]>;
  resolve6(hostname: string, options?: ResolveOptions): Promise<string[] | RecordWithTtl[]> {
    return this.#addresses(hostname, 'AAAA', options);
  }

  resolveAny(hostname: string): Promise<AnyRecord[]> {
    return this.#records(hostname, 'ANY', (records, aliasTtl) => toAnyList(records, aliasTtl));
  }

  resolveCaa(hostname: string): Promise<CaaRecord[]> {
    return this.#typed(hostname, 'CAA', toCaa);
  }

  resolveCname(hostname: string): Promise<string[]> {
    return this.#typed(hostname, 'CNAME', record => record.target);
  }

  resolveMx(hostname: string): Promise<MxRecord[]> {
    return this.#typed(hostname, 'MX', toMx);
  }

  resolveNaptr(hostname: string): Promise<NaptrRecord[]> {
    return this.#typed(hostname, 'NAPTR', toNaptr);
  }

  resolveNs(hostname: string): Promise<string[]> {
    return this.#typed(hostname, 'NS', record => record.target);
  }

  resolvePtr(hostname: string): Promise<string[]> {
    return this.#typed(hostname, 'PTR', record => record.target);
  }

  resolveSoa(hostname: string): Promise<SoaRecord> {
    return this.#typed(hostname, 'SOA', toSoa).then(([soa]) => {
      if (!soa) throw nodeError('ENODATA', SYSCALLS.SOA, hostname);
      return soa;
    });
  }

  resolveSrv(hostname: string): Promise<SrvRecord[]> {
    return this.#typed(hostname, 'SRV', toSrv);
  }

  resolveTlsa(hostname: string): Promise<TlsaRecord[]> {
    return this.#typed(hostname, 'TLSA', toTlsa);
  }

  resolveTxt(hostname: string): Promise<string[][]> {
    return this.#typed(hostname, 'TXT', record => record.strings);
  }

  // the names an address has: its PTR records under in-addr.arpa or ip6.arpa
  reverse(ip: string): Promise<string[]> {
    checkHostname(ip, 'ip');
    if (!ipFamily(ip)) {
      return Promise.reject(nodeError('EINVAL', 'getHostByAddr', ip, { errno: -22 }));
    }
    return this.#run(ip, 'PTR', reverseIp(ip.split('%')[0]), 'getHostByAddr', records =>
      records.flatMap(record => (record.type === 'PTR' ? [record.target] : []))
    );
  }

  lookup(hostname: string, family: number): Promise<LookupAddress>;
  lookup(hostname: string, options: LookupOneOptions): Promise<LookupAddress>;
  lookup(hostname: string, options: LookupAllOptions): Promise<LookupAddress[]>;
  lookup(hostname: string, options: LookupOptions): Promise<LookupAddress | LookupAddress[]>;
  lookup(hostname: string): Promise<LookupAddress>;
  lookup(
    hostname: string,
    options?: number | LookupOptions
  ): Promise<LookupAddress | LookupAddress[]> {
    // bad arguments are thrown, not rejected, as in Node
    checkHostname(hostname, 'hostname');
    const { all } = lookupSettings(options, defaultOrder);
    return lookupAddresses(hostname, options, defaultOrder, (name, family) =>
      this.#typed(name, family === 4 ? 'A' : 'AAAA', record => record.address)
    ).then(addresses => (all ? addresses : addresses[0]));
  }

  // `lookup` with a callback, for the `lookup` option of `net.connect`, `tls.connect`,
  // `http.Agent` and undici. Bound, so it can be passed as it is
  readonly connectLookup = (
    hostname: string,
    options: number | LookupOptions | LookupCallback,
    callback?: LookupCallback
  ): void => {
    const done = (typeof options === 'function' ? options : callback) as LookupCallback;
    const given = typeof options === 'function' ? undefined : options;
    if (typeof done !== 'function') {
      throw argumentError(
        'The "callback" argument must be of type function.',
        'ERR_INVALID_ARG_TYPE'
      );
    }
    // bad arguments throw here, before any callback, as in Node
    checkHostname(hostname, 'hostname');
    const { all } = lookupSettings(given, defaultOrder);
    lookupAddresses(hostname, given, defaultOrder, (name, family) =>
      this.#typed(name, family === 4 ? 'A' : 'AAAA', record => record.address)
    ).then(
      addresses => {
        if (all) done(null, addresses);
        else done(null, addresses[0].address, addresses[0].family);
      },
      (error: Error) => (done as (error: Error) => void)(error)
    );
  };

  // ---- inside

  #make(): LibraryResolver {
    return new LibraryResolver({
      ...this.#options,
      servers: this.#servers,
      transports: this.#transports,
    });
  }

  #addresses(
    hostname: string,
    type: 'A' | 'AAAA',
    options?: ResolveOptions
  ): Promise<string[] | RecordWithTtl[]> {
    if (options?.ttl === true) {
      return this.#typed(hostname, type, (record, aliasTtl) => ({
        address: record.address,
        ttl: Math.min(record.ttl, aliasTtl),
      }));
    }
    return this.#typed(hostname, type, record => record.address);
  }

  #typed<Type extends KnownRecordType, Out>(
    hostname: string,
    type: Type,
    convert: (record: Extract<DnsRecord, { type: Type }>, aliasTtl: number) => Out
  ): Promise<Out[]> {
    return this.#records(hostname, type, (records, aliasTtl) =>
      records.flatMap(record =>
        record.type === type
          ? [convert(record as Extract<DnsRecord, { type: Type }>, aliasTtl)]
          : []
      )
    );
  }

  #records<Out>(
    hostname: string,
    type: string,
    convert: (records: DnsRecord[], aliasTtl: number) => Out
  ): Promise<Out> {
    // a name that is not a string is thrown, not rejected, as in Node
    checkHostname(hostname);
    return this.#run(hostname, type, hostname, SYSCALLS[type], convert);
  }

  // ask, and turn what comes back into Node's result or Node's error. A response with no
  // records in its answer section is ENODATA; one with records, none of the type asked
  // for, is an empty list, as c-ares has it
  #run<Out>(
    hostname: string,
    type: string,
    name: string,
    syscall: string,
    convert: (records: DnsRecord[], aliasTtl: number) => Out
  ): Promise<Out> {
    return new Promise<Out>((resolve, reject) => {
      const cancel = (code: string) => {
        this.#pending.delete(cancel);
        reject(nodeError(code, syscall, hostname));
      };
      this.#pending.add(cancel);
      this.#resolver.query(name, type).then(
        answer => {
          this.#pending.delete(cancel);
          const code =
            rcodeError(answer.rcode) ?? (answer.answers.length === 0 ? 'ENODATA' : undefined);
          if (code) reject(nodeError(code, syscall, hostname));
          else {
            // an address reached through an alias lives no longer than the alias, as c-ares
            // reports it
            const aliasTtl = Math.min(
              ...answer.answers.flatMap(record =>
                record.type === 'CNAME' || record.type === 'DNAME' ? [record.ttl] : []
              )
            );
            resolve(convert(answer.records, aliasTtl));
          }
        },
        (error: unknown) => {
          this.#pending.delete(cancel);
          // a record the server sent that does not decode is a bad response, as in c-ares
          const code = error instanceof ParseError ? 'EBADRESP' : failureCode(error);
          reject(nodeError(code, syscall, hostname, { cause: error }));
        }
      );
    });
  }
}

// the process-wide resolver the functions below use, as `node:dns/promises` has one
const shared = new Resolver();

export const getServers = (): string[] => shared.getServers();
export const setServers = (servers: readonly string[]): void => shared.setServers(servers);

export const resolve: Resolver['resolve'] = shared.resolve.bind(shared);
export const resolve4: Resolver['resolve4'] = shared.resolve4.bind(shared);
export const resolve6: Resolver['resolve6'] = shared.resolve6.bind(shared);
export const resolveAny: Resolver['resolveAny'] = shared.resolveAny.bind(shared);
export const resolveCaa: Resolver['resolveCaa'] = shared.resolveCaa.bind(shared);
export const resolveCname: Resolver['resolveCname'] = shared.resolveCname.bind(shared);
export const resolveMx: Resolver['resolveMx'] = shared.resolveMx.bind(shared);
export const resolveNaptr: Resolver['resolveNaptr'] = shared.resolveNaptr.bind(shared);
export const resolveNs: Resolver['resolveNs'] = shared.resolveNs.bind(shared);
export const resolvePtr: Resolver['resolvePtr'] = shared.resolvePtr.bind(shared);
export const resolveSoa: Resolver['resolveSoa'] = shared.resolveSoa.bind(shared);
export const resolveSrv: Resolver['resolveSrv'] = shared.resolveSrv.bind(shared);
export const resolveTlsa: Resolver['resolveTlsa'] = shared.resolveTlsa.bind(shared);
export const resolveTxt: Resolver['resolveTxt'] = shared.resolveTxt.bind(shared);
export const reverse: Resolver['reverse'] = shared.reverse.bind(shared);
export const lookup: Resolver['lookup'] = shared.lookup.bind(shared);
export const connectLookup: Resolver['connectLookup'] = shared.connectLookup;
