import { parseIpv4, parseIpv6 } from '../records/addresses';
import { hostsEntries, LOOKUP_HINTS } from '../transports/host';
import { argumentError, checkHostname, getaddrinfoError } from './errors';

// `lookup`: what `node:dns`'s `lookup` does with the operating system's getaddrinfo,
// done with the library. An IP address is returned as it is; then the hosts file is
// read; `localhost` and names under it are the loopback addresses (RFC 6761 §6.3);
// everything else is asked of the DNS servers, A and AAAA at once

export interface LookupOptions {
  family?: number | 'IPv4' | 'IPv6';
  // `V4MAPPED` and `ALL` change the answer for family 6. `ADDRCONFIG` is accepted and has
  // no effect: both families are returned whatever this machine's interfaces are
  hints?: number;
  all?: boolean;
  order?: 'ipv4first' | 'ipv6first' | 'verbatim';
  // deprecated in Node: true is `order: 'verbatim'`, false is `order: 'ipv4first'`
  verbatim?: boolean;
}

export interface LookupOneOptions extends LookupOptions {
  all?: false;
}

export interface LookupAllOptions extends LookupOptions {
  all: true;
}

export interface LookupAddress {
  address: string;
  family: number;
}

// `node:dns`'s hint flags, with this platform's values
export const { ADDRCONFIG, V4MAPPED, ALL } = LOOKUP_HINTS;

export type ResultOrder = 'ipv4first' | 'ipv6first' | 'verbatim';

// asks the DNS for one family's addresses. Resolves to the addresses, or rejects with the
// facade's error for the query
export type AddressQuery = (hostname: string, family: 4 | 6) => Promise<string[]>;

export function ipFamily(text: string): 0 | 4 | 6 {
  if (parseIpv4(text)) return 4;
  if (parseIpv6(text.split('%')[0])) return 6;
  return 0;
}

interface Settings {
  family: 0 | 4 | 6;
  hints: number;
  all: boolean;
  order: ResultOrder;
}

export function lookupSettings(options: unknown, defaultOrder: ResultOrder): Settings {
  let family: unknown = 0;
  let hints = 0;
  let all = false;
  let order = defaultOrder;
  if (typeof options === 'number') family = options;
  else if (options !== undefined && options !== null) {
    if (typeof options !== 'object') {
      throw argumentError(
        `The "options" argument must be one of type number or object. Received type ${typeof options}`,
        'ERR_INVALID_ARG_TYPE'
      );
    }
    const given = options as LookupOptions;
    family = given.family ?? 0;
    hints = given.hints ?? 0;
    all = given.all === true;
    if (given.verbatim !== undefined) order = given.verbatim ? 'verbatim' : 'ipv4first';
    if (given.order !== undefined) order = given.order;
  }
  if (family === 'IPv4') family = 4;
  if (family === 'IPv6') family = 6;
  if (family !== 0 && family !== 4 && family !== 6) {
    throw argumentError(
      `The property 'options.family' must be one of: 0, 4, 6. Received ${String(family)}`
    );
  }
  if (typeof hints !== 'number' || (hints & ~(ADDRCONFIG | V4MAPPED | ALL)) !== 0) {
    throw argumentError(`The argument 'hints' is invalid. Received ${String(hints)}`);
  }
  if (!['ipv4first', 'ipv6first', 'verbatim'].includes(order)) {
    throw argumentError(`The argument 'order' is invalid. Received ${String(order)}`);
  }
  return { family, hints, all, order };
}

const LOOPBACK: LookupAddress[] = [
  { address: '127.0.0.1', family: 4 },
  { address: '::1', family: 6 },
];

const isLocalhost = (name: string) => /(^|\.)localhost\.?$/i.test(name);

// IPv4 first, IPv6 first, or as found: IPv4 then IPv6 for the DNS, file order for the
// hosts file
function ordered(addresses: LookupAddress[], order: ResultOrder): LookupAddress[] {
  if (order === 'verbatim') return addresses;
  const first = order === 'ipv4first' ? 4 : 6;
  return [
    ...addresses.filter(entry => entry.family === first),
    ...addresses.filter(entry => entry.family !== first),
  ];
}

export async function lookupAddresses(
  hostname: unknown,
  options: unknown,
  defaultOrder: ResultOrder,
  query: AddressQuery
): Promise<LookupAddress[]> {
  const name = checkHostname(hostname, 'hostname');
  const { family, hints, order } = lookupSettings(options, defaultOrder);

  const literal = ipFamily(name);
  if (literal) return [{ address: name, family: literal }];

  const wanted = (entry: LookupAddress) => family === 0 || entry.family === family;
  const mapped = family === 6 && (hints & V4MAPPED) !== 0;

  const fromHosts = hostsEntries(name);
  const local = fromHosts.length > 0 ? fromHosts : isLocalhost(name) ? LOOPBACK : [];
  if (local.length > 0) {
    if (mapped) return withMapped(local, hints);
    const found = local.filter(wanted);
    if (found.length > 0) return ordered(found, order);
  }

  const families: (4 | 6)[] = family === 4 ? [4] : family === 6 && !mapped ? [6] : [4, 6];
  const settled = await Promise.allSettled(families.map(each => query(name, each)));

  const found: LookupAddress[] = [];
  settled.forEach((result, index) => {
    if (result.status === 'fulfilled') {
      for (const address of result.value) found.push({ address, family: families[index] });
    }
  });

  if (mapped) {
    const result = withMapped(found, hints);
    if (result.length > 0) return result;
  } else if (found.length > 0) {
    return ordered(found, order);
  }

  // nothing found: the name does not exist or has no addresses (ENOTFOUND, as getaddrinfo
  // reports both), or no server could say (EAI_AGAIN)
  const failures: unknown[] = settled.flatMap(result =>
    result.status === 'rejected' ? [result.reason as unknown] : []
  );
  const definite = failures.every(
    error => (error as { code?: string }).code === 'ENOTFOUND' || isNoData(error)
  );
  throw getaddrinfoError(definite ? 'ENOTFOUND' : 'EAI_AGAIN', name, failures[0]);
}

const isNoData = (error: unknown) =>
  ['ENODATA', 'EBADNAME'].includes((error as { code?: string }).code ?? '');

// family 6 with V4MAPPED, from addresses of both families. With ALL: the IPv6 addresses,
// then the IPv4 ones mapped; alone: the IPv4 ones mapped only when there is no IPv6
function withMapped(addresses: LookupAddress[], hints: number): LookupAddress[] {
  const ipv6 = addresses.filter(entry => entry.family === 6);
  const ipv4 = mapV4(addresses.filter(entry => entry.family === 4));
  if ((hints & ALL) !== 0) return [...ipv6, ...ipv4];
  return ipv6.length > 0 ? ipv6 : ipv4;
}

const mapV4 = (addresses: LookupAddress[]): LookupAddress[] =>
  addresses.map(entry => ({ address: `::ffff:${entry.address}`, family: 6 }));
