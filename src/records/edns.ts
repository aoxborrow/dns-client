import { ParseError } from '../errors';
import { EDNS_OPTIONS, EXTENDED_DNS_ERRORS } from '../protocol/edns';
import {
  concatBytes,
  formatIpv4,
  formatIpv6,
  latin1Decode,
  readU16,
  toHex,
  utf8Decode,
  writeU16,
} from '../wire/bytes';
import type { Edns, EdnsOption } from '../wire/message';
import { parseIpv4, parseIpv6 } from './addresses';

// EDNS options with their contents decoded. The wire layer hands options over as a code
// and bytes; these give the common ones fields, and build the ones a client sends.

/** the nameserver's identifier for itself (RFC 5001): free-form bytes, usually text */
export interface NsidOption {
  name: 'NSID';
  code: 3;
  /** the identifier as text when it is printable ASCII, otherwise null */
  nsid: string | null;
  /** the identifier as hex, always */
  hex: string;
}

/** the client's network, as a resolver passes it on (RFC 7871) */
export interface ClientSubnetOption {
  name: 'CLIENT_SUBNET';
  code: 8;
  /** 1 for IPv4, 2 for IPv6 */
  family: number;
  sourcePrefixLength: number;
  scopePrefixLength: number;
  address: string;
}

/** DNS cookies (RFC 7873), hex */
export interface CookieOption {
  name: 'COOKIE';
  code: 10;
  clientCookie: string;
  serverCookie: string | null;
}

/** edns-tcp-keepalive (RFC 7828) */
export interface TcpKeepaliveOption {
  name: 'TCP_KEEPALIVE';
  code: 11;
  /**
   * how long the server will hold an idle connection, as the wire carries it: in units of
   * 100 milliseconds (RFC 7828 §3.1). Null in a query
   */
  timeout: number | null;
}

/** padding (RFC 7830) */
export interface PaddingOption {
  name: 'PADDING';
  code: 12;
  length: number;
}

/** the DNSSEC algorithms, DS hashes or NSEC3 hashes a client understands (RFC 6975) */
export interface AlgorithmsOption {
  name: 'DAU' | 'DHU' | 'N3U';
  code: 5 | 6 | 7;
  algorithms: number[];
}

/** the trust anchors a client holds, by key tag (RFC 8145) */
export interface KeyTagOption {
  name: 'KEY_TAG';
  code: 14;
  keyTags: number[];
}

/** an extended DNS error (RFC 8914): why a response is what it is */
export interface ExtendedErrorOption {
  name: 'EDE';
  code: 15;
  infoCode: number;
  /** the registry's description of the code, or null for a code not in it */
  purpose: string | null;
  /** whatever the server added, often empty */
  extraText: string;
}

/**
 * an option the library does not decode, or one that does not fit its layout: its code and bytes
 */
export interface UnknownOption {
  name: `OPTION${number}`;
  code: number;
  /** hex */
  data: string;
}

/** an EDNS option, decoded */
export type TypedEdnsOption =
  | NsidOption
  | ClientSubnetOption
  | CookieOption
  | TcpKeepaliveOption
  | PaddingOption
  | AlgorithmsOption
  | KeyTagOption
  | ExtendedErrorOption
  | UnknownOption;

const unknown = (option: EdnsOption): UnknownOption => ({
  name: `OPTION${option.code}`,
  code: option.code,
  data: toHex(option.data),
});

const ALGORITHM_OPTION_NAMES = { 5: 'DAU', 6: 'DHU', 7: 'N3U' } as const;

/**
 * decode one option. An option whose contents do not fit its layout comes back as
 * unknown, with its bytes: a bad option should not cost the caller the whole response
 */
export function decodeEdnsOption(option: EdnsOption): TypedEdnsOption {
  const { code, data } = option;
  switch (code) {
    case EDNS_OPTIONS.NSID: {
      const printable = data.length > 0 && data.every(byte => byte >= 0x20 && byte <= 0x7e);
      return { name: 'NSID', code, nsid: printable ? latin1Decode(data) : null, hex: toHex(data) };
    }
    case EDNS_OPTIONS.CLIENT_SUBNET: {
      if (data.length < 4) return unknown(option);
      const family = readU16(data, 0);
      const size = family === 1 ? 4 : family === 2 ? 16 : 0;
      const prefix = data.subarray(4);
      if (size === 0 || prefix.length > size) return unknown(option);
      // the address is cut to the prefix on the wire; pad it back out with zeros
      const address = new Uint8Array(size);
      address.set(prefix);
      return {
        name: 'CLIENT_SUBNET',
        code,
        family,
        sourcePrefixLength: data[2],
        scopePrefixLength: data[3],
        address: family === 1 ? formatIpv4(address) : formatIpv6(address),
      };
    }
    case EDNS_OPTIONS.COOKIE: {
      // an 8-byte client cookie, then nothing or an 8 to 32-byte server cookie
      if (data.length !== 8 && (data.length < 16 || data.length > 40)) return unknown(option);
      return {
        name: 'COOKIE',
        code,
        clientCookie: toHex(data.subarray(0, 8)),
        serverCookie: data.length > 8 ? toHex(data.subarray(8)) : null,
      };
    }
    case EDNS_OPTIONS.TCP_KEEPALIVE: {
      if (data.length !== 0 && data.length !== 2) return unknown(option);
      // the timeout is in units of 100 milliseconds
      return {
        name: 'TCP_KEEPALIVE',
        code,
        timeout: data.length === 2 ? readU16(data, 0) : null,
      };
    }
    case EDNS_OPTIONS.PADDING:
      return { name: 'PADDING', code, length: data.length };
    case EDNS_OPTIONS.DAU:
    case EDNS_OPTIONS.DHU:
    case EDNS_OPTIONS.N3U:
      return { name: ALGORITHM_OPTION_NAMES[code], code, algorithms: [...data] };
    case EDNS_OPTIONS.KEY_TAG: {
      if (data.length % 2 !== 0) return unknown(option);
      const keyTags: number[] = [];
      for (let offset = 0; offset < data.length; offset += 2) keyTags.push(readU16(data, offset));
      return { name: 'KEY_TAG', code, keyTags };
    }
    case EDNS_OPTIONS.EDE: {
      if (data.length < 2) return unknown(option);
      const infoCode = readU16(data, 0);
      return {
        name: 'EDE',
        code,
        infoCode,
        purpose: (EXTENDED_DNS_ERRORS as Record<number, string>)[infoCode] ?? null,
        // some servers end the text with a zero byte
        extraText: utf8Decode(data.subarray(2)).replace(/\0+$/, ''),
      };
    }
    default:
      return unknown(option);
  }
}

/** every option of a message, decoded. A message with no EDNS has none */
export function decodeEdnsOptions(edns: Edns | undefined): TypedEdnsOption[] {
  return (edns?.options ?? []).map(decodeEdnsOption);
}

/** the extended DNS errors a response carries, if any */
export function extendedErrors(edns: Edns | undefined): ExtendedErrorOption[] {
  return decodeEdnsOptions(edns).filter(
    (option): option is ExtendedErrorOption => option.name === 'EDE'
  );
}

// ---- options a client sends

/** ask the server to identify itself */
export function nsidOption(): EdnsOption {
  return { code: EDNS_OPTIONS.NSID, data: new Uint8Array(0) };
}

/** a cookie: the client's eight bytes, and the server's from an earlier response if known */
export function cookieOption(clientCookie: Uint8Array, serverCookie?: Uint8Array): EdnsOption {
  if (clientCookie.length !== 8) throw new ParseError('A client cookie is exactly 8 bytes');
  if (serverCookie && (serverCookie.length < 8 || serverCookie.length > 32)) {
    throw new ParseError('A server cookie is 8 to 32 bytes');
  }
  return {
    code: EDNS_OPTIONS.COOKIE,
    data: serverCookie ? concatBytes([clientCookie, serverCookie]) : Uint8Array.from(clientCookie),
  };
}

/** padding of the given length, to hide a message's size on an encrypted transport */
export function paddingOption(length: number): EdnsOption {
  return { code: EDNS_OPTIONS.PADDING, data: new Uint8Array(length) };
}

/**
 * the client's subnet: an address and how many of its leading bits to reveal. A prefix
 * length of 0 asks the resolver not to pass any client address on
 */
export function clientSubnetOption(address: string, sourcePrefixLength: number): EdnsOption {
  const ipv4 = parseIpv4(address);
  const bytes = ipv4 ?? parseIpv6(address);
  if (!bytes) throw new ParseError(`Not an IP address: ${address}`);
  if (
    !Number.isInteger(sourcePrefixLength) ||
    sourcePrefixLength < 0 ||
    sourcePrefixLength > bytes.length * 8
  ) {
    throw new ParseError(`Prefix length out of range: ${sourcePrefixLength}`);
  }
  // only the bytes the prefix covers are sent, with the bits past it cleared
  const kept = Uint8Array.from(bytes.subarray(0, Math.ceil(sourcePrefixLength / 8)));
  const spare = kept.length * 8 - sourcePrefixLength;
  if (spare > 0) kept[kept.length - 1] &= 0xff << spare;
  const head = new Uint8Array(4);
  writeU16(head, 0, ipv4 ? 1 : 2);
  head[2] = sourcePrefixLength;
  return { code: EDNS_OPTIONS.CLIENT_SUBNET, data: concatBytes([head, kept]) };
}
