import { ConnectionError, ProxyError } from '../errors';
import { parseIpv4, parseIpv6 } from '../records/addresses';
import { concatBytes, formatIpv4, formatIpv6, latin1Decode, latin1Encode } from '../wire/bytes';
import { formatHostPort } from './endpoint';
import type { Proxy } from './proxy';
import { ConnectionClosedError, writeBytes } from './stream';
import type { StreamReader } from './stream';
import type { Connection } from './types';

// the SOCKS5 handshake (RFC 1928) with username/password authentication (RFC 1929),
// written against a `Connection` so it runs wherever one can be opened

const VERSION = 0x05;
const METHOD_NONE = 0x00;
const METHOD_PASSWORD = 0x02;
const METHOD_UNACCEPTABLE = 0xff;

export const SOCKS5_COMMANDS = { connect: 0x01, udpAssociate: 0x03 } as const;
type Command = (typeof SOCKS5_COMMANDS)[keyof typeof SOCKS5_COMMANDS];

const ADDRESS_IPV4 = 0x01;
const ADDRESS_NAME = 0x03;
const ADDRESS_IPV6 = 0x04;

// reply codes, RFC 1928 §6
const REPLIES: Record<number, string> = {
  0x01: 'general failure',
  0x02: 'connection not allowed by the proxy',
  0x03: 'network unreachable',
  0x04: 'host unreachable',
  0x05: 'connection refused',
  0x06: 'TTL expired',
  0x07: 'command not supported',
  0x08: 'address type not supported',
};

// replies that are about the target, not about the proxy: the proxy did its part
const TARGET_FAILURES = new Set([0x03, 0x04, 0x05, 0x06]);

export const SOCKS5_COMMAND_NOT_SUPPORTED = 0x07;

// a ProxyError that remembers the proxy's reply code
export class Socks5ReplyError extends ProxyError {
  constructor(
    message: string,
    readonly reply: number
  ) {
    super(message);
    this.name = 'ProxyError';
  }
}

// a SOCKS5 address: type, address, port. Names are sent as names for the proxy to resolve
export function socks5Address(host: string, port: number): Uint8Array {
  const v4 = parseIpv4(host);
  const v6 = v4 ? null : parseIpv6(host);
  let address: Uint8Array;
  if (v4) address = concatBytes([Uint8Array.of(ADDRESS_IPV4), v4]);
  else if (v6) address = concatBytes([Uint8Array.of(ADDRESS_IPV6), v6]);
  else {
    const name = latin1Encode(host);
    if (name.length > 255) throw new ProxyError(`Host name too long for SOCKS5: ${host}`);
    address = concatBytes([Uint8Array.of(ADDRESS_NAME, name.length), name]);
  }
  return concatBytes([address, Uint8Array.of(port >>> 8, port & 0xff)]);
}

// read a SOCKS5 address off a buffer, returning it and how many bytes it took
export function readSocks5Address(
  bytes: Uint8Array,
  offset: number
): { host: string; port: number; length: number } | undefined {
  const type = bytes[offset];
  let host: string;
  let end: number;
  if (type === ADDRESS_IPV4) {
    end = offset + 5;
    if (bytes.length < end + 2) return undefined;
    host = formatIpv4(bytes.subarray(offset + 1, end));
  } else if (type === ADDRESS_IPV6) {
    end = offset + 17;
    if (bytes.length < end + 2) return undefined;
    host = formatIpv6(bytes.subarray(offset + 1, end));
  } else if (type === ADDRESS_NAME) {
    end = offset + 2 + (bytes[offset + 1] ?? 0);
    if (bytes.length < end + 2) return undefined;
    host = latin1Decode(bytes.subarray(offset + 2, end));
  } else {
    return undefined;
  }
  return { host, port: (bytes[end] << 8) | bytes[end + 1], length: end + 2 - offset };
}

// run the handshake for one command. Resolves with the address the proxy bound, which
// for UDP ASSOCIATE is where datagrams are to be sent
export async function socks5Handshake(
  reader: StreamReader,
  connection: Connection,
  proxy: Proxy,
  command: Command,
  target: { host: string; port: number }
): Promise<{ host: string; port: number }> {
  const hasCredentials = proxy.username !== undefined;
  try {
    // greeting: the one authentication method on offer. With credentials that is
    // username/password alone, so a proxy cannot skip checking them
    const offered = hasCredentials ? METHOD_PASSWORD : METHOD_NONE;
    await writeBytes(connection, Uint8Array.of(VERSION, 1, offered));
    const [version, method] = await reader.read(2);
    if (version !== VERSION) {
      throw new ProxyError(`${proxy.display} is not a SOCKS5 proxy`);
    }
    if (method === METHOD_UNACCEPTABLE) {
      throw new ProxyError(
        hasCredentials
          ? `Proxy ${proxy.display} accepts none of the offered authentication methods`
          : `Proxy ${proxy.display} requires authentication`
      );
    }

    if (method !== offered) {
      throw new ProxyError(`Proxy ${proxy.display} chose an authentication method not offered`);
    }

    if (method === METHOD_PASSWORD) {
      const username = new TextEncoder().encode(proxy.username ?? '');
      const password = new TextEncoder().encode(proxy.password ?? '');
      if (username.length > 255 || password.length > 255) {
        throw new ProxyError('Proxy credentials are too long for SOCKS5');
      }
      await writeBytes(
        connection,
        concatBytes([
          Uint8Array.of(0x01, username.length),
          username,
          Uint8Array.of(password.length),
          password,
        ])
      );
      const [, status] = await reader.read(2);
      if (status !== 0x00) {
        throw new ProxyError(`Proxy ${proxy.display} rejected the credentials`);
      }
    }

    // the request itself
    await writeBytes(
      connection,
      concatBytes([Uint8Array.of(VERSION, command, 0x00), socks5Address(target.host, target.port)])
    );
    const [, reply, , addressType] = await reader.read(4);
    if (reply !== 0x00) {
      const reason = REPLIES[reply] ?? `reply code ${reply}`;
      const where = formatHostPort(target.host, target.port);
      if (command === SOCKS5_COMMANDS.connect && TARGET_FAILURES.has(reply)) {
        throw new ConnectionError(`Cannot reach ${where} through ${proxy.display}: ${reason}`);
      }
      throw new Socks5ReplyError(
        command === SOCKS5_COMMANDS.connect
          ? `Proxy ${proxy.display} refused to connect to ${where}: ${reason}`
          : `Proxy ${proxy.display} refused a UDP association: ${reason}`,
        reply
      );
    }

    // the bound address: its length depends on its type
    let rest: Uint8Array;
    if (addressType === ADDRESS_IPV4) rest = await reader.read(6);
    else if (addressType === ADDRESS_IPV6) rest = await reader.read(18);
    else if (addressType === ADDRESS_NAME) {
      const [length] = await reader.read(1);
      rest = concatBytes([Uint8Array.of(length), await reader.read(length + 2)]);
    } else {
      throw new ProxyError(`Proxy ${proxy.display} sent an address of unknown type`);
    }
    const bound = readSocks5Address(concatBytes([Uint8Array.of(addressType), rest]), 0);
    if (!bound) throw new ProxyError(`Proxy ${proxy.display} sent an unreadable address`);
    return { host: bound.host, port: bound.port };
  } catch (error) {
    if (error instanceof ConnectionClosedError) {
      throw new ProxyError(`Proxy ${proxy.display} closed the connection during the handshake`, {
        cause: error,
      });
    }
    throw error;
  }
}
