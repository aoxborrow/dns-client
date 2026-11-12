import { NoServerError } from '../errors';
import { parseIpv4, parseIpv6 } from '../records/addresses';
import { formatIpv6 } from '../wire/bytes';
import { toAsciiName } from '../wire/names';
import type { Endpoint, Server, TransportName } from './types';

// turning what a caller wrote into a server a transport can use

export const DEFAULT_PORTS: Record<TransportName, number> = {
  udp: 53,
  tcp: 53,
  tls: 853,
  doh: 443,
};

const DOH_PATH = '/dns-query';

export const isIpv4 = (text: string): boolean => parseIpv4(text) !== null;

// an IPv6 address, with or without a zone (`fe80::1%en0`)
export const isIpv6 = (text: string): boolean => parseIpv6(text.split('%')[0]) !== null;

export const isIp = (text: string): boolean => isIpv4(text) || isIpv6(text);

// one spelling per address, so an answer's source can be compared with the server it was
// sent to: IPv4 as written, IPv6 in RFC 5952 form without its zone
export function normalizeAddress(address: string): string {
  if (!address.includes(':')) return address;
  const bytes = parseIpv6(address.split('%')[0]);
  return bytes ? formatIpv6(bytes) : address;
}

// host and port as they go in a URL or a log line: IPv6 in brackets
export function formatHostPort(host: string, port: number): string {
  return host.includes(':') ? `[${host}]:${port}` : `${host}:${port}`;
}

// what was written is never repeated in these errors: a server string is free text, and
// free text is where a password or a token ends up

function parsePort(text: string): number {
  const port = Number(text);
  if (!/^\d+$/.test(text) || port < 1 || port > 0xffff) {
    throw new NoServerError('Invalid port in the server address');
  }
  return port;
}

// a host is an IP address or a DNS name, and nothing else gets as far as a socket, a TLS
// handshake or the request line sent to a proxy. In particular no whitespace or control
// character does: a line break in a host would split an HTTP CONNECT request in two
const HOST = /^[A-Za-z0-9._:%-]+$/;

export function checkHost(host: string): string {
  let ascii = host;
  if (!host.includes(':')) {
    try {
      // a name may be written in Unicode
      ascii = toAsciiName(host);
    } catch {
      throw new NoServerError('Invalid server address: not an IP address or a host name');
    }
  }
  if (!HOST.test(ascii)) {
    throw new NoServerError('Invalid server address: not an IP address or a host name');
  }
  return ascii;
}

// a DoH URL, checked. Credentials in the URL are refused: `fetch` rejects such a URL and
// repeats it, credentials and all, in the error it throws
export function parseDohUrl(text: string): URL {
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    // the parser's own error carries the text it was given, so it is not kept as a cause
    throw new NoServerError('Invalid DoH server URL');
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new NoServerError('A DoH server URL has to start with https:// or http://');
  }
  if (url.username || url.password) {
    throw new NoServerError(
      'A DoH server URL cannot carry credentials: send them from a custom fetch instead'
    );
  }
  return url;
}

// split "host", "host:port", "[v6]" and "[v6]:port". A bare IPv6 address has colons of
// its own, so it only carries a port in the bracketed form
function splitHostPort(text: string): { host: string; port?: number } {
  if (text.startsWith('[')) {
    const end = text.indexOf(']');
    if (end === -1) throw new NoServerError('Invalid server address');
    const rest = text.slice(end + 1);
    if (rest !== '' && !rest.startsWith(':')) {
      throw new NoServerError('Invalid server address');
    }
    return {
      host: text.slice(1, end),
      ...(rest && { port: parsePort(rest.slice(1)) }),
    };
  }
  const colon = text.indexOf(':');
  if (colon === -1 || colon !== text.lastIndexOf(':')) return { host: text };
  return { host: text.slice(0, colon), port: parsePort(text.slice(colon + 1)) };
}

// resolve a server to an endpoint for one transport. `port` is the caller's `port`
// option, which a port written into the server itself overrides
export function toEndpoint(
  server: string | Server,
  transport: TransportName,
  port?: number
): Endpoint {
  let described: Server;
  if (typeof server !== 'string') {
    described = server;
  } else if (/^https?:\/\//i.test(server)) {
    const url = parseDohUrl(server);
    described = {
      // the URL parser keeps the brackets around an IPv6 host
      address: url.hostname.replace(/^\[|\]$/g, ''),
      ...(url.port && { port: Number(url.port) }),
      url: server,
    };
  } else {
    const { host, port: written } = splitHostPort(server.trim());
    described = { address: host, ...(written !== undefined && { port: written }) };
  }

  if (!described.address) throw new NoServerError('No server given');
  const host = checkHost(described.address);

  if (transport === 'doh') {
    if (described.url) {
      const url = parseDohUrl(described.url);
      const schemePort = url.protocol === 'http:' ? 80 : DEFAULT_PORTS.doh;
      return { host, port: url.port ? Number(url.port) : schemePort, url: described.url };
    }
    const usedPort = described.port ?? port ?? DEFAULT_PORTS.doh;
    const authority =
      usedPort === DEFAULT_PORTS.doh
        ? host.includes(':')
          ? `[${host}]`
          : host
        : formatHostPort(host, usedPort);
    return { host, port: usedPort, url: `https://${authority}${DOH_PATH}` };
  }

  return {
    host,
    port: described.port ?? port ?? DEFAULT_PORTS[transport],
    ...(transport === 'tls' && { serverName: checkHost(described.serverName ?? host) }),
  };
}
