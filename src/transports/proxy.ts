import { ConnectionError, DnsError, errorData, ProxyError } from '../errors';
import { toBase64 } from '../wire/bytes';
import { formatHostPort } from './endpoint';
import { httpConnectHandshake } from './http-connect';
import { socks5Handshake, SOCKS5_COMMANDS } from './socks5';
import { closeQuietly, StreamReader } from './stream';
import type { Connect, Connection, OnEvent, ProxyInput, ProxyTarget } from './types';

// proxies: what one is, how to pick it for a target, and how to get a tunnel through it.
// Credentials live in `Proxy` and go nowhere else: every message and event is built from
// `display`, and anything that wraps another error's text is scrubbed first

export interface Proxy {
  protocol: 'socks5' | 'http';
  host: string;
  port: number;
  username?: string;
  password?: string;
  // the proxy as it may be shown: scheme, host and port
  display: string;
  // tells two proxies, or two sets of credentials on one proxy, apart when pooling
  // connections. Never shown
  key: string;
}

const SCHEMES: Record<string, { protocol: Proxy['protocol']; port: number }> = {
  'socks5:': { protocol: 'socks5', port: 1080 },
  // the same thing: names are always sent to the proxy to resolve
  'socks5h:': { protocol: 'socks5', port: 1080 },
  'http:': { protocol: 'http', port: 80 },
};

const OTHER_SCHEMES = new Set(['socks:', 'socks4:', 'socks4a:', 'https:']);

export function parseProxy(input: string | URL): Proxy {
  let url: URL;
  try {
    url = typeof input === 'string' ? new URL(input) : input;
  } catch {
    // the text may hold credentials, so it is not repeated
    throw new TypeError('Invalid proxy URL');
  }
  const scheme = SCHEMES[url.protocol];
  if (!scheme) {
    // a scheme is only named when it is one somebody would write on purpose: text like
    // "user:pass@host" parses as a URL whose scheme is the username
    const named = OTHER_SCHEMES.has(url.protocol) ? ` "${url.protocol.slice(0, -1)}"` : '';
    throw new TypeError(`Unsupported proxy scheme${named}: use socks5:// or http://`);
  }
  const host = url.hostname.replace(/^\[|\]$/g, '');
  if (!host) throw new TypeError('Invalid proxy URL: no host');
  const port = url.port ? Number(url.port) : scheme.port;
  const username = url.username ? decodeURIComponent(url.username) : undefined;
  const password = url.password ? decodeURIComponent(url.password) : undefined;
  return {
    protocol: scheme.protocol,
    host,
    port,
    ...(username !== undefined && { username }),
    ...(password !== undefined && { password }),
    display: `${scheme.protocol}://${formatHostPort(host, port)}`,
    // a tuple, so no credentials can be split differently into the same key
    key: JSON.stringify([scheme.protocol, host, port, username ?? null, password ?? null]),
  };
}

// the proxy to use for one target, if any
export function resolveProxy(
  input: ProxyInput | undefined,
  target: ProxyTarget
): Proxy | undefined {
  if (input === undefined) return undefined;
  const chosen = typeof input === 'function' ? input(target) : input;
  return chosen === undefined ? undefined : parseProxy(chosen);
}

// the value of a Proxy-Authorization header
export function basicCredentials(proxy: Proxy): string {
  const pair = `${proxy.username ?? ''}:${proxy.password ?? ''}`;
  return `Basic ${toBase64(new TextEncoder().encode(pair))}`;
}

// remove the proxy's credentials from text that came from somewhere else, such as the
// message of an error being wrapped
export function scrub(text: string, proxy: Proxy): string {
  let out = text;
  const secrets = [proxy.password, proxy.username && proxy.password && basicCredentials(proxy)];
  for (const secret of secrets) {
    if (secret) out = out.split(secret).join('***');
  }
  if (proxy.username) out = out.split(`${proxy.username}:`).join('***:');
  return out;
}

const messageOf = (error: unknown) => (error instanceof Error ? error.message : String(error));

// a connection to `target` through the proxy, plain: the caller upgrades it to TLS if it
// wants TLS. `connect` is how the proxy itself is reached
export async function openTunnel(
  connect: Connect,
  proxy: Proxy,
  target: { host: string; port: number },
  options: { signal?: AbortSignal; onEvent?: OnEvent } = {}
): Promise<Connection> {
  const started = Date.now();
  const targetText = formatHostPort(target.host, target.port);
  const report = (error?: unknown) =>
    options.onEvent?.({
      event: 'proxy',
      proxy: proxy.display,
      command: 'connect',
      target: targetText,
      elapsed: Date.now() - started,
      ...(error !== undefined && { error: errorData(error) }),
    });

  let connection: Connection | undefined;
  const onAbort = () => {
    if (connection) void closeQuietly(connection);
  };
  options.signal?.addEventListener('abort', onAbort, { once: true });

  try {
    try {
      connection = await connect({ hostname: proxy.host, port: proxy.port });
    } catch (cause) {
      throw new ProxyError(
        `Cannot reach proxy ${proxy.display}: ${scrub(messageOf(cause), proxy)}`,
        { cause }
      );
    }
    if (options.signal?.aborted) {
      void closeQuietly(connection);
      throw options.signal.reason;
    }

    const reader = new StreamReader(connection.readable);
    let early: Uint8Array;
    try {
      if (proxy.protocol === 'socks5') {
        await socks5Handshake(reader, connection, proxy, SOCKS5_COMMANDS.connect, target);
      } else {
        await httpConnectHandshake(reader, connection, proxy, target);
      }
      early = reader.release();
    } catch (error) {
      void closeQuietly(connection);
      if (options.signal?.aborted) throw options.signal.reason;
      // a target the handshake refused to write is the caller's mistake, not the proxy's
      if (error instanceof DnsError || error instanceof TypeError) throw error;
      throw new ProxyError(
        `Proxy ${proxy.display} failed while connecting to ${targetText}: ${scrub(messageOf(error), proxy)}`,
        { cause: error }
      );
    }
    report();
    return early.length ? withEarlyBytes(connection, early) : connection;
  } catch (error) {
    if (error instanceof ProxyError || error instanceof ConnectionError) report(error);
    throw error;
  } finally {
    options.signal?.removeEventListener('abort', onAbort);
  }
}

// a connection whose first bytes were already read off it during the handshake
function withEarlyBytes(connection: Connection, early: Uint8Array): Connection {
  const reader = connection.readable.getReader();
  const readable = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(early);
    },
    async pull(controller) {
      const { done, value } = await reader.read();
      if (done) controller.close();
      else controller.enqueue(value);
    },
    cancel(reason) {
      return reader.cancel(reason);
    },
  });
  return {
    ...connection,
    readable,
    close: () => connection.close(),
    startTls() {
      // those bytes belonged to the TLS handshake and cannot be put back
      throw new ConnectionError('The server sent data before the TLS handshake');
    },
  };
}
