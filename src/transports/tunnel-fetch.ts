import { ConnectionError, DnsError } from '../errors';
import { concatBytes, latin1Decode, latin1Encode } from '../wire/bytes';
import { formatHostPort } from './endpoint';
import { openTunnel, resolveProxy } from './proxy';
import type { Proxy } from './proxy';
import { defaultConnect } from './runtime';
import { closeQuietly, StreamReader, writeBytes } from './stream';
import type { Connect, Connection, OnEvent, ProxyInput, TlsOptions } from './types';

// a small `fetch` that makes its requests over connections it opens itself, so they can
// go through a proxy: HTTP/1.1 over a `Connection`, tunnelled and upgraded to TLS as
// needed. It exists because a runtime's own `fetch` either cannot be pointed at a proxy
// (Workers) or needs a dependency to do it (Node).
//
// connections are kept open and reused. Without that, every DoH query would pay for a
// proxy handshake and a TLS handshake.
//
// it does what DoH needs and no more: GET and POST with a byte body, a response read
// whole into memory, no redirects, no compression, no HTTP/2

export interface TunnelFetchOptions {
  proxy?: ProxyInput;
  // how connections are opened. Default: the runtime's own
  connect?: Connect;
  tls?: TlsOptions;
  // how long an unused connection is kept, in milliseconds. Default 5000; 0 closes each
  // connection after its response
  idleTimeout?: number;
}

export interface TunnelFetchInit {
  method?: string;
  headers?: Record<string, string>;
  body?: Uint8Array;
  signal?: AbortSignal;
  onEvent?: OnEvent;
}

export interface TunnelFetch {
  (url: string | URL, init?: TunnelFetchInit): Promise<Response>;
  // close the connections being kept
  close(): void;
}

interface Kept {
  connection: Connection;
  reader: StreamReader;
  // whether a request has already been answered on it
  used: boolean;
  idleTimer?: ReturnType<typeof setTimeout>;
}

interface Parsed {
  status: number;
  statusText: string;
  headers: [string, string][];
  body: Uint8Array;
  // whether the connection can carry another request
  reusable: boolean;
}

const DEFAULT_IDLE_TIMEOUT = 5000;
const MAX_HEADER_BYTES = 64 * 1024;
const CRLF = latin1Encode('\r\n');
const HEADER_END = latin1Encode('\r\n\r\n');
// statuses that never carry a body
const BODILESS = new Set([204, 205, 304]);

const messageOf = (error: unknown) => (error instanceof Error ? error.message : String(error));

// a response is being read off a connection that had been used before, and it ended
// before a single byte came back: the server had already dropped it
class StaleConnectionError extends Error {}

// one status line and its headers
async function readHead(reader: StreamReader) {
  const head = latin1Decode(await reader.readUntil(HEADER_END, MAX_HEADER_BYTES));
  const [statusLine, ...lines] = head.slice(0, -4).split('\r\n');
  const match = /^HTTP\/(1\.[01]) (\d{3})(?: (.*))?$/.exec(statusLine);
  if (!match) throw new Error('not an HTTP/1.1 response');
  const headers: [string, string][] = [];
  for (const line of lines) {
    const colon = line.indexOf(':');
    if (colon > 0) headers.push([line.slice(0, colon).trim(), line.slice(colon + 1).trim()]);
  }
  return { version: match[1], status: Number(match[2]), statusText: match[3] ?? '', headers };
}

async function readResponse(reader: StreamReader, method: string): Promise<Parsed> {
  let head = await readHead(reader);
  // informational responses come before the real one
  while (head.status >= 100 && head.status < 200 && head.status !== 101) {
    head = await readHead(reader);
  }
  const { version, status, statusText, headers } = head;

  const header = (name: string) =>
    headers.find(([key]) => key.toLowerCase() === name)?.[1].toLowerCase();
  let reusable = version === '1.1' && header('connection') !== 'close';
  if (version === '1.0' && header('connection') === 'keep-alive') reusable = true;

  let body: Uint8Array;
  if (method === 'HEAD' || BODILESS.has(status)) {
    body = new Uint8Array(0);
  } else if (header('transfer-encoding')?.includes('chunked')) {
    const chunks: Uint8Array[] = [];
    for (;;) {
      const sizeLine = latin1Decode(await reader.readUntil(CRLF, MAX_HEADER_BYTES));
      const size = Number.parseInt(sizeLine.split(';')[0].trim(), 16);
      if (!Number.isFinite(size) || size < 0) throw new Error('bad chunk size');
      if (size === 0) break;
      // a copy: the reader's buffer moves on
      chunks.push((await reader.read(size)).slice());
      await reader.read(2);
    }
    // trailers, up to the empty line
    while ((await reader.readUntil(CRLF, MAX_HEADER_BYTES)).length > 2);
    body = concatBytes(chunks);
  } else if (header('content-length') !== undefined) {
    const length = Number(header('content-length'));
    if (!Number.isInteger(length) || length < 0) throw new Error('bad Content-Length');
    body = (await reader.read(length)).slice();
  } else {
    // no length given: the body runs to the end of the connection
    body = (await reader.readAll()).slice();
    reusable = false;
  }
  return { status, statusText, headers, body, reusable };
}

function encodeRequest(url: URL, method: string, init: TunnelFetchInit): Uint8Array {
  const headers: Record<string, string> = {
    'Host': url.host,
    // the body is read as it arrives, with no decompression
    'Accept-Encoding': 'identity',
    ...init.headers,
  };
  if (init.body) headers['Content-Length'] = String(init.body.length);
  const lines = [`${method} ${url.pathname}${url.search} HTTP/1.1`];
  for (const [name, value] of Object.entries(headers)) {
    if (/[\r\n:]/.test(name) || /[\r\n]/.test(value)) {
      throw new DnsError(`Invalid HTTP header "${name.replace(/[\r\n]/g, ' ')}"`);
    }
    lines.push(`${name}: ${value}`);
  }
  const head = latin1Encode(`${lines.join('\r\n')}\r\n\r\n`);
  return init.body ? concatBytes([head, init.body]) : head;
}

export function createTunnelFetch(options: TunnelFetchOptions = {}): TunnelFetch {
  const idleTimeout = options.idleTimeout ?? DEFAULT_IDLE_TIMEOUT;
  const idle = new Map<string, Kept[]>();
  const open = new Set<Kept>();
  let closed = false;

  async function connectTo(
    url: URL,
    port: number,
    proxy: Proxy | undefined,
    init: TunnelFetchInit
  ): Promise<Kept> {
    const host = url.hostname.replace(/^\[|\]$/g, '');
    const where = formatHostPort(host, port);
    const connect = options.connect ?? defaultConnect(options.tls);
    let connection: Connection;
    if (proxy) {
      connection = await openTunnel(
        connect,
        proxy,
        { host, port },
        { signal: init.signal, onEvent: init.onEvent }
      );
    } else {
      try {
        connection = await connect({ hostname: host, port });
      } catch (cause) {
        throw new ConnectionError(`Cannot connect to ${where}: ${messageOf(cause)}`, { cause });
      }
    }
    if (url.protocol === 'https:') {
      try {
        connection = await connection.startTls(host);
      } catch (cause) {
        void closeQuietly(connection);
        if (cause instanceof DnsError) throw cause;
        throw new ConnectionError(`TLS handshake with ${where} failed: ${messageOf(cause)}`, {
          cause,
        });
      }
    }
    const kept: Kept = { connection, reader: new StreamReader(connection.readable), used: false };
    open.add(kept);
    return kept;
  }

  function discard(kept: Kept): void {
    clearTimeout(kept.idleTimer);
    open.delete(kept);
    void kept.reader.cancel();
    void closeQuietly(kept.connection);
  }

  function keep(key: string, kept: Kept): void {
    if (closed || idleTimeout <= 0) {
      discard(kept);
      return;
    }
    kept.used = true;
    kept.connection.unref?.();
    let list = idle.get(key);
    if (!list) idle.set(key, (list = []));
    list.push(kept);
    kept.idleTimer = setTimeout(() => {
      const waiting = idle.get(key);
      const at = waiting?.indexOf(kept) ?? -1;
      if (at !== -1) waiting?.splice(at, 1);
      if (waiting?.length === 0) idle.delete(key);
      discard(kept);
    }, idleTimeout);
    (kept.idleTimer as { unref?: () => void }).unref?.();
  }

  function takeIdle(key: string): Kept | undefined {
    const list = idle.get(key);
    const kept = list?.pop();
    if (list?.length === 0) idle.delete(key);
    if (kept) {
      clearTimeout(kept.idleTimer);
      kept.connection.ref?.();
    }
    return kept;
  }

  // one request and its response on one connection
  async function exchangeOn(
    kept: Kept,
    request: Uint8Array,
    method: string,
    signal: AbortSignal | undefined
  ): Promise<Parsed> {
    const onAbort = () => discard(kept);
    signal?.addEventListener('abort', onAbort, { once: true });
    const receivedBefore = kept.reader.received;
    try {
      await writeBytes(kept.connection, request);
      return await readResponse(kept.reader, method);
    } catch (error) {
      if (signal?.aborted) throw signal.reason;
      if (kept.used && kept.reader.received === receivedBefore) throw new StaleConnectionError();
      throw error;
    } finally {
      signal?.removeEventListener('abort', onAbort);
    }
  }

  const tunnelFetch = async (input: string | URL, init: TunnelFetchInit = {}) => {
    if (closed) throw new ConnectionError('This fetch was closed');
    if (init.signal?.aborted) throw init.signal.reason;
    const url = new URL(input);
    if (url.protocol !== 'https:' && url.protocol !== 'http:') {
      throw new DnsError(`Cannot fetch a ${url.protocol} URL`);
    }
    const port = url.port ? Number(url.port) : url.protocol === 'https:' ? 443 : 80;
    const host = url.hostname.replace(/^\[|\]$/g, '');
    const proxy = resolveProxy(options.proxy, { host, port, transport: 'doh' });
    const key = `${url.protocol}//${url.host}|${proxy?.key ?? ''}`;
    const method = (init.method ?? 'GET').toUpperCase();
    const request = encodeRequest(url, method, init);

    let parsed: Parsed | undefined;
    let kept = takeIdle(key) ?? (await connectTo(url, port, proxy, init));
    try {
      parsed = await exchangeOn(kept, request, method, init.signal);
    } catch (error) {
      discard(kept);
      if (!(error instanceof StaleConnectionError)) throw error;
      // the kept connection had gone away; a new one gets the request
      kept = await connectTo(url, port, proxy, init);
      try {
        parsed = await exchangeOn(kept, request, method, init.signal);
      } catch (second) {
        discard(kept);
        throw second;
      }
    }
    if (parsed.reusable) keep(key, kept);
    else discard(kept);

    return new Response(BODILESS.has(parsed.status) ? null : (parsed.body as BodyInit), {
      status: parsed.status,
      statusText: parsed.statusText,
      headers: parsed.headers,
    });
  };

  return Object.assign(tunnelFetch, {
    close() {
      closed = true;
      idle.clear();
      for (const kept of [...open]) discard(kept);
    },
  });
}
