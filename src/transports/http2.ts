import type { ClientHttp2Session, ClientHttp2Stream, IncomingHttpHeaders } from 'node:http2';
import type { TLSSocket } from 'node:tls';
import { ConnectionError } from '../errors';
import { nodeTlsOptions, whenReady } from './node';
import { openTunnel } from './proxy';
import type { Proxy } from './proxy';
import { defaultConnect } from './runtime';
import type { Connection, OnEvent, TlsOptions } from './types';

// DoH over HTTP/2 with `node:http2`, for Node, whose own `fetch` speaks only HTTP/1.1.
// RFC 8484 §5.2 names HTTP/2 as the minimum recommended version, and some servers (some
// of Quad9's sites among them) answer HTTP/1.1 with a 505.
//
// one session per origin (and proxy), shared by every query to it: each query is a
// stream of its own, so they run side by side on one connection. A session with nothing
// in flight is closed after the idle timeout. A session the server sends away (GOAWAY)
// or that fails takes no new queries; a query it took down without an answer is sent
// once more on a fresh one.
//
// TLS is set up here, with ALPN, before the session starts. A server that does not pick
// h2 is remembered, and its queries are handed back to the caller to send with `fetch`.
// Node's modules are imported when the first query is sent, never at load

type Modules = {
  http2: typeof import('node:http2');
  tls: typeof import('node:tls');
  Duplex: typeof import('node:stream').Duplex;
};

let modules: Promise<Modules | undefined> | undefined;

// undefined where the runtime has no `node:http2`. As in node.ts, each import is awaited
// inside a `try`, so that a bundler building for a browser leaves it for the runtime. An
// import handed on as a promise, to `Promise.all` say, fails such a build even inside a `try`
async function importModules(): Promise<Modules | undefined> {
  try {
    const http2 = await import('node:http2');
    const tls = await import('node:tls');
    const { Duplex } = await import('node:stream');
    return { http2, tls, Duplex };
  } catch {
    return undefined;
  }
}

function loadModules(): Promise<Modules | undefined> {
  return (modules ??= importModules());
}

export interface Http2ClientOptions {
  tls?: TlsOptions;
  // how long a session with nothing in flight is kept open, in milliseconds. 0 closes it
  // as soon as its queries are answered
  idleTimeout?: number;
}

export interface Http2Request {
  url: string;
  method: string;
  // lowercase names
  headers: Record<string, string>;
  body?: Uint8Array;
  signal?: AbortSignal;
  // reach the server through this proxy's tunnel
  proxy?: Proxy;
  onEvent?: OnEvent;
}

export interface Http2Response {
  status: number;
  contentType: string | null;
  bytes: Uint8Array;
}

export interface Http2Client {
  // undefined when the server does not speak HTTP/2, or the runtime has no `node:http2`:
  // the request was not sent
  request(request: Http2Request): Promise<Http2Response | undefined>;
  // close every session, failing whatever is still in flight
  close(): void;
}

interface Session {
  session: ClientHttp2Session;
  // streams in flight
  active: number;
  // sent away, failed or closed: no new streams
  dead: boolean;
  idleTimer?: ReturnType<typeof setTimeout>;
  retire(): void;
  ref(): void;
  unref(): void;
}

// a session being opened or open, or undefined for a server that does not speak HTTP/2
interface Slot {
  promise: Promise<Session | undefined>;
  settled: boolean;
  // queries waiting for the session to open. When every one has given up, the opening is
  // abandoned
  waiting: number;
  opening: AbortController;
}

// a stream failed in a way that says nothing about the query: sending it again may work
class SessionGone extends Error {
  constructor(readonly error: unknown) {
    super('HTTP/2 session gone');
  }
}

const DEFAULT_IDLE_TIMEOUT = 5000;

export function createHttp2Client(options: Http2ClientOptions = {}): Http2Client {
  const idleTimeout = options.idleTimeout ?? DEFAULT_IDLE_TIMEOUT;
  const slots = new Map<string, Slot>();
  const open = new Set<Session>();
  // after close() nothing is sent, and nothing in flight is sent again: a query fails as
  // one on a closed TCP transport does
  let closed = false;
  const closedError = () => new ConnectionError('The DoH transport was closed');

  async function openSession(
    mods: Modules,
    key: string,
    slot: Slot,
    url: URL,
    request: Http2Request
  ): Promise<Session | undefined> {
    const { http2, tls, Duplex } = mods;
    const host = url.hostname.replace(/^\[|\]$/g, '');
    const port = url.port ? Number(url.port) : 443;
    const signal = slot.opening.signal;
    const tlsOptions = { ...nodeTlsOptions(options.tls, host), ALPNProtocols: ['h2', 'http/1.1'] };

    let tunnel: Connection | undefined;
    let socket: TLSSocket;
    if (request.proxy) {
      tunnel = await openTunnel(
        defaultConnect(options.tls),
        request.proxy,
        { host, port },
        { signal, ...(request.onEvent && { onEvent: request.onEvent }) }
      );
      // the web streams of Node's own types, which differ from the DOM's only on paper
      const duplex = Duplex.fromWeb(tunnel as unknown as Parameters<typeof Duplex.fromWeb>[0]);
      socket = tls.connect({ ...tlsOptions, socket: duplex });
    } else {
      socket = tls.connect({ ...tlsOptions, port });
    }
    const onAbort = () => socket.destroy();
    signal.addEventListener('abort', onAbort, { once: true });
    try {
      await whenReady(socket, 'secureConnect');
    } catch (error) {
      socket.destroy();
      if (signal.aborted) throw signal.reason;
      throw error;
    } finally {
      signal.removeEventListener('abort', onAbort);
    }
    // every query that wanted it gave up while the handshake finished
    if (signal.aborted) {
      socket.destroy();
      throw signal.reason;
    }
    if (socket.alpnProtocol !== 'h2') {
      socket.destroy();
      return undefined;
    }

    const session = http2.connect(url.origin, { createConnection: () => socket });
    const record: Session = {
      session,
      active: 0,
      dead: false,
      retire() {
        if (!record.dead) {
          record.dead = true;
          clearTimeout(record.idleTimer);
          if (slots.get(key) === slot) slots.delete(key);
        }
        // the session goes once its last stream does
        if (record.active === 0) {
          open.delete(record);
          if (!session.closed) session.close();
        }
      },
      ref() {
        session.ref();
        tunnel?.ref?.();
      },
      unref() {
        session.unref();
        tunnel?.unref?.();
      },
    };
    open.add(record);
    // idle until its first stream, so it cannot outlive queries that gave up on it. Even
    // with an idle timeout of 0 the timer gives the waiting queries their turn first
    record.unref();
    record.idleTimer = setTimeout(() => record.retire(), Math.max(idleTimeout, 0));
    (record.idleTimer as { unref?: () => void }).unref?.();
    session.on('goaway', () => record.retire());
    // the streams carry the error to their queries
    session.on('error', () => record.retire());
    session.on('close', () => {
      record.dead = true;
      clearTimeout(record.idleTimer);
      if (slots.get(key) === slot) slots.delete(key);
      open.delete(record);
    });
    return record;
  }

  async function sessionFor(
    mods: Modules,
    url: URL,
    request: Http2Request
  ): Promise<Session | undefined> {
    const key = request.proxy ? `${request.proxy.key}|${url.origin}` : url.origin;
    let slot = slots.get(key);
    if (slot?.settled) {
      const session = await slot.promise;
      if (!session || !session.dead) return session;
      if (slots.get(key) === slot) slots.delete(key);
      slot = undefined;
    }
    if (!slot) {
      const fresh: Slot = {
        settled: false,
        waiting: 0,
        opening: new AbortController(),
        promise: undefined as unknown as Promise<Session | undefined>,
      };
      fresh.promise = openSession(mods, key, fresh, url, request).then(
        session => {
          fresh.settled = true;
          return session;
        },
        (error: unknown) => {
          fresh.settled = true;
          if (slots.get(key) === fresh) slots.delete(key);
          throw error;
        }
      );
      // nobody may be waiting by the time it fails
      fresh.promise.catch(() => undefined);
      slots.set(key, fresh);
      slot = fresh;
    }

    const waiting = slot;
    waiting.waiting++;
    try {
      return await untilAborted(waiting.promise, request.signal);
    } finally {
      waiting.waiting--;
      if (waiting.waiting === 0 && !waiting.settled) {
        if (slots.get(key) === waiting) slots.delete(key);
        waiting.opening.abort();
      }
    }
  }

  function send(mods: Modules, record: Session, url: URL, request: Http2Request) {
    const { constants } = mods.http2;
    return new Promise<Http2Response>((resolve, reject) => {
      const { signal } = request;
      let status: number | undefined;
      let contentType: string | null = null;
      const chunks: Buffer[] = [];
      let stream: ClientHttp2Stream | undefined;
      let finished = false;

      // `cut`: the stream ended with no response at all, which a server does not do on
      // purpose; its connection went
      const finish = (error?: unknown, cut = false) => {
        if (finished) return;
        finished = true;
        signal?.removeEventListener('abort', onAbort);
        record.active--;
        const gone =
          error !== undefined &&
          !signal?.aborted &&
          status === undefined &&
          (cut || record.dead || stream?.rstCode === constants.NGHTTP2_REFUSED_STREAM);
        // a fresh session for the query sent again, and for the ones after it
        if (gone || record.dead) record.retire();
        else if (record.active === 0) idle(record);
        if (error === undefined) {
          resolve({
            status: status ?? 0,
            contentType,
            bytes: new Uint8Array(Buffer.concat(chunks)),
          });
        } else if (signal?.aborted) {
          reject(signal.reason);
        } else if (gone) {
          // the server never took the query, or the session went before it answered
          reject(new SessionGone(error));
        } else {
          reject(error);
        }
      };
      const onAbort = () => {
        stream?.close(constants.NGHTTP2_CANCEL);
        finish(signal?.reason);
      };

      record.active++;
      clearTimeout(record.idleTimer);
      record.ref();
      try {
        stream = record.session.request(
          {
            ':method': request.method,
            ':path': url.pathname + url.search,
            ...request.headers,
            // Cloudflare answers a POST without it with a 400
            ...(request.body && { 'content-length': String(request.body.length) }),
          },
          { endStream: !request.body }
        );
      } catch (error) {
        // the session closed between being picked and being asked
        record.retire();
        finish(error);
        return;
      }
      signal?.addEventListener('abort', onAbort, { once: true });
      stream.on('response', (headers: IncomingHttpHeaders) => {
        status = Number(headers[':status']);
        contentType = headers['content-type'] ?? null;
      });
      stream.on('data', (chunk: Buffer) => chunks.push(chunk));
      stream.on('end', () => {
        if (status === undefined) finish(new Error('HTTP/2 stream ended with no response'), true);
        else finish();
      });
      stream.on('error', error => finish(error));
      stream.on('close', () => {
        if (!finished) {
          finish(new Error(`HTTP/2 stream closed with code ${stream?.rstCode ?? 'unknown'}`));
        }
      });
      if (request.body) stream.end(request.body);
    });
  }

  function idle(record: Session) {
    if (idleTimeout <= 0) {
      record.retire();
      return;
    }
    record.unref();
    clearTimeout(record.idleTimer);
    record.idleTimer = setTimeout(() => record.retire(), idleTimeout);
    (record.idleTimer as { unref?: () => void }).unref?.();
  }

  return {
    async request(request) {
      const mods = await loadModules();
      if (!mods) return undefined;
      if (request.signal?.aborted) throw request.signal.reason;
      if (closed) throw closedError();
      const url = new URL(request.url);
      // once on the session there is, and once more on a fresh one if that one went
      for (let attempt = 1; ; attempt++) {
        try {
          const record = await sessionFor(mods, url, request);
          if (!record) return undefined;
          return await send(mods, record, url, request);
        } catch (error) {
          if (request.signal?.aborted) throw request.signal.reason;
          if (closed) throw closedError();
          if (!(error instanceof SessionGone)) throw error;
          if (attempt >= 2) throw error.error;
        }
      }
    },

    close() {
      closed = true;
      for (const slot of slots.values()) slot.opening.abort();
      slots.clear();
      for (const record of open) {
        record.dead = true;
        clearTimeout(record.idleTimer);
        record.session.destroy();
      }
      open.clear();
    },
  };
}

// the promise, or the signal's reason if it aborts first
function untilAborted<T>(promise: Promise<T>, signal: AbortSignal | undefined): Promise<T> {
  if (!signal) return promise;
  if (signal.aborted) return Promise.reject(signal.reason);
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(signal.reason);
    signal.addEventListener('abort', onAbort, { once: true });
    promise.then(
      value => {
        signal.removeEventListener('abort', onAbort);
        resolve(value);
      },
      (error: unknown) => {
        signal.removeEventListener('abort', onAbort);
        reject(error);
      }
    );
  });
}
