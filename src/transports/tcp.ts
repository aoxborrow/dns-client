import type { Socket } from 'node:net';
import { ConnectionError, DnsError, EmptyResponseError } from '../errors';
import { concatBytes } from '../wire/bytes';
import { formatHostPort, isIp } from './endpoint';
import { whenReady } from './node';
import { openTunnel, resolveProxy } from './proxy';
import type { Proxy } from './proxy';
import { defaultConnect, isNode } from './runtime';
import { closeQuietly } from './stream';
import type {
  Connection,
  Endpoint,
  OnEvent,
  Transport,
  TransportOptions,
  TransportRequest,
  TransportResponse,
} from './types';

// DNS over TCP, and over TLS (DoT), which is the same framing on an encrypted stream.
//
// by default a TCP query gets a connection of its own, closed when it is answered. That
// is what `dig` does and it works everywhere.
//
// with `pipeline` (the default for DoT) connections are kept per server and reused, and
// queries are pipelined (RFC 7766): several can be in flight on one connection, each
// answer finding its query by ID, so a burst of queries to one server costs one
// handshake. A connection with nothing in flight is closed after an idle timeout.
//
// servers are not uniformly good at that, which is why it is opt-in for TCP. Some close
// a connection after one answer, some drop an idle connection without saying so, and
// some keep it open and never answer a second query. A query caught on a connection that
// had already been used is sent again once, on a connection of its own, and a server
// seen closing on pipelined queries is given one query per connection from then on. A
// server that goes silent cannot be told from a slow one, and costs a timeout

export interface TcpTransportOptions extends Pick<
  TransportOptions,
  'proxy' | 'connect' | 'tls' | 'idleTimeout' | 'pipeline'
> {
  // speak TLS on the connection: DNS over TLS
  secure?: boolean;
}

// what the framing needs from a byte stream, whichever kind it is
interface Wire {
  write(bytes: Uint8Array): void;
  close(): void;
  ref(): void;
  unref(): void;
}

interface WireHandlers {
  onData(chunk: Uint8Array): void;
  // the stream ended; with an error if that is why
  onClose(error?: unknown): void;
}

interface Waiting {
  id: number;
  // the query behind its two-byte length
  framed: Uint8Array;
  request: TransportRequest;
  resolve(response: TransportResponse): void;
  reject(error: unknown): void;
  // drop the abort listener
  settle(): void;
  channel?: Channel;
  // whether another query had already been written to the channel before this one
  reused: boolean;
  // whether this query has already been given its second chance
  resent: boolean;
}

interface Channel {
  key: string;
  endpoint: Endpoint;
  proxy?: Proxy;
  wire?: Wire;
  // who is waiting, by ID. Two queries can carry the same random ID, so each ID holds a
  // list, and the query's own `accept` tells their answers apart
  waiting: Map<number, Waiting[]>;
  // how many queries are waiting
  inFlight: number;
  // bytes of an incomplete frame
  partial?: Uint8Array;
  // queries written so far
  written: number;
  // whether two queries were ever in flight at once
  pipelined: boolean;
  // takes one query at a time
  exclusive: boolean;
  closed: boolean;
  idleTimer?: ReturnType<typeof setTimeout>;
  // stops a connection attempt nobody is waiting for any more
  opening: AbortController;
}

const DEFAULT_IDLE_TIMEOUT = 5000;

const messageOf = (error: unknown) => (error instanceof Error ? error.message : String(error));

// a `node:net` or `node:tls` socket as a wire
function socketWire(socket: Socket, handlers: WireHandlers): Wire {
  socket.on('data', (chunk: Buffer) => {
    handlers.onData(new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.length));
  });
  socket.on('error', error => handlers.onClose(error));
  socket.on('close', () => handlers.onClose());
  return {
    write: bytes => void socket.write(bytes),
    close: () => void socket.destroy(),
    ref: () => void socket.ref(),
    unref: () => void socket.unref(),
  };
}

// a `Connection` as a wire
function connectionWire(connection: Connection, handlers: WireHandlers): Wire {
  const reader = connection.readable.getReader();
  const writer = connection.writable.getWriter();
  void (async () => {
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        handlers.onData(value);
      }
      handlers.onClose();
    } catch (error) {
      handlers.onClose(error);
    }
  })();
  return {
    write: bytes => void writer.write(bytes).catch((error: unknown) => handlers.onClose(error)),
    close() {
      void reader.cancel().catch(() => undefined);
      void closeQuietly(connection);
    },
    ref: () => connection.ref?.(),
    unref: () => connection.unref?.(),
  };
}

export function createTcpTransport(options: TcpTransportOptions = {}): Transport {
  const name = options.secure ? 'tls' : 'tcp';
  const idleTimeout = options.idleTimeout ?? DEFAULT_IDLE_TIMEOUT;
  const pipeline = options.pipeline ?? Boolean(options.secure);
  const channels = new Map<string, Set<Channel>>();
  // servers that closed a connection with pipelined queries still unanswered
  const onePerConnection = new Set<string>();
  let closed = false;

  // ---- opening

  async function openNative(channel: Channel, handlers: WireHandlers): Promise<Wire> {
    const { host, port, serverName } = channel.endpoint;
    let socket: Socket;
    if (options.secure) {
      const tls = await import('node:tls');
      const name = serverName ?? host;
      socket = tls.connect({
        host,
        port,
        // SNI carries names only; a certificate for an IP address is checked against `host`
        ...(!isIp(name) && { servername: name }),
        ...(options.tls?.ca !== undefined && { ca: [options.tls.ca].flat() }),
        ...(options.tls?.rejectUnauthorized !== undefined && {
          rejectUnauthorized: options.tls.rejectUnauthorized,
        }),
      });
    } else {
      const net = await import('node:net');
      socket = net.connect({ host, port });
    }
    socket.setNoDelay(true);
    const onAbort = () => socket.destroy();
    channel.opening.signal.addEventListener('abort', onAbort, { once: true });
    try {
      await whenReady(socket, options.secure ? 'secureConnect' : 'connect');
    } catch (error) {
      socket.destroy();
      throw error;
    } finally {
      channel.opening.signal.removeEventListener('abort', onAbort);
    }
    return socketWire(socket, handlers);
  }

  async function openConnection(
    channel: Channel,
    handlers: WireHandlers,
    onEvent: OnEvent | undefined
  ): Promise<Wire> {
    const { host, port, serverName } = channel.endpoint;
    const where = formatHostPort(host, port);
    let connection: Connection;
    if (options.connect) {
      try {
        connection = await options.connect({ hostname: host, port });
      } catch (cause) {
        // whatever a caller's own connect throws is a connection failure
        throw new ConnectionError(`Cannot connect to ${where}: ${messageOf(cause)}`, { cause });
      }
    } else if (channel.proxy) {
      connection = await openTunnel(
        defaultConnect(options.tls),
        channel.proxy,
        { host, port },
        { signal: channel.opening.signal, onEvent }
      );
    } else {
      connection = await defaultConnect(options.tls)({ hostname: host, port });
    }
    if (options.secure) {
      try {
        connection = await connection.startTls(serverName ?? host);
      } catch (cause) {
        void closeQuietly(connection);
        if (cause instanceof DnsError) throw cause;
        throw new ConnectionError(`TLS handshake with ${where} failed: ${messageOf(cause)}`, {
          cause,
        });
      }
    }
    if (channel.opening.signal.aborted) {
      void closeQuietly(connection);
      throw new ConnectionError(`Connection to ${where} was abandoned`);
    }
    return connectionWire(connection, handlers);
  }

  function open(
    key: string,
    endpoint: Endpoint,
    proxy: Proxy | undefined,
    exclusive: boolean,
    onEvent: OnEvent | undefined
  ): Channel {
    const channel: Channel = {
      key,
      endpoint,
      ...(proxy && { proxy }),
      waiting: new Map(),
      inFlight: 0,
      written: 0,
      pipelined: false,
      exclusive,
      closed: false,
      opening: new AbortController(),
    };
    let set = channels.get(key);
    if (!set) channels.set(key, (set = new Set()));
    set.add(channel);

    const handlers: WireHandlers = {
      onData: chunk => receive(channel, chunk),
      onClose: error => shut(channel, error),
    };
    // the socket itself where there is one and nothing stands between it and the server
    const native = !options.connect && !proxy && isNode();
    (native ? openNative(channel, handlers) : openConnection(channel, handlers, onEvent)).then(
      wire => {
        if (channel.closed) {
          wire.close();
          return;
        }
        channel.wire = wire;
        for (const waiter of [...channel.waiting.values()].flat()) write(channel, waiter);
        if (channel.inFlight === 0) rest(channel);
      },
      (error: unknown) => {
        shut(
          channel,
          error instanceof DnsError
            ? error
            : new ConnectionError(
                `Cannot connect to ${formatHostPort(endpoint.host, endpoint.port)}: ${messageOf(error)}`,
                { cause: error }
              )
        );
      }
    );
    return channel;
  }

  // ---- a channel's life

  function add(channel: Channel, waiter: Waiting): void {
    const list = channel.waiting.get(waiter.id);
    if (list) list.push(waiter);
    else channel.waiting.set(waiter.id, [waiter]);
    channel.inFlight++;
    waiter.channel = channel;
  }

  // false if the query was not waiting on the channel any more
  function remove(channel: Channel, waiter: Waiting): boolean {
    const list = channel.waiting.get(waiter.id);
    const at = list?.indexOf(waiter) ?? -1;
    if (!list || at === -1) return false;
    list.splice(at, 1);
    if (list.length === 0) channel.waiting.delete(waiter.id);
    channel.inFlight--;
    return true;
  }

  function write(channel: Channel, waiter: Waiting): void {
    waiter.reused = channel.written > 0;
    channel.written++;
    if (channel.inFlight > 1) channel.pipelined = true;
    channel.wire?.write(waiter.framed);
  }

  function receive(channel: Channel, chunk: Uint8Array): void {
    const data = channel.partial ? concatBytes([channel.partial, chunk]) : chunk;
    let offset = 0;
    while (data.length - offset >= 2) {
      const length = (data[offset] << 8) | data[offset + 1];
      if (data.length - offset - 2 < length) break;
      // a copy, so the answer does not hold the whole read buffer alive
      const frame = data.slice(offset + 2, offset + 2 + length);
      offset += 2 + length;
      if (frame.length < 2) continue;
      const list = channel.waiting.get((frame[0] << 8) | frame[1]);
      // an answer nobody is waiting for: its query timed out, or it was never asked
      if (!list) continue;
      // with one query under the ID the answer is its, whatever it says; with several,
      // each is asked whether the answer is the one it wants
      const waiter =
        (list.length > 1 && list.find(candidate => candidate.request.accept?.(frame))) || list[0];
      remove(channel, waiter);
      waiter.settle();
      waiter.resolve({ bytes: frame, transport: name });
    }
    channel.partial = offset < data.length ? data.subarray(offset) : undefined;
    if (channel.inFlight === 0 && !channel.closed) rest(channel);
  }

  // nothing in flight: let the process go, and close after a while
  function rest(channel: Channel): void {
    if (idleTimeout <= 0 || channel.exclusive) {
      shut(channel);
      return;
    }
    channel.wire?.unref();
    clearTimeout(channel.idleTimer);
    channel.idleTimer = setTimeout(() => shut(channel), idleTimeout);
    (channel.idleTimer as { unref?: () => void }).unref?.();
  }

  // the channel is over, by our choice or the server's. Whoever is still waiting is sent
  // again or told why not
  function shut(channel: Channel, error?: unknown): void {
    if (channel.closed) return;
    channel.closed = true;
    clearTimeout(channel.idleTimer);
    channel.opening.abort();
    channel.wire?.close();
    const set = channels.get(channel.key);
    set?.delete(channel);
    if (set?.size === 0) channels.delete(channel.key);

    const stranded = [...channel.waiting.values()].flat();
    channel.waiting.clear();
    channel.inFlight = 0;
    if (stranded.length === 0) return;
    if (channel.pipelined && channel.wire) onePerConnection.add(channel.key);

    const where = formatHostPort(channel.endpoint.host, channel.endpoint.port);
    for (const waiter of stranded) {
      waiter.channel = undefined;
      // a connection that had been used before may simply have gone stale
      if (!closed && waiter.reused && !waiter.resent && channel.wire) {
        waiter.resent = true;
        assign(waiter, true);
        continue;
      }
      waiter.settle();
      if (error instanceof DnsError) waiter.reject(error);
      else if (error !== undefined) {
        waiter.reject(
          new ConnectionError(`Connection to ${where} failed: ${messageOf(error)}`, {
            cause: error,
          })
        );
      } else if (!channel.wire) {
        waiter.reject(new ConnectionError(`Connection to ${where} was closed`));
      } else if (channel.partial?.length) {
        waiter.reject(new ConnectionError(`${where} closed the connection mid-response`));
      } else {
        waiter.reject(new EmptyResponseError(`${where} closed the connection without answering`));
      }
    }
  }

  // put a query on a channel: one already open to the server if it can take it, or a new one
  function assign(waiter: Waiting, alone: boolean): void {
    const { endpoint } = waiter.request;
    let proxy: Proxy | undefined;
    try {
      proxy = options.connect
        ? undefined
        : resolveProxy(options.proxy, {
            host: endpoint.host,
            port: endpoint.port,
            transport: name,
          });
    } catch (error) {
      waiter.settle();
      waiter.reject(error);
      return;
    }
    const key = `${endpoint.host}|${endpoint.port}|${endpoint.serverName ?? ''}|${proxy?.key ?? ''}`;
    const single = alone || onePerConnection.has(key);

    let channel: Channel | undefined;
    if (!alone) {
      for (const candidate of channels.get(key) ?? []) {
        if (candidate.closed || candidate.exclusive) continue;
        if (single && candidate.inFlight > 0) continue;
        channel = candidate;
        break;
      }
    }
    channel ??= open(key, endpoint, proxy, alone, waiter.request.onEvent);

    clearTimeout(channel.idleTimer);
    if (channel.inFlight === 0) channel.wire?.ref();
    add(channel, waiter);
    if (channel.wire) write(channel, waiter);
  }

  // stop waiting for an answer, after an abort
  function withdraw(waiter: Waiting): void {
    const { channel } = waiter;
    if (!channel || !remove(channel, waiter)) return;
    if (channel.inFlight > 0 || channel.closed) return;
    // nobody wants a connection that is still being opened
    if (!channel.wire) shut(channel);
    else rest(channel);
  }

  return {
    name,

    send(request) {
      if (closed) return Promise.reject(new ConnectionError(`The ${name} transport is closed`));
      const { signal, query } = request;
      if (signal?.aborted) return Promise.reject(signal.reason);
      if (query.length > 0xffff) {
        return Promise.reject(new DnsError('Query is too large to send over TCP'));
      }

      return new Promise<TransportResponse>((resolve, reject) => {
        const framed = new Uint8Array(query.length + 2);
        framed[0] = query.length >>> 8;
        framed[1] = query.length & 0xff;
        framed.set(query, 2);

        const onAbort = () => {
          withdraw(waiter);
          reject(signal?.reason);
        };
        const waiter: Waiting = {
          id: (query[0] << 8) | query[1],
          framed,
          request,
          resolve,
          reject,
          settle: () => signal?.removeEventListener('abort', onAbort),
          reused: false,
          resent: false,
        };
        signal?.addEventListener('abort', onAbort, { once: true });
        assign(waiter, !pipeline);
      });
    },

    close() {
      closed = true;
      const error = new ConnectionError(`The ${name} transport was closed`);
      for (const set of [...channels.values()]) {
        for (const channel of [...set]) shut(channel, error);
      }
    },
  };
}
