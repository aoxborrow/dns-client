import type { RemoteInfo, Socket } from 'node:dgram';
import { ConnectionError, DnsError, errorData, NoServerError, ProxyError } from '../errors';
import { concatBytes } from '../wire/bytes';
import { checkHost, formatHostPort, isIp, normalizeAddress } from './endpoint';
import { resolveProxy, scrub } from './proxy';
import type { Proxy } from './proxy';
import { defaultConnect, isWorkers } from './runtime';
import {
  readSocks5Address,
  socks5Address,
  SOCKS5_COMMAND_NOT_SUPPORTED,
  SOCKS5_COMMANDS,
  socks5Handshake,
  Socks5ReplyError,
} from './socks5';
import { closeQuietly, StreamReader } from './stream';
import { createTcpTransport } from './tcp';
import type {
  Connection,
  Transport,
  TransportOptions,
  TransportRequest,
  TransportResponse,
} from './types';

// DNS over UDP, on a fresh socket for every query.
//
// each query gets its own socket, bound by the system to a new ephemeral port, and the
// socket is closed once the query is over: when the send ends, or with a `lifetime`,
// when the exchange does, so its retransmissions share the port and an answer to any
// copy is heard. The source port is then as unpredictable as the system makes it, and
// an off-path attacker forging an answer has to guess it as well as the 16-bit ID
// (RFC 5452 §4.5, §9.2). A few long-lived shared sockets would save the system calls,
// but leave the port one of a handful of values. An answer still finds its query by
// where it came from and the ID it carries.
//
// through a SOCKS5 proxy the same thing runs over one UDP association; through a proxy
// that cannot carry UDP the query goes over TCP instead, and the response says so

/** the options of `createUdpTransport` */
export interface UdpTransportOptions extends Pick<TransportOptions, 'proxy' | 'tls'> {
  /**
   * the transport a query is handed to when the proxy cannot carry UDP. One is made on
   * demand if this is left out
   */
  tcp?: () => Transport;
}

type Family = 'udp4' | 'udp6';

interface Waiting {
  accept?: (response: Uint8Array) => boolean;
  resolve(response: TransportResponse): void;
  reject(error: unknown): void;
  // stop waiting: forget the entry and its abort listener
  settle(): void;
}

interface SharedSocket {
  socket: Socket;
  // who is waiting, by "address|port|id". Two queries can share a key when their random
  // IDs collide, so each key holds a list and `accept` tells the answers apart
  waiting: Map<string, Waiting[]>;
  count: number;
  closed: boolean;
}

// a SOCKS5 UDP association: datagrams go to the proxy's relay with a small header naming
// the real destination, and come back the same way. It lasts as long as its control
// connection
interface Association {
  shared: SharedSocket;
  control: Connection;
  relay: { host: string; port: number };
}

// an association being set up, and the callers waiting on it. Each caller can give up on
// its own; the setup is abandoned only when every one of them has
interface Setup {
  promise: Promise<Association>;
  opening: AbortController;
  // callers still waiting and not given up
  waiting: number;
  // set up, or failed: from then on nobody can call it off
  settled: boolean;
}

const UNSPECIFIED = new Set(['0.0.0.0', '::']);

const keyOf = (address: string, port: number, id: number) => `${address}|${port}|${id}`;
const messageOf = (error: unknown) => (error instanceof Error ? error.message : String(error));

/** DNS over UDP. Every query gets a socket and source port of its own (RFC 5452) */
export function createUdpTransport(options: UdpTransportOptions = {}): Transport {
  // the sockets of the queries in flight, each closed when its query ends
  const open = new Set<SharedSocket>();
  // the socket an exchange's retransmissions go out on, until its lifetime ends
  const held = new WeakMap<AbortSignal, Map<Family, SharedSocket>>();
  const associations = new Map<string, Setup>();
  // proxies that turned down UDP ASSOCIATE: no point asking again
  const withoutUdp = new Set<string>();
  let dgram: typeof import('node:dgram') | undefined;
  let ownTcp: Transport | undefined;
  let closed = false;

  const tcp = () => options.tcp?.() ?? (ownTcp ??= createTcpTransport(options));

  async function loadDgram() {
    // Workers has a `node:dgram` that loads and then does nothing, so there the import
    // going through says nothing about UDP
    if (isWorkers()) throw new DnsError('UDP is not available in this runtime');
    try {
      return (dgram ??= await import('node:dgram'));
    } catch (cause) {
      throw new DnsError('UDP is not available in this runtime', { cause });
    }
  }

  // ---- sockets

  function openSocket(
    module: typeof import('node:dgram'),
    family: Family,
    onMessage: (shared: SharedSocket, message: Uint8Array, remote: RemoteInfo) => void,
    onGone: (shared: SharedSocket) => void
  ): SharedSocket {
    const shared: SharedSocket = {
      socket: module.createSocket(family),
      waiting: new Map(),
      count: 0,
      closed: false,
    };
    shared.socket.on('message', (message, remote) => onMessage(shared, message, remote));
    shared.socket.on('error', error => {
      onGone(shared);
      failAll(shared, new ConnectionError(`UDP socket error: ${error.message}`, { cause: error }));
    });
    // an idle socket must not keep the process alive
    shared.socket.unref();
    return shared;
  }

  function failAll(shared: SharedSocket, error: DnsError): void {
    if (shared.closed) return;
    shared.closed = true;
    const everyone = [...shared.waiting.values()].flat();
    shared.waiting.clear();
    for (const waiter of everyone) {
      waiter.settle();
      waiter.reject(error);
    }
    try {
      shared.socket.close();
    } catch {
      // already closed
    }
  }

  // hand an answer to whoever is waiting for it
  function settleFirst(shared: SharedSocket, key: string, bytes: Uint8Array): void {
    const list = shared.waiting.get(key);
    if (!list) return;
    const waiter = list.find(candidate => !candidate.accept || candidate.accept(bytes));
    if (!waiter) return;
    waiter.settle();
    waiter.resolve({ bytes, transport: 'udp' });
  }

  function deliver(shared: SharedSocket, message: Uint8Array, remote: RemoteInfo): void {
    if (message.length < 12) return;
    const id = (message[0] << 8) | message[1];
    settleFirst(
      shared,
      keyOf(normalizeAddress(remote.address), remote.port, id),
      new Uint8Array(message.buffer, message.byteOffset, message.length)
    );
  }

  // send a datagram and wait for the answer filed under `key`
  function sendAndWait(
    shared: SharedSocket,
    key: string,
    datagram: Uint8Array,
    to: { host: string; port: number },
    request: TransportRequest
  ): Promise<TransportResponse> {
    return new Promise((resolve, reject) => {
      const { signal } = request;
      const onAbort = () => {
        waiter.settle();
        reject(signal?.reason);
      };
      const waiter: Waiting = {
        accept: request.accept,
        resolve,
        reject,
        settle() {
          signal?.removeEventListener('abort', onAbort);
          const list = shared.waiting.get(key);
          if (list) {
            const at = list.indexOf(waiter);
            if (at !== -1) list.splice(at, 1);
            if (list.length === 0) shared.waiting.delete(key);
          }
          if (--shared.count === 0 && !shared.closed) shared.socket.unref();
        },
      };

      const list = shared.waiting.get(key);
      if (list) list.push(waiter);
      else shared.waiting.set(key, [waiter]);
      if (shared.count++ === 0) shared.socket.ref();
      signal?.addEventListener('abort', onAbort, { once: true });

      shared.socket.send(datagram, to.port, to.host, error => {
        // only if the query is still waiting: an answer or an abort may have come first
        if (!error || !shared.waiting.get(key)?.includes(waiter)) return;
        waiter.settle();
        reject(
          new ConnectionError(
            `Cannot send to ${formatHostPort(to.host, to.port)}: ${error.message}`,
            { cause: error }
          )
        );
      });
    });
  }

  // ---- direct

  // the system lookup takes no signal, so an abort stops the wait for it instead
  async function resolveHost(host: string, signal: AbortSignal | undefined): Promise<string> {
    if (isIp(host)) return host;
    let onAbort = () => {};
    try {
      const { lookup } = await import('node:dns/promises');
      // made only once nothing more is awaited before the race, so its rejection is handled
      if (signal?.aborted) throw signal.reason;
      const aborted = new Promise<never>((_, reject) => {
        onAbort = () => reject(signal?.reason);
        signal?.addEventListener('abort', onAbort, { once: true });
      });
      return (await Promise.race([lookup(host), aborted])).address;
    } catch (cause) {
      if (signal?.aborted) throw signal.reason;
      throw new NoServerError(`Cannot resolve server name "${host}"`, { server: host, cause });
    } finally {
      signal?.removeEventListener('abort', onAbort);
    }
  }

  async function sendDirect(request: TransportRequest): Promise<TransportResponse> {
    const module = dgram ?? (await loadDgram());
    const { endpoint, query } = request;
    const address = isIp(endpoint.host)
      ? endpoint.host
      : await resolveHost(endpoint.host, request.signal);
    if (request.signal?.aborted) throw request.signal.reason;
    // the transport may have closed while the module loaded or the name resolved
    if (closed) throw new ConnectionError('The UDP transport was closed');
    const id = (query[0] << 8) | query[1];
    const family: Family = address.includes(':') ? 'udp6' : 'udp4';
    const lifetime = request.lifetime?.aborted ? undefined : request.lifetime;
    const release = (socket: SharedSocket) => {
      open.delete(socket);
      failAll(socket, new ConnectionError('The UDP query is over'));
    };
    let shared = lifetime ? held.get(lifetime)?.get(family) : undefined;
    if (!shared || shared.closed) {
      // unbound until the first send, when the system picks a new ephemeral port for it
      const opened = openSocket(module, family, deliver, socket => open.delete(socket));
      open.add(opened);
      if (lifetime) {
        const sockets = held.get(lifetime) ?? new Map<Family, SharedSocket>();
        sockets.set(family, opened);
        held.set(lifetime, sockets);
        lifetime.addEventListener('abort', () => release(opened), { once: true });
      }
      shared = opened;
    }
    try {
      return await sendAndWait(
        shared,
        keyOf(normalizeAddress(address), endpoint.port, id),
        query,
        { host: address, port: endpoint.port },
        request
      );
    } finally {
      // answered, timed out, failed or given up on: the socket goes with the query, or
      // with the exchange when it may be sent again
      if (!lifetime) release(shared);
    }
  }

  // ---- through a SOCKS5 association

  // an answer from the relay: three bytes of header, the address it really came from,
  // then the datagram
  function deliverRelayed(association: Association) {
    return (shared: SharedSocket, message: Uint8Array, remote: RemoteInfo): void => {
      if (
        remote.port !== association.relay.port ||
        normalizeAddress(remote.address) !== normalizeAddress(association.relay.host)
      ) {
        return;
      }
      const bytes = new Uint8Array(message.buffer, message.byteOffset, message.length);
      // a fragmented datagram (byte 2) is not something a DNS answer should ever be
      if (bytes.length < 4 || bytes[2] !== 0x00) return;
      const source = readSocks5Address(bytes, 3);
      if (!source) return;
      const payload = bytes.subarray(3 + source.length);
      if (payload.length < 12) return;
      const id = (payload[0] << 8) | payload[1];
      settleFirst(shared, keyOf(normalizeAddress(source.host), source.port, id), payload);
    };
  }

  // `drop` forgets this association, so the next query sets up a new one. `signal` aborts
  // the setup, which ends the control connection whatever the handshake is waiting on
  async function associate(
    proxy: Proxy,
    request: TransportRequest,
    signal: AbortSignal,
    drop: () => void
  ): Promise<Association> {
    const module = dgram ?? (await loadDgram());
    const started = Date.now();
    const report = (target: string, error?: unknown) =>
      request.onEvent?.({
        event: 'proxy',
        proxy: proxy.display,
        command: 'udp-associate',
        target,
        elapsed: Date.now() - started,
        ...(error !== undefined && { error: errorData(error) }),
      });

    let control: Connection | undefined;
    const onAbort = () => {
      if (control) void closeQuietly(control);
    };
    signal.addEventListener('abort', onAbort, { once: true });
    const stopIfAborted = () => {
      if (signal.aborted) throw signal.reason;
    };
    try {
      try {
        control = await defaultConnect(options.tls)({ hostname: proxy.host, port: proxy.port });
      } catch (cause) {
        stopIfAborted();
        throw new ProxyError(
          `Cannot reach proxy ${proxy.display}: ${scrub(messageOf(cause), proxy)}`,
          { cause }
        );
      }
      stopIfAborted();
      const reader = new StreamReader(control.readable);
      // the address the client will send from is not known to it, so it is left unspecified
      const bound = await socks5Handshake(reader, control, proxy, SOCKS5_COMMANDS.udpAssociate, {
        host: '0.0.0.0',
        port: 0,
      });
      // an unspecified relay address means "the address you reached me on"
      const relayHost = await resolveHost(
        UNSPECIFIED.has(bound.host) ? proxy.host : bound.host,
        signal
      );
      stopIfAborted();
      const relay = { host: relayHost, port: bound.port };

      const association: Association = {
        control,
        relay,
        shared: undefined as unknown as SharedSocket,
      };
      association.shared = openSocket(
        module,
        relayHost.includes(':') ? 'udp6' : 'udp4',
        deliverRelayed(association),
        drop
      );
      control.unref?.();

      // the proxy ends the association by closing the control connection
      const opened = control;
      void (async () => {
        try {
          while ((await reader.readSome()) !== undefined);
        } catch {
          // closed with an error, which ends it just the same
        }
        drop();
        failAll(
          association.shared,
          new ProxyError(`Proxy ${proxy.display} ended the UDP association`)
        );
        void closeQuietly(opened);
      })();

      report(formatHostPort(relay.host, relay.port));
      return association;
    } catch (error) {
      if (control) void closeQuietly(control);
      // everyone waiting gave up, and the handshake failed because of it
      if (signal.aborted) throw signal.reason;
      const wrapped =
        error instanceof DnsError
          ? error
          : new ProxyError(
              `Proxy ${proxy.display} failed to set up UDP: ${scrub(messageOf(error), proxy)}`,
              { cause: error }
            );
      report('0.0.0.0:0', wrapped);
      throw wrapped;
    } finally {
      signal.removeEventListener('abort', onAbort);
    }
  }

  // the association for a proxy, set up by the first query that needs it and shared by
  // the rest. A query that gives up stops waiting at once; the setup goes on for whoever
  // is still waiting, and stops when nobody is
  function association(proxy: Proxy, request: TransportRequest): Promise<Association> {
    let setup = associations.get(proxy.key);
    if (!setup) {
      const created: Setup = {
        promise: undefined as unknown as Promise<Association>,
        opening: new AbortController(),
        waiting: 0,
        settled: false,
      };
      const drop = () => {
        if (associations.get(proxy.key) === created) associations.delete(proxy.key);
      };
      created.promise = associate(proxy, request, created.opening.signal, drop).then(
        joined => {
          created.settled = true;
          return joined;
        },
        (error: unknown) => {
          created.settled = true;
          drop();
          throw error;
        }
      );
      // the callers each hear about a failure; this copy of it is nobody's
      created.promise.catch(() => undefined);
      associations.set(proxy.key, created);
      setup = created;
    }
    return join(proxy, setup, request.signal);
  }

  function join(proxy: Proxy, setup: Setup, signal: AbortSignal | undefined): Promise<Association> {
    if (signal?.aborted) return Promise.reject(signal.reason);
    if (setup.settled) return setup.promise;
    setup.waiting++;
    // a caller that cannot give up keeps the setup going until it ends
    if (!signal) return setup.promise;
    return new Promise((resolve, reject) => {
      const onAbort = () => {
        if (!setup.settled && --setup.waiting === 0) {
          // forgotten first, so a query arriving now starts afresh
          if (associations.get(proxy.key) === setup) associations.delete(proxy.key);
          setup.opening.abort(signal.reason);
        }
        reject(signal.reason);
      };
      signal.addEventListener('abort', onAbort, { once: true });
      setup.promise.then(
        joined => {
          signal.removeEventListener('abort', onAbort);
          resolve(joined);
        },
        error => {
          signal.removeEventListener('abort', onAbort);
          reject(error);
        }
      );
    });
  }

  function overTcp(request: TransportRequest): Promise<TransportResponse> {
    request.onEvent?.({
      event: 'tcp-fallback',
      server: formatHostPort(request.endpoint.host, request.endpoint.port),
      reason: 'proxy',
    });
    return tcp().send(request);
  }

  async function sendProxied(proxy: Proxy, request: TransportRequest): Promise<TransportResponse> {
    const { endpoint, query } = request;
    // UDP needs SOCKS5, and an address to match the answer against: a name is resolved
    // by the proxy, which only a tunnel can ask it to do
    if (proxy.protocol !== 'socks5' || !isIp(endpoint.host) || withoutUdp.has(proxy.key)) {
      return overTcp(request);
    }
    let joined: Association;
    try {
      joined = await association(proxy, request);
    } catch (error) {
      if (error instanceof Socks5ReplyError && error.reply === SOCKS5_COMMAND_NOT_SUPPORTED) {
        withoutUdp.add(proxy.key);
        return overTcp(request);
      }
      throw error;
    }
    if (request.signal?.aborted) throw request.signal.reason;

    const id = (query[0] << 8) | query[1];
    const datagram = concatBytes([
      Uint8Array.of(0x00, 0x00, 0x00),
      socks5Address(endpoint.host, endpoint.port),
      query,
    ]);
    return sendAndWait(
      joined.shared,
      keyOf(normalizeAddress(endpoint.host), endpoint.port, id),
      datagram,
      joined.relay,
      request
    );
  }

  return {
    name: 'udp',

    send(request) {
      if (closed) return Promise.reject(new ConnectionError('The UDP transport is closed'));
      if (request.signal?.aborted) return Promise.reject(request.signal.reason);
      let proxy: Proxy | undefined;
      try {
        // as in the TCP transport: an endpoint handed straight in is checked here
        checkHost(request.endpoint.host);
        proxy = resolveProxy(options.proxy, {
          host: request.endpoint.host,
          port: request.endpoint.port,
          transport: 'udp',
        });
      } catch (error) {
        return Promise.reject(error);
      }
      return proxy ? sendProxied(proxy, request) : sendDirect(request);
    },

    close() {
      closed = true;
      const error = new ConnectionError('The UDP transport was closed');
      for (const shared of [...open]) failAll(shared, error);
      open.clear();
      for (const setup of associations.values()) {
        // one still being set up stops, and its callers hear why
        setup.opening.abort(error);
        setup.promise.then(
          joined => {
            failAll(joined.shared, error);
            void closeQuietly(joined.control);
          },
          () => undefined
        );
      }
      associations.clear();
      ownTcp?.close();
    },
  };
}
