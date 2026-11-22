import type { ErrorData } from '../errors';
import type { RcodeName } from '../protocol/header';

// the shapes every transport shares. Nothing in this file touches a runtime API, so any
// entry point can import it

export type TransportName = 'udp' | 'tcp' | 'tls' | 'doh';

// a server, as a caller may describe it
export interface Server {
  // an IP address or a hostname
  address: string;
  // defaults to the transport's own: 53, 853 for DoT, 443 for DoH
  port?: number;
  // DoT: the name the certificate has to match. Defaults to the address
  serverName?: string;
  // DoH: the URL queries are sent to. Defaults to https://<address>/dns-query
  url?: string;
}

// a server with everything a transport needs filled in
export interface Endpoint {
  host: string;
  port: number;
  serverName?: string;
  url?: string;
}

// ---- connections

// a byte stream to a remote host. The shape is Cloudflare's `Socket`, which is also the
// smallest thing a proxy handshake and a TLS upgrade can be written against
export interface Connection {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
  close(): void | Promise<void>;
  // upgrade to TLS in place, checking the certificate against `hostname`. The connection
  // this was called on must not be used afterwards
  startTls(hostname: string): Connection | Promise<Connection>;
  // optional, for runtimes where an open connection keeps the process alive: `unref`
  // lets it exit while the connection is idle, `ref` holds it while a query is in flight
  ref?(): void;
  unref?(): void;
}

export interface ConnectTarget {
  hostname: string;
  port: number;
}

// open a plain TCP connection. TLS is always a `startTls` on the result
export type Connect = (target: ConnectTarget) => Connection | Promise<Connection>;

// the part of `fetch` that DoH uses
export type FetchLike = (
  url: string,
  init: {
    method: string;
    headers: Record<string, string>;
    body?: Uint8Array;
    signal?: AbortSignal;
  }
) => Promise<{
  status: number;
  headers: { get(name: string): string | null };
  arrayBuffer(): Promise<ArrayBuffer>;
}>;

// ---- proxies

export interface ProxyTarget {
  host: string;
  port: number;
  transport: TransportName;
}

// a proxy URL (`socks5://user:pass@host:1080`, `http://host:3128`), or a function that
// picks one per target; returning nothing means no proxy for that target
export type ProxyInput = string | URL | ((target: ProxyTarget) => string | URL | undefined);

// TLS settings for DoT, and DoH over HTTP/2. Node only; other runtimes use their own trust
// store
export interface TlsOptions {
  // certificate authorities to trust instead of the runtime's, PEM
  ca?: string | readonly string[];
  // accept a certificate that does not verify. For tests against throwaway servers
  rejectUnauthorized?: boolean;
}

export interface TransportOptions {
  // send everything through this proxy. Nothing falls back to a direct connection. DoH
  // goes through it over HTTP/2 on Node; elsewhere, and to a server that does not offer
  // HTTP/2, it needs `fetch` as well
  proxy?: ProxyInput;
  // how DoH requests are made. Default: HTTP/2 with `node:http2` on Node for an https://
  // URL, and the runtime's `fetch` otherwise
  fetch?: FetchLike;
  // how TCP connections are opened. Wins over `proxy` for TCP and DoT
  connect?: Connect;
  tls?: TlsOptions;
  // with `pipeline`: how long an unused TCP or DoT connection is kept open, in
  // milliseconds; and how long a DoH HTTP/2 session is. 0 closes each connection as soon
  // as its queries are answered. Default 5000
  idleTimeout?: number;
  // keep TCP connections open and send several queries down one at a time (RFC 7766).
  // Default false for TCP: each query gets a connection of its own, closed when it is
  // answered. Plenty of authoritative servers, Cloudflare's among them, answer the first
  // query on a connection and say nothing to the rest. Default true for DoT, where the
  // handshake is dear and the servers are resolvers that expect it. Worth turning on for
  // TCP to a resolver known to handle it
  pipeline?: boolean;
  // DoH request method. Default GET
  dohMethod?: 'GET' | 'POST';
}

// ---- events

// one per network exchange, whether it worked or not
export interface QueryEvent {
  event: 'query';
  server: string;
  port: number;
  query: string;
  type: string;
  // the transport the query actually went over
  transport: TransportName;
  // 1 for the first attempt
  attempt: number;
  // milliseconds
  elapsed: number;
  bytesSent: number;
  bytesReceived?: number;
  rcode?: number;
  rcodeName?: RcodeName | `RCODE${number}`;
  truncated?: boolean;
  error?: ErrorData;
}

// an attempt failed and another is about to be made
export interface RetryEvent {
  event: 'retry';
  server: string;
  query: string;
  type: string;
  transport: TransportName;
  // the attempt about to start
  attempt: number;
  error: ErrorData;
}

// a query that was meant for UDP is going over TCP instead
export interface TcpFallbackEvent {
  event: 'tcp-fallback';
  server: string;
  query?: string;
  type?: string;
  // the UDP answer was truncated, or the proxy cannot carry UDP
  reason: 'truncated' | 'proxy';
}

// a proxy was asked for a tunnel or a UDP association
export interface ProxyEvent {
  event: 'proxy';
  // the proxy, without credentials
  proxy: string;
  command: 'connect' | 'udp-associate';
  // host:port the proxy was asked to reach
  target: string;
  elapsed: number;
  error?: ErrorData;
}

// a truncated UDP answer could not be asked again over TCP: the TCP query failed, or there
// was no time left for it. The truncated answer is what comes back
export interface TcpFallbackFailedEvent {
  event: 'tcp-fallback-failed';
  server: string;
  query: string;
  type: string;
  error: ErrorData;
}

export type DnsEvent =
  QueryEvent | RetryEvent | TcpFallbackEvent | TcpFallbackFailedEvent | ProxyEvent;
export type OnEvent = (event: DnsEvent) => void;

// ---- the transport itself

export interface TransportRequest {
  endpoint: Endpoint;
  // a whole DNS message; its first two bytes are the ID answers are matched on
  query: Uint8Array;
  // rejects the send with the signal's reason and frees whatever it was holding
  signal?: AbortSignal;
  // UDP only: whether a datagram that carries the right ID from the right address is the
  // answer. Anything refused is dropped and the wait goes on
  accept?: (response: Uint8Array) => boolean;
  // UDP only: aborts when the whole exchange is over. The query's socket then outlives the
  // attempt until it does, so a retransmission with the same `lifetime` goes out from the
  // same port and a late answer to either copy is heard. Without it the socket closes
  // when the send ends
  lifetime?: AbortSignal;
  onEvent?: OnEvent;
}

export interface TransportResponse {
  bytes: Uint8Array;
  // the transport that carried the answer, which is TCP for a UDP query sent through a
  // proxy that cannot carry UDP
  transport: TransportName;
}

export interface Transport {
  readonly name: TransportName;
  send(request: TransportRequest): Promise<TransportResponse>;
  // close every socket and connection, failing whatever is still in flight
  close(): void;
}
