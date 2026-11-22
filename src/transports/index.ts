// @aoxborrow/dns/transports: the four transports, to send a message you encoded yourself,
// and the set of them that resolvers share (`createTransports`). Node's modules are loaded
// when a connection is first opened, never at import.
//
// `/transports/doh` is DNS over HTTPS alone, without UDP and TCP beside it
export { closeDefaultTransports, createTransports } from './set';
export type { Transports } from './set';
export { createDohTransport } from './doh';
export { createTcpTransport } from './tcp';
export { createTlsTransport } from './tls';
export { createUdpTransport } from './udp';
export { createNodeConnect } from './node';
export { createCloudflareConnect } from './cloudflare';
export { DEFAULT_PORTS } from './endpoint';
export type { DohTransportOptions } from './doh';
export type { TcpTransportOptions } from './tcp';
export type { TlsTransportOptions } from './tls';
export type { UdpTransportOptions } from './udp';
export type { CloudflareConnectFunction, CloudflareSocket } from './cloudflare';
export type * from './types';
