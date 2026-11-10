// @aoxborrow/dns-client: the whole library. The narrower entry points (`/records`, `/wire`,
// `/transports/*`) carry less and run in more places
export * from './errors';
export * from './records/index';
export * from './wire/index';
export { digCommand, exchange } from './exchange';
export type {
  DigOptions,
  ExchangeOptions,
  ExchangeResult,
  QueryFlag,
  DnsQuestion,
} from './exchange';
export {
  closeDefaultTransports,
  createCloudflareConnect,
  createNodeConnect,
  createTransports,
  createTunnelFetch,
  DEFAULT_PORTS,
} from './transports/index';
export type {
  Transports,
  TunnelFetch,
  TunnelFetchInit,
  TunnelFetchOptions,
} from './transports/index';
export type * from './transports/types';
