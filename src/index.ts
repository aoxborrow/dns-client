// @aoxborrow/dns: the whole library. The narrower entry points (`/records`, `/wire`,
// `/transports/*`) carry less and run in more places.
//
// questions are asked through a resolver. The function both are built on (`./exchange`:
// one question to one server) is not exported: asking one particular server is the
// `server` option on `Resolver.query`
export * from './errors';
export * from './records/index';
export * from './wire/index';
export * from './resolvers/index';
export {
  closeDefaultTransports,
  createCloudflareConnect,
  createNodeConnect,
  createTransports,
  DEFAULT_PORTS,
} from './transports/index';
export type { Transports } from './transports/index';
export type * from './transports/types';
