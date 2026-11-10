// @aoxborrow/dns-client: the whole library. The narrower entry points (`/records`, `/wire`,
// `/transports/*`) carry less and run in more places.
//
// the resolvers, which are how questions get asked, arrive with the next milestone. The
// function they are built on (`./exchange`: one question to one server) is not exported:
// asking one particular server is an option on a resolver's `query`
export * from './errors';
export * from './records/index';
export * from './wire/index';
export {
  closeDefaultTransports,
  createCloudflareConnect,
  createNodeConnect,
  createTransports,
  DEFAULT_PORTS,
} from './transports/index';
export type { Transports } from './transports/index';
export type * from './transports/types';
