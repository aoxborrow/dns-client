import { createCloudflareConnect } from './cloudflare';
import { createNodeConnect } from './node';
import type { Connect, TlsOptions } from './types';

// which runtime this is, and what that means for opening connections

// Workers is checked first: with its Node compatibility flag on, it also looks like Node
export const isWorkers = (): boolean =>
  typeof navigator !== 'undefined' && navigator.userAgent === 'Cloudflare-Workers';

// Node, and the runtimes that implement its `net`, `tls` and `dgram` modules
export const isNode = (): boolean =>
  !isWorkers() && typeof process !== 'undefined' && Boolean(process.versions?.node);

// the runtime's own way to open a TCP connection
export function defaultConnect(tls?: TlsOptions): Connect {
  return isWorkers() ? createCloudflareConnect() : createNodeConnect(tls);
}

// milliseconds on a clock that never goes backwards
export const now = (): number => performance.now();
