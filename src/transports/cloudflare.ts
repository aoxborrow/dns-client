import type { Connect, Connection } from './types';

// the Cloudflare Workers connector, over the runtime's own `connect()` from
// `cloudflare:sockets`.
//
// not run yet: the shape follows Cloudflare's documentation, and the Workers spike in the
// adoption plan is what proves it

// the parts of a Workers `Socket` this needs
export interface CloudflareSocket {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
  close(): Promise<void>;
  startTls(options?: { expectedServerHostname?: string }): CloudflareSocket;
}

export type CloudflareConnectFunction = (
  address: { hostname: string; port: number },
  options?: { secureTransport?: 'off' | 'on' | 'starttls'; allowHalfOpen?: boolean }
) => CloudflareSocket;

function wrapSocket(socket: CloudflareSocket): Connection {
  return {
    readable: socket.readable,
    writable: socket.writable,
    close: () => socket.close(),
    startTls: hostname => wrapSocket(socket.startTls({ expectedServerHostname: hostname })),
  };
}

// the specifier is kept out of a literal `import()` so a bundler building for another
// runtime does not try to resolve a module that only exists on Workers
const SOCKETS_MODULE = 'cloudflare:sockets';

// pass the runtime's `connect` to skip the dynamic import:
//   import { connect } from 'cloudflare:sockets';
//   createCloudflareConnect(connect)
export function createCloudflareConnect(connectFunction?: CloudflareConnectFunction): Connect {
  let loaded = connectFunction;
  return async target => {
    if (!loaded) {
      const module = (await import(/* @vite-ignore */ SOCKETS_MODULE)) as {
        connect: CloudflareConnectFunction;
      };
      loaded = module.connect;
    }
    // every connection starts plain and may be upgraded, which is what 'starttls' allows
    return wrapSocket(loaded(target, { secureTransport: 'starttls' }));
  };
}
