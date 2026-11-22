import { DnsError } from '../errors';
import type { Connect, Connection } from './types';

// the Cloudflare Workers connector, over the runtime's own `connect()` from
// `cloudflare:sockets`.
//
// this connector has not itself run on Workers. What it does follows a spike that ran the
// same socket calls on a deployed Worker

/** the parts of a Workers `Socket` this needs */
export interface CloudflareSocket {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
  close(): Promise<void>;
  startTls(options?: { expectedServerHostname?: string }): CloudflareSocket;
}

/** the runtime's `connect` from `cloudflare:sockets` */
export type CloudflareConnectFunction = (
  address: { hostname: string; port: number },
  options?: { secureTransport?: 'off' | 'on' | 'starttls'; allowHalfOpen?: boolean }
) => CloudflareSocket;

const sameHost = (a: string, b: string) =>
  a.replace(/\.$/, '').toLowerCase() === b.replace(/\.$/, '').toLowerCase();

function wrapSocket(socket: CloudflareSocket, connectedTo: string): Connection {
  return {
    readable: socket.readable,
    writable: socket.writable,
    close: () => socket.close(),
    startTls(hostname) {
      // a deployed Worker only completes a TLS upgrade for the host the socket was opened
      // to. Opened to a proxy, or to an address with another name expected on the
      // certificate, the runtime closes the socket without a word (local workerd does
      // not, which is why this is refused here and not left to fail). That rules out DoT
      // and DoH through a proxy on Workers
      if (!sameHost(hostname, connectedTo)) {
        throw new DnsError(
          `Cloudflare Workers cannot start TLS with ${hostname} on a connection opened to ` +
            `${connectedTo}. Through a proxy there, DNS over HTTPS needs a \`fetch\` that does ` +
            'its own TLS (the tunnelfetch package is one) and DNS over TLS is not available; ' +
            'without a proxy, a DoT server has to be given by the name on its certificate'
        );
      }
      return wrapSocket(socket.startTls({ expectedServerHostname: hostname }), connectedTo);
    },
  };
}

// the specifier is kept out of a literal `import()` so a bundler building for another
// runtime does not try to resolve a module that only exists on Workers
const SOCKETS_MODULE = 'cloudflare:sockets';

/**
 * the `connect` for Cloudflare Workers. Pass it the runtime's own:
 *
 * ```ts
 * import { connect } from 'cloudflare:sockets';
 * createCloudflareConnect(connect);
 * ```
 *
 * Without it the module is imported by name at run time, which a bundled Worker cannot do:
 * its bundler never saw the import, so there is nothing to load. Passing `connect` is the
 * way that always works
 */
export function createCloudflareConnect(connectFunction?: CloudflareConnectFunction): Connect {
  let loaded = connectFunction;
  return async target => {
    if (!loaded) {
      try {
        const module = (await import(/* @vite-ignore */ SOCKETS_MODULE)) as {
          connect: CloudflareConnectFunction;
        };
        loaded = module.connect;
      } catch (cause) {
        throw new DnsError(
          "Cannot load cloudflare:sockets. Import `connect` from 'cloudflare:sockets' " +
            'yourself and pass it as the `connect` option',
          { cause }
        );
      }
    }
    // every connection starts plain and may be upgraded, which is what 'starttls' allows
    return wrapSocket(loaded(target, { secureTransport: 'starttls' }), target.hostname);
  };
}
