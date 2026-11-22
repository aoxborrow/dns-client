import { createDohTransport } from './doh';
import { createTcpTransport } from './tcp';
import type { Transport, TransportName, TransportOptions } from './types';
import { createUdpTransport } from './udp';

// the four transports as one thing that shares their sockets and connections between
// queries. A transport is made the first time it is asked for, so a set costs nothing
// for the transports it never uses

export interface Transports {
  get(name: TransportName): Transport;
  // close every socket and connection the set holds
  close(): void;
}

export function createTransports(options: TransportOptions = {}): Transports {
  const made = new Map<TransportName, Transport>();

  const make = (name: TransportName): Transport => {
    switch (name) {
      case 'udp':
        // UDP hands a query to TCP when a proxy cannot carry it
        return createUdpTransport({ ...options, tcp: () => get('tcp') });
      case 'tcp':
        return createTcpTransport(options);
      case 'tls':
        return createTcpTransport({ ...options, secure: true });
      case 'doh':
        return createDohTransport(options);
    }
  };

  const get = (name: TransportName): Transport => {
    let transport = made.get(name);
    if (!transport) made.set(name, (transport = make(name)));
    return transport;
  };

  return {
    get,
    close() {
      for (const transport of made.values()) transport.close();
      made.clear();
    },
  };
}

let shared: Transports | undefined;

// the set used by calls that bring no transport options of their own
export function defaultTransports(): Transports {
  return (shared ??= createTransports());
}

// close the shared set. Its sockets never keep a process alive, so this is for code that
// wants them gone at a known point
export function closeDefaultTransports(): void {
  shared?.close();
  shared = undefined;
}
