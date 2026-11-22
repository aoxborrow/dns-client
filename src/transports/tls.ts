import { createTcpTransport } from './tcp';
import type { TcpTransportOptions } from './tcp';
import type { Transport } from './types';

// DNS over TLS (RFC 7858): the TCP transport with the connection encrypted. The default
// port is 853, and the certificate is checked against the server's `serverName`, or its
// address when no name is given

/** the options of `createTlsTransport` */
export type TlsTransportOptions = Omit<TcpTransportOptions, 'secure'>;

/**
 * DNS over TLS (RFC 7858): the TCP transport with the connection encrypted, port 853, pipelined by
 * default. The certificate is checked against the server's `serverName`, or its address when no
 * name is given
 */
export function createTlsTransport(options: TlsTransportOptions = {}): Transport {
  return createTcpTransport({ ...options, secure: true });
}
