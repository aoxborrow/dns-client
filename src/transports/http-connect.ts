import { ConnectionError, ProxyError } from '../errors';
import { latin1Decode, latin1Encode } from '../wire/bytes';
import { checkHost, formatHostPort } from './endpoint';
import { basicCredentials } from './proxy';
import type { Proxy } from './proxy';
import { ConnectionClosedError, writeBytes } from './stream';
import type { StreamReader } from './stream';
import type { Connection } from './types';

// the HTTP CONNECT handshake: ask the proxy for a tunnel, read its verdict

const HEADER_END = latin1Encode('\r\n\r\n');
const MAX_HEADER_BYTES = 16 * 1024;

export async function httpConnectHandshake(
  reader: StreamReader,
  connection: Connection,
  proxy: Proxy,
  target: { host: string; port: number }
): Promise<void> {
  // the host goes into the request line as written. One with a line break in it would end
  // that line early and let whatever follows pass as headers, or as a second request
  const authority = formatHostPort(checkHost(target.host), target.port);
  if (!Number.isInteger(target.port) || target.port < 1 || target.port > 0xffff) {
    throw new TypeError('Invalid port in the server address');
  }
  const lines = [`CONNECT ${authority} HTTP/1.1`, `Host: ${authority}`];
  if (proxy.username !== undefined) {
    lines.push(`Proxy-Authorization: ${basicCredentials(proxy)}`);
  }

  let head: string;
  try {
    await writeBytes(connection, latin1Encode(`${lines.join('\r\n')}\r\n\r\n`));
    head = latin1Decode(await reader.readUntil(HEADER_END, MAX_HEADER_BYTES));
  } catch (error) {
    if (error instanceof ConnectionClosedError) {
      throw new ProxyError(`Proxy ${proxy.display} closed the connection during the handshake`, {
        cause: error,
      });
    }
    throw error;
  }

  const status = /^HTTP\/1\.[01] (\d{3})/.exec(head);
  if (!status) throw new ProxyError(`${proxy.display} is not an HTTP proxy`);
  const code = Number(status[1]);
  if (code >= 200 && code < 300) return;

  if (code === 407) {
    throw new ProxyError(
      proxy.username === undefined
        ? `Proxy ${proxy.display} requires authentication`
        : `Proxy ${proxy.display} rejected the credentials`
    );
  }
  // a gateway error means the proxy tried and the target did not answer
  if (code === 502 || code === 504) {
    throw new ConnectionError(`Cannot reach ${authority} through ${proxy.display}: HTTP ${code}`);
  }
  throw new ProxyError(`Proxy ${proxy.display} refused to connect to ${authority}: HTTP ${code}`);
}
