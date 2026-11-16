import http from 'node:http';
import type { AddressInfo } from 'node:net';
import type { Responder } from '../test/support/fixture-server';

// a plain-HTTP DNS-over-HTTPS endpoint on localhost (RFC 8484 without the TLS), answering
// from the same responder as the UDP and TCP fixture server, so the DoH clients can be
// measured offline too. GET with `?dns=` and POST are both served, with keep-alive

export interface DohServer {
  url: string;
  // how many TCP connections the clients opened
  readonly connections: number;
  close(): Promise<void>;
}

const fromBase64Url = (text: string) =>
  Uint8Array.from(Buffer.from(text.replace(/-/g, '+').replace(/_/g, '/'), 'base64'));

export async function startDohServer(respond: Responder): Promise<DohServer> {
  let connections = 0;
  const server = http.createServer((request, response) => {
    const answer = (query: Uint8Array) => {
      const reply = respond({ transport: 'tcp', query });
      if (!reply) {
        response.writeHead(504).end();
        return;
      }
      const body = Uint8Array.from(reply.response);
      // the query's ID, as the fixture server does
      body.set(query.subarray(0, 2), 0);
      response.writeHead(200, {
        'content-type': 'application/dns-message',
        'content-length': body.length,
      });
      response.end(body);
    };
    if (request.method === 'GET') {
      const dns = new URL(request.url ?? '/', 'http://localhost').searchParams.get('dns');
      if (!dns) response.writeHead(400).end();
      else answer(fromBase64Url(dns));
      return;
    }
    const chunks: Buffer[] = [];
    request.on('data', (chunk: Buffer) => chunks.push(chunk));
    request.on('end', () => answer(Uint8Array.from(Buffer.concat(chunks))));
  });
  server.keepAliveTimeout = 30_000;
  server.on('connection', () => connections++);
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}/dns-query`,
    get connections() {
      return connections;
    },
    close: () =>
      new Promise<void>(resolve => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}
