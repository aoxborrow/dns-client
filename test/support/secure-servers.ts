import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import tls from 'node:tls';

// in-process servers for the encrypted transports: DNS over TLS, and DNS over HTTPS (with
// a plain-HTTP mode so the HTTP side can be tested apart from TLS).
//
// the certificate is made fresh for each test run with the `openssl` command, which CI
// and every developer machine has. Nothing secret is committed, and nothing expires

export interface TestCertificate {
  key: string;
  cert: string;
}

let certificate: TestCertificate | undefined;

// a self-signed certificate for localhost and 127.0.0.1, valid for a couple of days
export function testCertificate(): TestCertificate {
  if (certificate) return certificate;
  const dir = mkdtempSync(path.join(tmpdir(), 'dns-cert-'));
  try {
    const key = path.join(dir, 'key.pem');
    const cert = path.join(dir, 'cert.pem');
    execFileSync(
      'openssl',
      [
        ...['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1'],
        ...['-nodes', '-keyout', key, '-out', cert, '-days', '2', '-subj', '/CN=localhost'],
        ...['-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1'],
      ],
      { stdio: 'ignore' }
    );
    certificate = { key: readFileSync(key, 'utf8'), cert: readFileSync(cert, 'utf8') };
    return certificate;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// from raw query bytes to raw response bytes, or undefined to stay silent
export type SecureResponder = (query: Uint8Array) => Uint8Array | undefined;

// the response with the query's ID
function withQueryId(response: Uint8Array, query: Uint8Array): Uint8Array {
  if (response.length < 2) return response;
  const patched = Uint8Array.from(response);
  patched.set(query.subarray(0, 2), 0);
  return patched;
}

// ---------------------------------------------------------------------------
// DNS over TLS
// ---------------------------------------------------------------------------

export interface DotServer {
  address: string;
  port: number;
  received: Uint8Array[];
  readonly connections: number;
  close(): Promise<void>;
}

export async function startDotServer(respond: SecureResponder): Promise<DotServer> {
  const received: Uint8Array[] = [];
  const sockets = new Set<tls.TLSSocket>();
  let connections = 0;

  const server = tls.createServer(testCertificate(), socket => {
    connections++;
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.on('error', () => socket.destroy());
    let buffered = Buffer.alloc(0);
    socket.on('data', (chunk: Buffer) => {
      buffered = Buffer.concat([buffered, chunk]);
      while (buffered.length >= 2 && buffered.length >= 2 + buffered.readUInt16BE(0)) {
        const length = buffered.readUInt16BE(0);
        const query = Uint8Array.from(buffered.subarray(2, 2 + length));
        buffered = buffered.subarray(2 + length);
        received.push(query);
        const response = respond(query);
        if (!response) continue;
        const body = withQueryId(response, query);
        const framed = Buffer.alloc(2 + body.length);
        framed.writeUInt16BE(body.length, 0);
        framed.set(body, 2);
        socket.write(framed);
      }
    });
  });
  // a failed handshake is the client's problem, not a reason to crash the test
  server.on('tlsClientError', () => undefined);
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));

  return {
    address: '127.0.0.1',
    port: (server.address() as AddressInfo).port,
    received,
    get connections() {
      return connections;
    },
    async close() {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>(resolve => server.close(() => resolve()));
    },
  };
}

// ---------------------------------------------------------------------------
// DNS over HTTPS
// ---------------------------------------------------------------------------

export interface DohRequest {
  method: string;
  url: string;
  headers: http.IncomingHttpHeaders;
  query: Uint8Array;
}

export interface DohServerOptions {
  // serve over TLS with the test certificate. Default false: plain HTTP
  secure?: boolean;
  // answer every request with this status
  status?: number;
  // the Content-Type to answer with. Default application/dns-message
  contentType?: string;
  // send the body in pieces with no Content-Length, so it goes out chunked
  chunked?: boolean;
  // close the connection after each response
  closeConnection?: boolean;
}

export interface DohServer {
  // where queries go, e.g. http://127.0.0.1:1234/dns-query
  url: string;
  port: number;
  requests: DohRequest[];
  readonly connections: number;
  close(): Promise<void>;
}

export async function startDohServer(
  respond: SecureResponder,
  options: DohServerOptions = {}
): Promise<DohServer> {
  const requests: DohRequest[] = [];
  let connections = 0;

  const handler = (request: http.IncomingMessage, response: http.ServerResponse) => {
    const chunks: Buffer[] = [];
    request.on('data', (chunk: Buffer) => chunks.push(chunk));
    request.on('end', () => {
      const url = new URL(request.url ?? '/', 'http://localhost');
      const encoded = url.searchParams.get('dns');
      const query =
        request.method === 'GET' && encoded
          ? Uint8Array.from(Buffer.from(encoded, 'base64url'))
          : Uint8Array.from(Buffer.concat(chunks));
      requests.push({
        method: request.method ?? '',
        url: request.url ?? '',
        headers: request.headers,
        query,
      });

      const answer = respond(query);
      if (!answer) return; // leave the request hanging
      const body = Buffer.from(withQueryId(answer, query));
      response.statusCode = options.status ?? 200;
      response.setHeader('Content-Type', options.contentType ?? 'application/dns-message');
      if (options.closeConnection) response.setHeader('Connection', 'close');
      if (options.chunked) {
        const half = Math.ceil(body.length / 2);
        response.write(body.subarray(0, half));
        response.write(body.subarray(half));
        response.end();
      } else {
        response.end(body);
      }
    });
  };

  const server = options.secure
    ? https.createServer(testCertificate(), handler)
    : http.createServer(handler);
  server.on(options.secure ? 'secureConnection' : 'connection', () => connections++);
  server.on('tlsClientError', () => undefined);
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;

  return {
    url: `${options.secure ? 'https' : 'http'}://127.0.0.1:${port}/dns-query`,
    port,
    requests,
    get connections() {
      return connections;
    },
    async close() {
      server.closeAllConnections();
      await new Promise<void>(resolve => server.close(() => resolve()));
    },
  };
}
