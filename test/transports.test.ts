import {
  ConnectionError,
  DnsError,
  EmptyResponseError,
  InvalidResponseError,
  NoServerError,
  TimeoutError,
} from '../src/errors';
import { exchange } from '../src/exchange';
import { createCloudflareConnect } from '../src/transports/cloudflare';
import type { CloudflareSocket } from '../src/transports/cloudflare';
import { toBase64Url } from '../src/transports/doh';
import { normalizeAddress, toEndpoint } from '../src/transports/endpoint';
import { createTcpTransport, createTransports, createUdpTransport } from '../src/transports/index';
import type { Transports } from '../src/transports/index';
import type { FetchLike, Transport } from '../src/transports/types';
import { decodeMessage, encodeQuery } from '../src/wire/index';
import { answerTo, askedName } from './support/answers';
import { startFixtureServer } from './support/fixture-server';
import type { FixtureServer } from './support/fixture-server';
import { startDohServer, startDotServer, testCertificate } from './support/secure-servers';
import type { DohServer, DotServer } from './support/secure-servers';

// the transports apart from the proxies: server addresses, DoH, DoT, and the corners of
// UDP and TCP that `exchange` cannot reach on its own

const QUESTION = { name: 'example.com', type: 'A' };

describe('toEndpoint', () => {
  it('fills in the port for the transport', () => {
    expect(toEndpoint('192.0.2.1', 'udp')).toEqual({ host: '192.0.2.1', port: 53 });
    expect(toEndpoint('192.0.2.1', 'tcp')).toEqual({ host: '192.0.2.1', port: 53 });
    expect(toEndpoint('192.0.2.1', 'tls')).toEqual({
      host: '192.0.2.1',
      port: 853,
      serverName: '192.0.2.1',
    });
    expect(toEndpoint('dns.example', 'doh')).toEqual({
      host: 'dns.example',
      port: 443,
      url: 'https://dns.example/dns-query',
    });
  });

  it('reads a port written into the server, which beats the port option', () => {
    expect(toEndpoint('192.0.2.1:5353', 'udp', 99)).toEqual({ host: '192.0.2.1', port: 5353 });
    expect(toEndpoint('192.0.2.1', 'udp', 99)).toEqual({ host: '192.0.2.1', port: 99 });
    expect(toEndpoint('[2001:db8::1]:5353', 'tcp')).toEqual({ host: '2001:db8::1', port: 5353 });
    expect(toEndpoint('[2001:db8::1]', 'tcp')).toEqual({ host: '2001:db8::1', port: 53 });
    // a bare IPv6 address has colons of its own
    expect(toEndpoint('2001:db8::1', 'udp')).toEqual({ host: '2001:db8::1', port: 53 });
  });

  it('takes a DoH server as a URL, a name, or an address', () => {
    expect(toEndpoint('https://dns.example/custom?x=1', 'doh')).toEqual({
      host: 'dns.example',
      port: 443,
      url: 'https://dns.example/custom?x=1',
    });
    expect(toEndpoint('http://127.0.0.1:8053/dns-query', 'doh')).toEqual({
      host: '127.0.0.1',
      port: 8053,
      url: 'http://127.0.0.1:8053/dns-query',
    });
    expect(toEndpoint('2001:db8::1', 'doh').url).toBe('https://[2001:db8::1]/dns-query');
    expect(toEndpoint('dns.example:8443', 'doh').url).toBe('https://dns.example:8443/dns-query');
  });

  it('takes a server described as an object', () => {
    expect(toEndpoint({ address: '192.0.2.1', serverName: 'dns.example' }, 'tls')).toEqual({
      host: '192.0.2.1',
      port: 853,
      serverName: 'dns.example',
    });
    expect(toEndpoint({ address: '192.0.2.1', port: 8853 }, 'tls', 1).port).toBe(8853);
  });

  it('rejects a server it cannot read', () => {
    expect(() => toEndpoint('', 'udp')).toThrow(NoServerError);
    expect(() => toEndpoint('192.0.2.1:notaport', 'udp')).toThrow(NoServerError);
    expect(() => toEndpoint('192.0.2.1:70000', 'udp')).toThrow(NoServerError);
    expect(() => toEndpoint('[2001:db8::1', 'udp')).toThrow(NoServerError);
  });

  it('accepts only an address or a host name as the host', () => {
    // a line break in a host would split the request line sent to an HTTP proxy
    const hostile = [
      'evil.example\r\nX-Injected: 1',
      'evil.example\nGET / HTTP/1.1',
      'a b',
      'a/b',
      'a@b',
    ];
    for (const host of hostile) {
      for (const transport of ['udp', 'tcp', 'tls', 'doh'] as const) {
        expect(() => toEndpoint(host, transport), host).toThrow(NoServerError);
        expect(() => toEndpoint({ address: host }, transport), host).toThrow(NoServerError);
      }
    }
    expect(() =>
      toEndpoint({ address: '192.0.2.1', serverName: 'dns.example\r\nX: 1' }, 'tls')
    ).toThrow(NoServerError);
    // names with underscores, trailing dots and Unicode are still names
    expect(toEndpoint('_dns.resolver.arpa.', 'udp').host).toBe('_dns.resolver.arpa.');
    expect(toEndpoint('dns.münchen.example', 'tcp').host).toBe('dns.xn--mnchen-3ya.example');
    expect(toEndpoint('fe80::1%en0', 'udp').host).toBe('fe80::1%en0');
  });

  it('never repeats a server it cannot read, which may hold a secret', () => {
    const secrets = [
      'user:hunter2@192.0.2.1',
      'https://user:hunter2@dns.example/dns-query',
      'https://user:hunter2@bad host/',
      '[hunter2',
      '192.0.2.1:hunter2',
    ];
    for (const server of secrets) {
      for (const transport of ['udp', 'doh'] as const) {
        let error: unknown;
        try {
          toEndpoint(server, transport);
        } catch (caught) {
          error = caught;
        }
        expect(error, server).toBeInstanceOf(NoServerError);
        const text = `${(error as Error).message} ${JSON.stringify(error)} ${String((error as Error).cause)}`;
        expect(text).not.toContain('hunter2');
      }
    }
  });

  it('refuses a DoH URL that carries credentials or is not HTTP', () => {
    expect(() => toEndpoint('https://token@dns.example/dns-query', 'doh')).toThrow(/credentials/);
    expect(() =>
      toEndpoint({ address: 'dns.example', url: 'https://u:p@dns.example/dns-query' }, 'doh')
    ).toThrow(/credentials/);
    expect(() => toEndpoint({ address: 'dns.example', url: 'ftp://dns.example/' }, 'doh')).toThrow(
      NoServerError
    );
  });
});

describe('normalizeAddress', () => {
  it('gives every spelling of an IPv6 address one form', () => {
    expect(normalizeAddress('2001:0db8:0000:0000:0000:0000:0000:0001')).toBe('2001:db8::1');
    expect(normalizeAddress('2001:DB8::1')).toBe('2001:db8::1');
    expect(normalizeAddress('fe80::1%en0')).toBe('fe80::1');
    expect(normalizeAddress('192.0.2.1')).toBe('192.0.2.1');
  });
});

describe('UDP and TCP transports', () => {
  let server: FixtureServer;
  let transport: Transport;

  afterEach(async () => {
    transport?.close();
    await server?.close();
  });

  // two queries with the same ID in flight to the same server: random 16-bit IDs make
  // this rare, not impossible
  const colliding = () => {
    const first = encodeQuery({ id: 7, name: 'first.example', type: 'A' });
    const second = encodeQuery({ id: 7, name: 'second.example', type: 'A' });
    const wants = (name: string) => (bytes: Uint8Array) =>
      decodeMessage(bytes).questions[0].name === name;
    return { first, second, wants };
  };

  it.each([
    ['udp', () => createUdpTransport()],
    ['tcp', () => createTcpTransport({ pipeline: true })],
  ] as const)('gives each of two queries with one ID its own answer over %s', async (_, make) => {
    // answer in the opposite order to the one they were asked in
    server = await startFixtureServer(({ query }) => ({
      response: answerTo(query),
      delayMs: askedName(query) === 'first.example' ? 40 : 0,
    }));
    transport = make();
    const endpoint = { host: server.address, port: server.port };
    const { first, second, wants } = colliding();
    const [a, b] = await Promise.all([
      transport.send({ endpoint, query: first, accept: wants('first.example') }),
      transport.send({ endpoint, query: second, accept: wants('second.example') }),
    ]);
    expect(askedName(a.bytes)).toBe('first.example');
    expect(askedName(b.bytes)).toBe('second.example');
  });

  it('fails what is in flight when a transport is closed', async () => {
    server = await startFixtureServer(() => undefined);
    for (const make of [createUdpTransport, createTcpTransport]) {
      transport = make();
      const pending = transport.send({
        endpoint: { host: server.address, port: server.port },
        query: encodeQuery({ id: 1, name: 'example.com', type: 'A' }),
      });
      // let the query reach the wire first
      await new Promise(resolve => setTimeout(resolve, 20));
      transport.close();
      await expect(pending).rejects.toBeInstanceOf(ConnectionError);
      await expect(
        transport.send({
          endpoint: { host: server.address, port: server.port },
          query: encodeQuery({ id: 2, name: 'example.com', type: 'A' }),
        })
      ).rejects.toBeInstanceOf(ConnectionError);
    }
  });
});

describe('DNS over TLS', () => {
  let server: DotServer;
  let transports: Transports;

  beforeEach(async () => {
    server = await startDotServer(query => answerTo(query));
  });

  afterEach(async () => {
    transports?.close();
    await server.close();
  });

  it('asks over an encrypted connection and reuses it', async () => {
    transports = createTransports({ tls: { ca: testCertificate().cert } });
    const options = { transport: 'tls' as const, port: server.port, transports };
    const first = await exchange(QUESTION, server.address, options);
    const second = await exchange(QUESTION, server.address, options);
    expect(first.transport).toBe('tls');
    expect(first.message.answers).toHaveLength(1);
    expect(second.message.answers).toHaveLength(1);
    expect(server.received).toHaveLength(2);
    expect(server.connections).toBe(1);
    expect(first.toDig()).toBe(`dig +tls -p ${server.port} @127.0.0.1 example.com A`);
  });

  it('checks the certificate against the server name', async () => {
    transports = createTransports({ tls: { ca: testCertificate().cert } });
    const options = { transport: 'tls' as const, transports, retries: 0 };
    // the certificate names localhost, so this verifies
    await exchange(
      QUESTION,
      { address: '127.0.0.1', port: server.port, serverName: 'localhost' },
      options
    );
    // and it does not name this
    const error = await exchange(
      QUESTION,
      { address: '127.0.0.1', port: server.port, serverName: 'dns.example' },
      options
    ).catch(caught => caught);
    expect(error).toBeInstanceOf(ConnectionError);
    expect(error.transport).toBe('tls');
  });

  it('refuses a certificate it has no reason to trust', async () => {
    transports = createTransports();
    const error = await exchange(QUESTION, server.address, {
      transport: 'tls',
      port: server.port,
      transports,
      retries: 0,
    }).catch(caught => caught);
    expect(error).toBeInstanceOf(ConnectionError);
    expect(server.received).toHaveLength(0);
  });
});

describe('DNS over HTTPS', () => {
  let server: DohServer;
  let transports: Transports;

  afterEach(async () => {
    transports?.close();
    await server?.close();
  });

  it('sends the query in the URL of a GET by default', async () => {
    server = await startDohServer(query => answerTo(query));
    transports = createTransports();
    const result = await exchange(QUESTION, server.url, { transports });

    // a server given as a URL is asked over DoH without being told to
    expect(result.transport).toBe('doh');
    expect(result.message.answers).toHaveLength(1);
    const [request] = server.requests;
    expect(request.method).toBe('GET');
    expect(request.url).toBe(`/dns-query?dns=${toBase64Url(result.query.bytes)}`);
    expect(request.headers.accept).toBe('application/dns-message');
    // ID 0, so HTTP caches can share the answer
    expect(result.query.id).toBe(0);
    expect(decodeMessage(request.query).id).toBe(0);
    expect(result.toDig()).toBe(`dig +https -p ${server.port} @127.0.0.1 example.com A`);
  });

  it('sends the query as the body of a POST when asked to', async () => {
    server = await startDohServer(query => answerTo(query));
    transports = createTransports({ dohMethod: 'POST' });
    const result = await exchange(QUESTION, server.url, { transports });
    const [request] = server.requests;
    expect(request.method).toBe('POST');
    expect(request.url).toBe('/dns-query');
    expect(request.headers['content-type']).toBe('application/dns-message');
    expect(request.query).toEqual(result.query.bytes);
  });

  it('keeps the query string of the URL it was given', async () => {
    server = await startDohServer(query => answerTo(query));
    transports = createTransports();
    await exchange(QUESTION, `${server.url}?token=abc`, { transports });
    expect(server.requests[0].url).toMatch(/^\/dns-query\?token=abc&dns=/);
  });

  it('reports a server error as a failure worth retrying', async () => {
    server = await startDohServer(query => answerTo(query), { status: 503 });
    transports = createTransports();
    const error = await exchange(QUESTION, server.url, { transports, retries: 1 }).catch(
      caught => caught
    );
    expect(error).toBeInstanceOf(ConnectionError);
    expect(error.message).toContain('HTTP 503');
    expect(server.requests).toHaveLength(2);
  });

  it('reports a rejected request as an invalid response', async () => {
    server = await startDohServer(query => answerTo(query), { status: 400 });
    transports = createTransports();
    const error = await exchange(QUESTION, server.url, { transports }).catch(caught => caught);
    expect(error).toBeInstanceOf(InvalidResponseError);
    expect(server.requests).toHaveLength(1);
  });

  it('rejects a response that is not a DNS message', async () => {
    server = await startDohServer(query => answerTo(query), { contentType: 'text/html' });
    transports = createTransports();
    const error = await exchange(QUESTION, server.url, { transports }).catch(caught => caught);
    expect(error).toBeInstanceOf(InvalidResponseError);
    expect(error.message).toContain('text/html');
  });

  it('reports an empty body', async () => {
    server = await startDohServer(() => new Uint8Array(0));
    transports = createTransports();
    await expect(exchange(QUESTION, server.url, { transports, retries: 0 })).rejects.toBeInstanceOf(
      EmptyResponseError
    );
  });

  it('times out when the server never answers', async () => {
    server = await startDohServer(() => undefined);
    transports = createTransports();
    await expect(
      exchange(QUESTION, server.url, { transports, timeout: 80, retries: 0 })
    ).rejects.toBeInstanceOf(TimeoutError);
  });

  it('uses the fetch it is given', async () => {
    server = await startDohServer(query => answerTo(query));
    const calls: string[] = [];
    const custom: FetchLike = (url, init) => {
      calls.push(`${init.method} ${url}`);
      return fetch(url, init as RequestInit);
    };
    const result = await exchange(QUESTION, server.url, { fetch: custom });
    expect(result.message.answers).toHaveLength(1);
    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatch(/^GET http:\/\/127\.0\.0\.1:\d+\/dns-query\?dns=/);
  });

  it('refuses a URL with credentials before fetch can repeat them in an error', async () => {
    server = await startDohServer(query => answerTo(query));
    const events: unknown[] = [];
    const withToken = server.url.replace('http://', 'http://user:hunter2@');
    transports = createTransports();
    // through `exchange`, and straight into the transport with an endpoint of its own
    const attempts = [
      exchange(QUESTION, withToken, { transports, retries: 0, onEvent: e => events.push(e) }),
      transports.get('doh').send({
        endpoint: { host: '127.0.0.1', port: server.port, url: withToken },
        query: encodeQuery({ id: 0, name: 'example.com', type: 'A' }),
      }),
    ];
    for (const attempt of attempts) {
      const error = await attempt.catch(caught => caught);
      expect(error).toBeInstanceOf(NoServerError);
      expect(error.retryable).toBe(false);
      expect(
        `${error.message} ${error.stack} ${JSON.stringify(error)} ${String(error.cause)}`
      ).not.toContain('hunter2');
    }
    expect(JSON.stringify(events)).not.toContain('hunter2');
    expect(server.requests).toHaveLength(0);
  });

  it('turns whatever a custom fetch throws into a connection error', async () => {
    const error = await exchange(QUESTION, 'https://dns.example/dns-query', {
      retries: 0,
      fetch: () => Promise.reject(new TypeError('fetch failed')),
    }).catch(caught => caught);
    expect(error).toBeInstanceOf(ConnectionError);
    expect(error.retryable).toBe(true);
    expect(error.cause).toBeInstanceOf(TypeError);
  });
});

describe('the Cloudflare connector', () => {
  // the runtime is not here to test against, so this checks the calls the connector
  // makes against the shape of the Workers socket API
  it('opens a plain connection that can be upgraded to TLS', async () => {
    const calls: unknown[] = [];
    const socket = (label: string): CloudflareSocket => ({
      readable: new ReadableStream<Uint8Array>(),
      writable: new WritableStream<Uint8Array>(),
      close: () => {
        calls.push(`${label} closed`);
        return Promise.resolve();
      },
      startTls: options => {
        calls.push(['startTls', options]);
        return socket('secure');
      },
    });
    const connect = createCloudflareConnect((address, options) => {
      calls.push(['connect', address, options]);
      return socket('plain');
    });

    const plain = await connect({ hostname: 'dns.example', port: 853 });
    const secure = await plain.startTls('dns.example');
    await secure.close();
    expect(calls).toEqual([
      ['connect', { hostname: 'dns.example', port: 853 }, { secureTransport: 'starttls' }],
      ['startTls', { expectedServerHostname: 'dns.example' }],
      'secure closed',
    ]);
  });

  it('refuses a TLS upgrade to a host other than the one it connected to', async () => {
    // deployed Workers close such a connection without an error, which is what a proxy
    // tunnel or a server given by address would run into
    let upgrades = 0;
    const socket: CloudflareSocket = {
      readable: new ReadableStream<Uint8Array>(),
      writable: new WritableStream<Uint8Array>(),
      close: () => Promise.resolve(),
      startTls: () => {
        upgrades++;
        return socket;
      },
    };
    const connect = createCloudflareConnect(() => socket);

    const viaProxy = await connect({ hostname: 'proxy.example', port: 1080 });
    expect(() => viaProxy.startTls('dns.example')).toThrow(DnsError);
    expect(() => viaProxy.startTls('dns.example')).toThrow(/Through a proxy there/);
    const byAddress = await connect({ hostname: '192.0.2.1', port: 853 });
    expect(() => byAddress.startTls('dns.example')).toThrow(DnsError);
    expect(upgrades).toBe(0);

    // the same name, however it is written, is fine
    const direct = await connect({ hostname: 'DNS.example.', port: 853 });
    await direct.startTls('dns.example');
    expect(upgrades).toBe(1);
  });

  it('carries DNS over TCP through a connect function the caller supplies', async () => {
    const server = await startFixtureServer(({ query }) => ({ response: answerTo(query) }));
    // a custom connect, built here on the Node connector, stands in for the runtime's
    const { createNodeConnect } = await import('../src/transports/index');
    const targets: string[] = [];
    const node = createNodeConnect();
    try {
      const result = await exchange(QUESTION, server.address, {
        transport: 'tcp',
        port: server.port,
        connect: target => {
          targets.push(`${target.hostname}:${target.port}`);
          return node(target);
        },
      });
      expect(result.message.answers).toHaveLength(1);
      expect(targets).toEqual([`127.0.0.1:${server.port}`]);
    } finally {
      await server.close();
    }
  });

  it('turns whatever a custom connect throws into a connection error', async () => {
    const error = await exchange(QUESTION, '192.0.2.1', {
      transport: 'tcp',
      retries: 0,
      connect: () => Promise.reject(new Error('no route')),
    }).catch(caught => caught);
    expect(error).toBeInstanceOf(ConnectionError);
    expect(error.message).toContain('no route');
    expect(error.retryable).toBe(true);
  });
});
