import { ConnectionError, DnsError, TimeoutError } from '../src/errors';
import { exchange } from '../src/exchange';
import { createTransports } from '../src/transports/index';
import type { Transports } from '../src/transports/index';
import type { DnsEvent, FetchLike, TransportOptions } from '../src/transports/types';
import { encodeQuery } from '../src/wire/index';
import { answerTo } from './support/answers';
import { startHttpConnectMock, startSocks5Mock } from './support/proxy-mocks';
import type { ProxyMock } from './support/proxy-mocks';
import { startDoh2Server, startDohServer, testCertificate } from './support/secure-servers';
import type { Doh2Server, DohServer } from './support/secure-servers';

// DoH over HTTP/2 with `node:http2`, which is what Node uses when it is not given a
// `fetch`: sessions shared and multiplexed, GOAWAY and dead sessions, timeouts, aborts,
// the fallback to `fetch`, and the way through a proxy

const QUESTION = { name: 'example.com', type: 'A' };
const tls = () => ({ ca: testCertificate().cert });
const wait = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

describe('DNS over HTTPS on HTTP/2', () => {
  let server: Doh2Server | undefined;
  let other: DohServer | undefined;
  let proxy: ProxyMock | undefined;
  let transports: Transports | undefined;

  const make = (options: TransportOptions = {}) =>
    (transports = createTransports({ tls: tls(), ...options }));

  afterEach(async () => {
    transports?.close();
    transports = undefined;
    vi.restoreAllMocks();
    await Promise.all([server?.close(), other?.close(), proxy?.close()]);
    server = other = proxy = undefined;
  });

  it('asks an HTTP/2-only server', async () => {
    server = await startDoh2Server(query => answerTo(query));
    const result = await exchange(QUESTION, server.url, { transports: make() });
    expect(result.transport).toBe('doh');
    expect(result.message.answers).toHaveLength(1);
    const [request] = server.requests;
    expect(request.method).toBe('GET');
    expect(request.url).toMatch(/^\/dns-query\?dns=/);
    expect(request.headers.accept).toBe('application/dns-message');
  });

  it('sends a POST with the query as its body', async () => {
    server = await startDoh2Server(query => answerTo(query));
    const result = await exchange(QUESTION, server.url, {
      transports: make({ dohMethod: 'POST' }),
    });
    const [request] = server.requests;
    expect(request.method).toBe('POST');
    expect(request.url).toBe('/dns-query');
    expect(request.headers['content-type']).toBe('application/dns-message');
    // Cloudflare refuses a POST without one
    expect(request.headers['content-length']).toBe(String(result.query.bytes.length));
    expect(request.query).toEqual(result.query.bytes);
  });

  it('runs concurrent queries side by side on one session', async () => {
    server = await startDoh2Server(query => answerTo(query), { delay: 30 });
    make();
    const names = Array.from({ length: 20 }, (_, i) => `n${i}.example.com`);
    const results = await Promise.all(
      names.map(name => exchange({ name, type: 'A' }, server!.url, { transports }))
    );
    expect(results.every(result => result.message.answers.length === 1)).toBe(true);
    expect(server.sessions).toBe(1);
    expect(server.maxConcurrent).toBe(20);

    // and the next query reuses it
    await exchange(QUESTION, server.url, { transports });
    expect(server.sessions).toBe(1);
  });

  it('closes a session left idle for the idle timeout', async () => {
    server = await startDoh2Server(query => answerTo(query));
    await exchange(QUESTION, server.url, { transports: make({ idleTimeout: 40 }) });
    expect(server.openSessions).toBe(1);
    await wait(150);
    expect(server.openSessions).toBe(0);
    // a new one is opened for the next query
    await exchange(QUESTION, server.url, { transports });
    expect(server.sessions).toBe(2);
  });

  it('closes each session when its queries are answered with an idle timeout of 0', async () => {
    server = await startDoh2Server(query => answerTo(query));
    make({ idleTimeout: 0 });
    await exchange(QUESTION, server.url, { transports });
    await exchange(QUESTION, server.url, { transports });
    expect(server.sessions).toBe(2);
    await wait(50);
    expect(server.openSessions).toBe(0);
  });

  it('opens a new session after the server sends the old one away', async () => {
    server = await startDoh2Server(query => answerTo(query), { goawayAfterAnswer: true });
    make();
    await exchange(QUESTION, server.url, { transports });
    await wait(20);
    const result = await exchange(QUESTION, server.url, { transports, retries: 0 });
    expect(result.message.answers).toHaveLength(1);
    expect(result.attempts).toBe(1);
    expect(server.sessions).toBe(2);
  });

  it('sends a query the server refused once more on a fresh session', async () => {
    server = await startDoh2Server(query => answerTo(query), {
      misbehave: index => (index === 0 ? 'refuse' : undefined),
    });
    const result = await exchange(QUESTION, server.url, { transports: make(), retries: 0 });
    expect(result.message.answers).toHaveLength(1);
    // the second send was inside the one attempt
    expect(result.attempts).toBe(1);
    expect(server.requests).toHaveLength(2);
    expect(server.sessions).toBe(2);
  });

  it('sends a query once more when its session dies under it', async () => {
    server = await startDoh2Server(query => answerTo(query), {
      misbehave: index => (index === 0 ? 'destroy' : undefined),
    });
    const result = await exchange(QUESTION, server.url, { transports: make(), retries: 0 });
    expect(result.message.answers).toHaveLength(1);
    expect(server.requests).toHaveLength(2);
    expect(server.sessions).toBe(2);
  });

  it('gives up after the second dead session, as a connection error', async () => {
    server = await startDoh2Server(query => answerTo(query), { misbehave: () => 'destroy' });
    const error = await exchange(QUESTION, server.url, { transports: make(), retries: 0 }).catch(
      caught => caught
    );
    expect(error).toBeInstanceOf(ConnectionError);
    expect(error.retryable).toBe(true);
    expect(server.requests).toHaveLength(2);
  });

  it('reports an HTTP error status as it does over fetch', async () => {
    // a server that is not this one at all: nothing listens on a closed port
    other = await startDohServer(query => answerTo(query));
    const port = other.port;
    await other.close();
    other = undefined;
    const error = await exchange(QUESTION, `https://127.0.0.1:${port}/dns-query`, {
      transports: make(),
      retries: 0,
    }).catch(caught => caught);
    expect(error).toBeInstanceOf(ConnectionError);
    expect(error.message).toContain('DoH request to 127.0.0.1 failed');
  });

  it('times out, and cancels the stream', async () => {
    server = await startDoh2Server(() => undefined);
    const error = await exchange(QUESTION, server.url, {
      transports: make(),
      timeout: 80,
      retries: 0,
    }).catch(caught => caught);
    expect(error).toBeInstanceOf(TimeoutError);
    await wait(30);
    expect(server.cancelled).toBe(1);
    // the session outlives the query, for the next one
    expect(server.openSessions).toBe(1);
  });

  it('stops when the signal aborts', async () => {
    server = await startDoh2Server(() => undefined);
    const controller = new AbortController();
    const reason = new Error('stop');
    setTimeout(() => controller.abort(reason), 50);
    const error = await make()
      .get('doh')
      .send({
        endpoint: { host: '127.0.0.1', port: server.port, url: server.url },
        query: encodeQuery({ id: 0, name: 'example.com', type: 'A' }),
        signal: controller.signal,
      })
      .catch(caught => caught);
    expect(error).toBe(reason);
    await wait(30);
    expect(server.cancelled).toBe(1);
  });

  it('closes its sessions when the transports close', async () => {
    server = await startDoh2Server(query => answerTo(query));
    await exchange(QUESTION, server.url, { transports: make() });
    transports!.close();
    await wait(30);
    expect(server.openSessions).toBe(0);
  });

  it('uses the fetch it is given instead', async () => {
    server = await startDoh2Server(query => answerTo(query));
    const calls: string[] = [];
    const custom: FetchLike = async (url, init) => {
      calls.push(`${init.method} ${url}`);
      const query = Buffer.from(new URL(url).searchParams.get('dns')!, 'base64url');
      return new Response(Buffer.from(answerTo(Uint8Array.from(query))!), {
        headers: { 'content-type': 'application/dns-message' },
      });
    };
    const result = await exchange(QUESTION, server.url, { transports: make({ fetch: custom }) });
    expect(result.message.answers).toHaveLength(1);
    expect(calls).toHaveLength(1);
    expect(server.requests).toHaveLength(0);
  });

  it('hands a server that does not offer HTTP/2 to fetch', async () => {
    // HTTPS on HTTP/1.1 only
    other = await startDohServer(query => answerTo(query), { secure: true });
    const seen: string[] = [];
    // the runtime's fetch, which cannot be told to trust the test certificate
    vi.spyOn(globalThis, 'fetch').mockImplementation(async input => {
      seen.push(String(input));
      const query = Buffer.from(new URL(String(input)).searchParams.get('dns')!, 'base64url');
      return new Response(Buffer.from(answerTo(Uint8Array.from(query))!), {
        headers: { 'content-type': 'application/dns-message' },
      });
    });
    make();
    await exchange(QUESTION, other.url, { transports });
    await exchange(QUESTION, other.url, { transports });
    expect(seen).toHaveLength(2);
    // the TLS handshake that found out, and no more: the answer is remembered
    expect(other.connections).toBeLessThanOrEqual(1);
    expect(other.requests).toHaveLength(0);
  });

  describe.each(['socks5', 'http'] as const)('through a %s proxy', kind => {
    it('carries the session through the tunnel', async () => {
      server = await startDoh2Server(query => answerTo(query));
      proxy = kind === 'socks5' ? await startSocks5Mock() : await startHttpConnectMock();
      const events: DnsEvent[] = [];
      make({ proxy: `${kind}://127.0.0.1:${proxy.port}` });
      const ask = (name: string) =>
        exchange({ name, type: 'A' }, server!.url, {
          transports,
          onEvent: event => events.push(event),
        });
      const results = await Promise.all(['a.example', 'b.example', 'c.example'].map(ask));
      expect(results.every(result => result.message.answers.length === 1)).toBe(true);
      // one tunnel, one session, three streams
      expect(proxy.requests).toEqual([
        expect.objectContaining({ command: 'connect', host: '127.0.0.1', port: server.port }),
      ]);
      expect(server.sessions).toBe(1);
      expect(server.requests).toHaveLength(3);
      expect(events.filter(event => event.event === 'proxy')).toHaveLength(1);
    });

    it('refuses a server that does not offer HTTP/2, rather than go around', async () => {
      other = await startDohServer(query => answerTo(query), { secure: true });
      proxy = kind === 'socks5' ? await startSocks5Mock() : await startHttpConnectMock();
      const fetchSpy = vi.spyOn(globalThis, 'fetch');
      const error = await exchange(QUESTION, other.url, {
        transports: make({ proxy: `${kind}://127.0.0.1:${proxy.port}` }),
        retries: 0,
      }).catch(caught => caught);
      expect(error).toBeInstanceOf(DnsError);
      expect(error.retryable).toBe(false);
      expect(error.message).toContain('does not speak HTTP/2');
      expect(error.message).toContain('pass a `fetch`');
      expect(fetchSpy).not.toHaveBeenCalled();
      expect(other.requests).toHaveLength(0);
    });
  });
});
