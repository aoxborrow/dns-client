import net from 'node:net';
import { ConnectionError, DnsError, NoServerError, ProxyError, TimeoutError } from '../src/errors';
import { exchange } from '../src/exchange';
import type { ExchangeOptions, ExchangeResult } from '../src/exchange';
import { createNodeConnect, createTransports } from '../src/transports/index';
import type { Transports } from '../src/transports/index';
import { parseProxy, scrub } from '../src/transports/proxy';
import type { DnsEvent, TransportName } from '../src/transports/types';
import { encodeQuery } from '../src/wire/index';
import { answerTo } from './support/answers';
import { startFixtureServer } from './support/fixture-server';
import type { FixtureServer } from './support/fixture-server';
import { startHttpConnectMock, startSocks5Mock } from './support/proxy-mocks';
import type { ProxyMock } from './support/proxy-mocks';
import { startDohServer, startDotServer, testCertificate } from './support/secure-servers';
import type { DohServer, DotServer } from './support/secure-servers';

// every transport through both kinds of proxy, and everything that can go wrong with
// one. The proxies and servers are all in this process

const QUESTION = { name: 'example.com', type: 'A' };

// awkward on purpose: characters that need escaping in a URL, and text that would be
// easy to spot if it leaked
const USERNAME = 'proxy-user-7f3a';
const PASSWORD = 'p@ss:w0rd/7f3a secret';
const CREDENTIALS = { username: USERNAME, password: PASSWORD };
const BASIC = Buffer.from(`${USERNAME}:${PASSWORD}`).toString('base64');

type Kind = 'socks5' | 'http';

function proxyUrl(kind: Kind, proxy: { port: number }, withCredentials = false): string {
  const userinfo = withCredentials
    ? `${encodeURIComponent(USERNAME)}:${encodeURIComponent(PASSWORD)}@`
    : '';
  return `${kind}://${userinfo}127.0.0.1:${proxy.port}`;
}

// everything an error says about itself, down its chain of causes
function errorText(error: unknown): string {
  const parts: string[] = [];
  for (let current = error; current instanceof Error; current = current.cause) {
    parts.push(current.name, current.message, current.stack ?? '', JSON.stringify(current));
  }
  return parts.join('\n');
}

function expectNoCredentials(text: string): void {
  for (const secret of [USERNAME, PASSWORD, encodeURIComponent(PASSWORD), BASIC]) {
    expect(text).not.toContain(secret);
  }
}

describe('proxies', () => {
  let dns: FixtureServer;
  let dot: DotServer;
  let doh: DohServer;
  let proxy: ProxyMock;
  let transports: Transports | undefined;
  let events: DnsEvent[];

  beforeAll(async () => {
    dns = await startFixtureServer(({ query }) => ({ response: answerTo(query) }));
    dot = await startDotServer(query => answerTo(query));
    doh = await startDohServer(query => answerTo(query));
  });

  afterAll(async () => {
    await Promise.all([dns.close(), dot.close(), doh.close()]);
  });

  beforeEach(() => {
    events = [];
    dns.received.length = 0;
    dot.received.length = 0;
    doh.requests.length = 0;
  });

  afterEach(async () => {
    transports?.close();
    transports = undefined;
    await proxy?.close();
  });

  async function startProxy(
    kind: Kind,
    options: { auth?: boolean; udpAssociate?: boolean; refuseWith?: number } = {}
  ): Promise<ProxyMock> {
    const auth = options.auth ? CREDENTIALS : undefined;
    proxy =
      kind === 'socks5'
        ? await startSocks5Mock({
            auth,
            udpAssociate: options.udpAssociate,
            refuseWith: options.refuseWith,
          })
        : await startHttpConnectMock({ auth, refuseWith: options.refuseWith });
    return proxy;
  }

  // ask the question over one transport, through whatever `proxy` option is given
  function ask(transport: TransportName, options: ExchangeOptions): Promise<ExchangeResult> {
    transports = createTransports({
      proxy: options.proxy,
      connect: options.connect,
      fetch: options.fetch,
      pipeline: options.pipeline,
      tls: { ca: testCertificate().cert },
    });
    const common: ExchangeOptions = {
      transport,
      transports,
      timeout: 2000,
      retries: 0,
      onEvent: event => events.push(event),
    };
    if (transport === 'doh') return exchange(QUESTION, doh.url, common);
    if (transport === 'tls') return exchange(QUESTION, dot.address, { ...common, port: dot.port });
    return exchange(QUESTION, dns.address, { ...common, port: dns.port });
  }

  // where each transport's queries end up
  const target = (transport: TransportName) =>
    transport === 'doh' ? doh.port : transport === 'tls' ? dot.port : dns.port;

  describe.each(['socks5', 'http'] as const)('through a %s proxy', kind => {
    describe.each([false, true])('with credentials: %s', auth => {
      it.each(['tcp', 'tls'] as const)('carries %s', async transport => {
        await startProxy(kind, { auth });
        const result = await ask(transport, { proxy: proxyUrl(kind, proxy, auth) });

        expect(result.transport).toBe(transport);
        expect(result.message.answers).toHaveLength(1);
        expect(proxy.requests).toEqual([
          {
            command: 'connect',
            host: '127.0.0.1',
            port: target(transport),
            ...(auth ? CREDENTIALS : { username: undefined, password: undefined }),
          },
        ]);

        const tunnel = events.find(event => event.event === 'proxy');
        expect(tunnel).toMatchObject({
          proxy: `${kind}://127.0.0.1:${proxy.port}`,
          command: 'connect',
          target: `127.0.0.1:${target(transport)}`,
        });
        expect(tunnel).not.toHaveProperty('error');
        expectNoCredentials(JSON.stringify(events));
      });
    });

    it('reuses the tunnel for the next query', async () => {
      await startProxy(kind);
      for (const transport of ['tcp', 'tls'] as const) {
        proxy.requests.length = 0;
        const first = await ask(transport, { proxy: proxyUrl(kind, proxy), pipeline: true });
        const again = await exchange(QUESTION, first.server, {
          transport,
          transports,
          port: first.port,
        });
        expect(again.message.answers).toHaveLength(1);
        // one tunnel, and with it one proxy handshake and one TLS handshake
        expect(proxy.requests).toHaveLength(1);
        transports?.close();
      }
    });

    it('reports a proxy that refuses the connection', async () => {
      await startProxy(kind, { refuseWith: kind === 'socks5' ? 0x02 : 403 });
      for (const transport of ['tcp', 'tls'] as const) {
        const error = await ask(transport, { proxy: proxyUrl(kind, proxy) }).catch(
          caught => caught
        );
        expect(error).toBeInstanceOf(ProxyError);
        expect(error.retryable).toBe(true);
        expect(error.transport).toBe(transport);
        expect(error.message).toContain(`${kind}://127.0.0.1:${proxy.port}`);
        transports?.close();
      }
      expect(dns.received).toHaveLength(0);
      expect(events.filter(event => event.event === 'proxy')).toHaveLength(2);
      expect(events.find(event => event.event === 'proxy')).toMatchObject({
        error: { name: 'ProxyError', retryable: true },
      });
    });

    it('reports credentials the proxy rejects, without repeating them', async () => {
      await startProxy(kind, { auth: true });
      const wrong = proxyUrl(kind, proxy, true).replace('7f3a%20secret', 'wrong');
      for (const transport of ['tcp', 'tls', 'udp'] as const) {
        const error = await ask(transport, { proxy: wrong }).catch(caught => caught);
        expect(error).toBeInstanceOf(ProxyError);
        expect(error.message).toContain('rejected the credentials');
        expectNoCredentials(errorText(error));
        expect(errorText(error)).not.toContain('wrong');
        transports?.close();
      }
      expectNoCredentials(JSON.stringify(events));
      expect(dns.received).toHaveLength(0);
    });

    it('reports a proxy that wants credentials when none were given', async () => {
      await startProxy(kind, { auth: true });
      const error = await ask('tcp', { proxy: proxyUrl(kind, proxy) }).catch(caught => caught);
      expect(error).toBeInstanceOf(ProxyError);
      expect(error.message).toContain('requires authentication');
    });

    it('reports a target the proxy cannot reach as a connection failure', async () => {
      await startProxy(kind);
      // a port nothing is listening on
      const closed = await startFixtureServer(() => undefined);
      await closed.close();
      transports = createTransports({ proxy: proxyUrl(kind, proxy) });
      const error = await exchange(QUESTION, closed.address, {
        transport: 'tcp',
        port: closed.port,
        transports,
        retries: 0,
        onEvent: event => events.push(event),
      }).catch(caught => caught);
      // the proxy did its job; it is the server that is not there
      expect(error).toBeInstanceOf(ConnectionError);
      expect(error.message).toContain(`127.0.0.1:${closed.port}`);
      expect(error.message).toContain(`${kind}://127.0.0.1:${proxy.port}`);
    });

    it('sends nothing directly when the proxy cannot be reached', async () => {
      // a proxy address nothing is listening on
      await startProxy(kind);
      const dead = proxyUrl(kind, proxy, true);
      await proxy.close();

      for (const transport of ['udp', 'tcp', 'tls'] as const) {
        const error = await ask(transport, { proxy: dead }).catch(caught => caught);
        expect(error).toBeInstanceOf(ProxyError);
        expect(error.message).toContain('Cannot reach proxy');
        expectNoCredentials(errorText(error));
        transports?.close();
      }
      // the queries failed; they did not quietly go around the proxy
      expect(dns.received).toHaveLength(0);
      expect(dot.received).toHaveLength(0);
      expect(doh.requests).toHaveLength(0);
      expectNoCredentials(JSON.stringify(events));
    });
  });

  describe('SOCKS5 authentication', () => {
    it('does not let a proxy skip the credentials it was given', async () => {
      // a proxy that says "no authentication" though only username/password was offered
      proxy = await startSocks5Mock({ auth: CREDENTIALS, chooseMethod: 0x00 });
      for (const transport of ['tcp', 'udp'] as const) {
        const error = await ask(transport, { proxy: proxyUrl('socks5', proxy, true) }).catch(
          caught => caught
        );
        expect(error).toBeInstanceOf(ProxyError);
        expect(error.message).toContain('chose an authentication method not offered');
        transports?.close();
      }
      // no request got as far as the proxy, and nothing reached the server
      expect(proxy.requests).toHaveLength(0);
      expect(dns.received).toHaveLength(0);
    });

    it('does not use a proxy that wants no credentials when some were given', async () => {
      proxy = await startSocks5Mock();
      const error = await ask('tcp', { proxy: proxyUrl('socks5', proxy, true) }).catch(
        caught => caught
      );
      expect(error).toBeInstanceOf(ProxyError);
      expect(error.message).toContain('accepts none of the offered authentication methods');
      expect(dns.received).toHaveLength(0);
    });
  });

  describe('DoH', () => {
    it('refuses to go around a proxy it cannot use', async () => {
      await startProxy('socks5', { auth: true });
      const error = await ask('doh', { proxy: proxyUrl('socks5', proxy, true) }).catch(
        caught => caught
      );
      // not a failure that may pass: the caller has to supply a fetch
      expect(error).toBeInstanceOf(DnsError);
      expect(error.retryable).toBe(false);
      expect(error.message).toContain('pass a `fetch`');
      expect(error.message).toContain(`socks5://127.0.0.1:${proxy.port}`);
      expectNoCredentials(errorText(error));
      expect(doh.requests).toHaveLength(0);
      expect(proxy.requests).toHaveLength(0);
    });
  });

  describe('a hostile server name', () => {
    // an endpoint handed straight to a transport skips the parsing of servers, so the
    // handshake has to refuse it on its own
    it('cannot inject headers or a second request into an HTTP CONNECT', async () => {
      await startProxy('http');
      transports = createTransports({ proxy: proxyUrl('http', proxy) });
      const hosts = [
        '127.0.0.1\r\nProxy-Authorization: Basic aW5qZWN0ZWQ=',
        `127.0.0.1:${dns.port} HTTP/1.1\r\n\r\nCONNECT 10.0.0.1:25`,
        'evil.example\nX-Injected: 1',
      ];
      for (const host of hosts) {
        for (const transport of ['tcp', 'tls', 'udp'] as const) {
          const error = await transports
            .get(transport)
            .send({
              endpoint: { host, port: dns.port },
              query: encodeQuery({ id: 1, name: 'example.com', type: 'A' }),
            })
            .catch(caught => caught);
          expect(error, host).toBeInstanceOf(NoServerError);
        }
      }
      // the proxy never saw a request line, let alone a second one
      expect(proxy.requests).toHaveLength(0);
      expect(dns.received).toHaveLength(0);
    });

    it('is refused by exchange before anything is sent', async () => {
      await startProxy('http');
      const error = await ask('tcp', { proxy: proxyUrl('http', proxy) }).then(() =>
        exchange(
          QUESTION,
          { address: 'evil.example\r\nX-Injected: 1', port: dns.port },
          {
            transport: 'tcp',
            transports,
          }
        ).catch(caught => caught)
      );
      expect(error).toBeInstanceOf(NoServerError);
      expect(proxy.requests).toHaveLength(1);
    });
  });

  describe('UDP', () => {
    it('goes through a SOCKS5 UDP association', async () => {
      await startProxy('socks5', { auth: true, udpAssociate: true });
      const result = await ask('udp', { proxy: proxyUrl('socks5', proxy, true) });

      expect(result.transport).toBe('udp');
      expect(result.message.answers).toHaveLength(1);
      expect(dns.received.map(({ transport }) => transport)).toEqual(['udp']);
      expect(proxy.requests).toEqual([
        { command: 'udp-associate', host: '0.0.0.0', port: 0, ...CREDENTIALS },
      ]);
      expect(events.find(event => event.event === 'proxy')).toMatchObject({
        command: 'udp-associate',
        proxy: `socks5://127.0.0.1:${proxy.port}`,
      });
      expectNoCredentials(JSON.stringify(events));
    });

    it('shares one association between queries', async () => {
      await startProxy('socks5', { udpAssociate: true });
      await ask('udp', { proxy: proxyUrl('socks5', proxy) });
      const results = await Promise.all(
        Array.from({ length: 10 }, (_, index) =>
          exchange({ name: `host${index}.example.com`, type: 'A' }, dns.address, {
            port: dns.port,
            transports,
          })
        )
      );
      results.forEach((result, index) => {
        expect(result.transport).toBe('udp');
        expect(result.message.questions[0].name).toBe(`host${index}.example.com`);
      });
      expect(proxy.requests).toHaveLength(1);
    });

    it('drops the association when the proxy ends it', async () => {
      await startProxy('socks5', { udpAssociate: true });
      await ask('udp', { proxy: proxyUrl('socks5', proxy) });
      await proxy.close();
      await new Promise(resolve => setTimeout(resolve, 20));
      // the next query asks the proxy again, and reports that it is gone: it does not
      // wait on an association that no longer exists
      const error = await exchange(QUESTION, dns.address, {
        port: dns.port,
        transports,
        retries: 0,
      }).catch(caught => caught);
      expect(error).toBeInstanceOf(ProxyError);
      expect(error.message).toContain('Cannot reach proxy');
    });

    it('falls back to TCP when a SOCKS5 proxy does not do UDP', async () => {
      await startProxy('socks5', { udpAssociate: false });
      const result = await ask('udp', { proxy: proxyUrl('socks5', proxy) });

      // the answer says which transport it really came over
      expect(result.transport).toBe('tcp');
      expect(dns.received.map(({ transport }) => transport)).toEqual(['tcp']);
      expect(proxy.requests.map(({ command }) => command)).toEqual(['connect']);
      expect(events.find(event => event.event === 'tcp-fallback')).toMatchObject({
        reason: 'proxy',
      });
      expect(events.find(event => event.event === 'query')).toMatchObject({ transport: 'tcp' });

      // and the proxy is not asked for UDP a second time
      await exchange(QUESTION, dns.address, { port: dns.port, transports });
      expect(proxy.requests.map(({ command }) => command)).toEqual(['connect', 'connect']);
    });

    it('always goes over TCP through an HTTP proxy, which cannot carry UDP', async () => {
      await startProxy('http');
      const result = await ask('udp', { proxy: proxyUrl('http', proxy) });
      expect(result.transport).toBe('tcp');
      expect(dns.received.map(({ transport }) => transport)).toEqual(['tcp']);
      expect(result.toDig()).toContain('+tcp');
    });

    describe('through a proxy that never answers the handshake', () => {
      let silent: net.Server;
      let connections: net.Socket[];
      let silentUrl: string;

      beforeEach(async () => {
        connections = [];
        silent = net.createServer(socket => {
          connections.push(socket);
          socket.on('error', () => undefined);
          // read and ignore whatever comes, so a close from the other end is noticed
          socket.resume();
        });
        await new Promise<void>(resolve => silent.listen(0, '127.0.0.1', resolve));
        silentUrl = `socks5://127.0.0.1:${(silent.address() as net.AddressInfo).port}`;
      });

      afterEach(async () => {
        for (const socket of connections) socket.destroy();
        await new Promise(resolve => silent.close(resolve));
      });

      const closed = (socket: net.Socket) =>
        new Promise<boolean>(resolve => {
          if (socket.destroyed || socket.readableEnded) resolve(true);
          else socket.once('close', () => resolve(true));
          setTimeout(() => resolve(false), 500);
        });

      it('times out, and drops the half-made association', async () => {
        transports = createTransports({ proxy: silentUrl });
        const options = { port: dns.port, transports, retries: 0 };
        const started = Date.now();
        const error = await exchange(QUESTION, dns.address, { ...options, timeout: 50 }).catch(
          caught => caught
        );
        expect(error).toBeInstanceOf(TimeoutError);
        expect(Date.now() - started).toBeLessThan(1000);
        expect(connections).toHaveLength(1);
        expect(await closed(connections[0])).toBe(true);

        // the next query does not wait on the one given up on: it tries afresh
        await exchange(QUESTION, dns.address, { ...options, timeout: 50 }).catch(() => undefined);
        expect(connections).toHaveLength(2);
      });

      it('keeps setting up for a caller still waiting when another gives up', async () => {
        transports = createTransports({ proxy: silentUrl });
        const first = new AbortController();
        const second = new AbortController();
        const ask = (signal: AbortSignal) =>
          exchange(QUESTION, dns.address, {
            port: dns.port,
            transports,
            retries: 0,
            timeout: 5000,
            signal,
          }).catch(caught => caught);
        const firstResult = ask(first.signal);
        const secondResult = ask(second.signal);
        await new Promise(resolve => setTimeout(resolve, 50));
        // both queries wait on the one association
        expect(connections).toHaveLength(1);

        first.abort(new Error('first gave up'));
        expect((await firstResult).message).toBe('first gave up');
        expect(await closed(connections[0])).toBe(false);

        second.abort(new Error('second gave up'));
        expect((await secondResult).message).toBe('second gave up');
        expect(await closed(connections[0])).toBe(true);
      });
    });
  });

  describe('choosing a proxy', () => {
    it('asks a function which proxy to use for each target', async () => {
      await startProxy('socks5');
      const asked: unknown[] = [];
      const result = await ask('tcp', {
        proxy: where => {
          asked.push(where);
          return proxyUrl('socks5', proxy);
        },
      });
      expect(result.message.answers).toHaveLength(1);
      expect(asked).toEqual([{ host: '127.0.0.1', port: dns.port, transport: 'tcp' }]);
      expect(proxy.requests).toHaveLength(1);
    });

    it('connects directly when the function names no proxy', async () => {
      await startProxy('socks5');
      for (const transport of ['udp', 'tcp', 'tls', 'doh'] as const) {
        const result = await ask(transport, { proxy: () => undefined });
        expect(result.transport).toBe(transport);
        transports?.close();
      }
      expect(proxy.requests).toHaveLength(0);
    });

    it('lets an explicit connect win over the proxy for TCP', async () => {
      await startProxy('socks5');
      const node = createNodeConnect();
      const opened: string[] = [];
      const result = await ask('tcp', {
        proxy: proxyUrl('socks5', proxy),
        connect: where => {
          opened.push(`${where.hostname}:${where.port}`);
          return node(where);
        },
      });
      expect(result.message.answers).toHaveLength(1);
      expect(opened).toEqual([`127.0.0.1:${dns.port}`]);
      expect(proxy.requests).toHaveLength(0);
    });

    it('lets an explicit fetch win over the proxy for DoH', async () => {
      await startProxy('socks5');
      const plain = await startDohServer(query => answerTo(query));
      const fetched: string[] = [];
      try {
        transports = createTransports({
          proxy: proxyUrl('socks5', proxy),
          fetch: (url, init) => {
            fetched.push(url);
            return fetch(url, init as RequestInit);
          },
        });
        const result = await exchange(QUESTION, plain.url, { transports });
        expect(result.message.answers).toHaveLength(1);
        expect(fetched).toHaveLength(1);
        expect(proxy.requests).toHaveLength(0);

        // and the proxy still applies to what was not overridden
        await exchange(QUESTION, dns.address, { transport: 'tcp', port: dns.port, transports });
        expect(proxy.requests).toHaveLength(1);
      } finally {
        await plain.close();
      }
    });
  });

  describe('proxy URLs', () => {
    it('reads scheme, host, port and credentials', () => {
      expect(parseProxy('socks5://127.0.0.1')).toMatchObject({
        protocol: 'socks5',
        host: '127.0.0.1',
        port: 1080,
        display: 'socks5://127.0.0.1:1080',
      });
      expect(parseProxy('socks5h://proxy.example:9050').protocol).toBe('socks5');
      expect(parseProxy(new URL('http://proxy.example:3128'))).toMatchObject({
        protocol: 'http',
        host: 'proxy.example',
        port: 3128,
      });
      expect(parseProxy('http://[2001:db8::1]:3128').display).toBe('http://[2001:db8::1]:3128');
      const parsed = parseProxy(proxyUrl('socks5', { port: 1080 }, true));
      expect(parsed.username).toBe(USERNAME);
      expect(parsed.password).toBe(PASSWORD);
      expectNoCredentials(parsed.display);
    });

    it('rejects a URL it cannot use, without repeating it', () => {
      const attempt = (url: string) => {
        try {
          parseProxy(url);
        } catch (error) {
          return error as Error;
        }
        throw new Error('expected a failure');
      };
      expect(attempt('socks4://127.0.0.1:1080').message).toContain('Unsupported proxy scheme');
      expect(attempt('https://127.0.0.1:8443')).toBeInstanceOf(DnsError);
      const garbled = attempt(`${USERNAME}:${PASSWORD}@not a url`);
      expect(garbled).toBeInstanceOf(DnsError);
      expectNoCredentials(garbled.message);
    });

    it('scrubs credentials out of text from elsewhere', () => {
      const parsed = parseProxy(proxyUrl('http', { port: 3128 }, true));
      const scrubbed = scrub(
        `connect to ${USERNAME}:${PASSWORD}@127.0.0.1 failed, header was Basic ${BASIC}`,
        parsed
      );
      expectNoCredentials(scrubbed);
      expect(scrubbed).toContain('127.0.0.1');
    });
  });
});
