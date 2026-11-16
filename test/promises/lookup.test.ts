import http from 'node:http';
import net from 'node:net';
import type { AddressInfo } from 'node:net';
import { promisify } from 'node:util';
import { Agent, fetch } from 'undici';
import { vi } from 'vitest';
import { ALL, Resolver, V4MAPPED } from '../../src/promises/index';
import type { LookupAddress } from '../../src/promises/index';
import { parseHosts } from '../../src/transports/host';
import { startFixtureServer } from '../support/fixture-server';
import type { FixtureServer } from '../support/fixture-server';
import { ZONE, zoneResponder } from '../support/zone';

// the hosts file these tests read: these names, and nothing else, so the machine's own
// file does not change what `localhost` gives
const HOSTS = vi.hoisted(
  () =>
    new Map([
      [
        'dual.hosts.test',
        [
          { address: '192.0.2.5', family: 4 },
          { address: '2001:db8::5', family: 6 },
        ],
      ],
      ['v4.hosts.test', [{ address: '192.0.2.6', family: 4 }]],
    ])
);
vi.mock('../../src/transports/host', async importOriginal => ({
  ...(await importOriginal<typeof import('../../src/transports/host')>()),
  hostsEntries: (name: string) => HOSTS.get(name.toLowerCase()) ?? [],
}));

// `lookup` and `connectLookup` against the fixture server, and the callback form doing
// its job for net.connect, http.Agent and undici: `app.example.test` resolves to
// 127.0.0.1, where a local server is listening

let dnsServer: FixtureServer;
let resolver: Resolver;

beforeAll(async () => {
  dnsServer = await startFixtureServer(zoneResponder);
  resolver = new Resolver({ timeout: 300, tries: 1, cache: false });
  resolver.setServers([`${dnsServer.address}:${dnsServer.port}`]);
});

afterAll(async () => {
  resolver.close();
  await dnsServer.close();
});

const codeOf = (promise: Promise<unknown>) =>
  promise.then(
    () => undefined,
    (error: { code: string; syscall: string; errno: number; message: string }) => error
  );

describe('lookup', () => {
  it('returns the first address, or all with all: true', async () => {
    expect(await resolver.lookup(`www.${ZONE}`)).toEqual({ address: '192.0.2.1', family: 4 });
    expect(await resolver.lookup(`www.${ZONE}`, { all: true })).toEqual([
      { address: '192.0.2.1', family: 4 },
      { address: '192.0.2.2', family: 4 },
      { address: '2001:db8::1', family: 6 },
    ]);
  });

  it('orders by family when asked', async () => {
    const all = await resolver.lookup(`www.${ZONE}`, { all: true, order: 'ipv6first' });
    expect(all.map(entry => entry.family)).toEqual([6, 4, 4]);
    const verbatimOff = await resolver.lookup(`www.${ZONE}`, { all: true, verbatim: false });
    expect(verbatimOff.map(entry => entry.family)).toEqual([4, 4, 6]);
  });

  it('asks only for the family given', async () => {
    expect(await resolver.lookup(`www.${ZONE}`, 6)).toEqual({ address: '2001:db8::1', family: 6 });
    expect(await resolver.lookup(`www.${ZONE}`, { family: 'IPv4', all: true })).toHaveLength(2);
    expect(await resolver.lookup(`v6only.${ZONE}`)).toEqual({ address: '2001:db8::6', family: 6 });
  });

  it('maps IPv4 into IPv6 with V4MAPPED', async () => {
    expect(await resolver.lookup(`v4only.${ZONE}`, { family: 6, hints: V4MAPPED })).toEqual({
      address: '::ffff:192.0.2.4',
      family: 6,
    });
    expect(
      await resolver.lookup(`www.${ZONE}`, { family: 6, hints: V4MAPPED | ALL, all: true })
    ).toEqual([
      { address: '2001:db8::1', family: 6 },
      { address: '::ffff:192.0.2.1', family: 6 },
      { address: '::ffff:192.0.2.2', family: 6 },
    ]);
  });

  it('returns an IP address as it is, as node:dns does', async () => {
    expect(await resolver.lookup('192.0.2.7')).toEqual({ address: '192.0.2.7', family: 4 });
    expect(await resolver.lookup('2001:db8::7', { all: true })).toEqual([
      { address: '2001:db8::7', family: 6 },
    ]);
  });

  it('answers localhost without asking', async () => {
    const before = dnsServer.received.length;
    const all = (await resolver.lookup('localhost', { all: true })) as LookupAddress[];
    expect(all.map(entry => entry.address).sort()).toEqual(['127.0.0.1', '::1']);
    expect(await resolver.lookup('api.localhost', 4)).toEqual({ address: '127.0.0.1', family: 4 });
    expect(dnsServer.received.length).toBe(before);
  });

  // getaddrinfo with AI_V4MAPPED | AI_ALL, as glibc has it: the IPv6 addresses, then the
  // IPv4 ones mapped. macOS ignores AI_ALL, so this is checked against glibc's rule and
  // the DNS branch, not against the machine running the tests
  it('maps IPv4 for family 6 with V4MAPPED and ALL, from the hosts file and for localhost', async () => {
    const before = dnsServer.received.length;
    const options = { family: 6, hints: V4MAPPED | ALL, all: true } as const;
    expect(await resolver.lookup('dual.hosts.test', options)).toEqual([
      { address: '2001:db8::5', family: 6 },
      { address: '::ffff:192.0.2.5', family: 6 },
    ]);
    expect(await resolver.lookup('localhost', options)).toEqual([
      { address: '::1', family: 6 },
      { address: '::ffff:127.0.0.1', family: 6 },
    ]);
    expect(await resolver.lookup('v4.hosts.test', options)).toEqual([
      { address: '::ffff:192.0.2.6', family: 6 },
    ]);
    // V4MAPPED alone maps IPv4 only when there is no IPv6
    expect(
      await resolver.lookup('dual.hosts.test', { family: 6, hints: V4MAPPED, all: true })
    ).toEqual([{ address: '2001:db8::5', family: 6 }]);
    expect(await resolver.lookup('v4.hosts.test', { family: 6, hints: V4MAPPED })).toEqual({
      address: '::ffff:192.0.2.6',
      family: 6,
    });
    expect(dnsServer.received.length).toBe(before);
  });

  it('fails as getaddrinfo does: ENOTFOUND, or EAI_AGAIN when no server could say', async () => {
    expect(await codeOf(resolver.lookup(`nx.${ZONE}`))).toMatchObject({
      code: 'ENOTFOUND',
      errno: -3008,
      syscall: 'getaddrinfo',
      hostname: `nx.${ZONE}`,
      message: `getaddrinfo ENOTFOUND nx.${ZONE}`,
    });
    // the name exists, with no address of the family asked for
    expect(await codeOf(resolver.lookup(`v4only.${ZONE}`, 6))).toMatchObject({ code: 'ENOTFOUND' });
    expect(await codeOf(resolver.lookup(`servfail.${ZONE}`))).toMatchObject({
      code: 'EAI_AGAIN',
      errno: -3001,
      message: `getaddrinfo EAI_AGAIN servfail.${ZONE}`,
    });
  });

  it('throws on bad arguments before asking, as node:dns does', async () => {
    const nodeDns = await import('node:dns/promises');
    const bad: [unknown, unknown][] = [
      [`www.${ZONE}`, { family: 5 }],
      [`www.${ZONE}`, { hints: 1 }],
      [42, undefined],
    ];
    for (const [hostname, options] of bad) {
      const thrown = (run: () => unknown) => {
        try {
          void run();
        } catch (error) {
          return (error as { code: string }).code;
        }
      };
      const lookupOf = (target: unknown) =>
        (target as { lookup: (...args: unknown[]) => unknown }).lookup;
      const theirs = thrown(() => lookupOf(nodeDns)(hostname, options));
      expect(theirs).toBeDefined();
      expect(thrown(() => lookupOf(resolver).call(resolver, hostname, options))).toBe(theirs);
    }
  });
});

describe('connectLookup', () => {
  it('calls back with an address and family, or with every address', async () => {
    const one = await new Promise<unknown[]>(resolve =>
      resolver.connectLookup(`www.${ZONE}`, { family: 4 }, (...args) => resolve(args))
    );
    expect(one).toEqual([null, '192.0.2.1', 4]);
    const all = await new Promise<unknown[]>(resolve =>
      resolver.connectLookup(`www.${ZONE}`, { all: true }, (...args) => resolve(args))
    );
    expect(all[1]).toHaveLength(3);
    const short = await new Promise<unknown[]>(resolve =>
      resolver.connectLookup(`www.${ZONE}`, (...args) => resolve(args))
    );
    expect(short).toEqual([null, '192.0.2.1', 4]);
  });

  it('calls back with the error alone', async () => {
    const args = await new Promise<unknown[]>(resolve =>
      resolver.connectLookup(`nx.${ZONE}`, {}, (...given) => resolve(given))
    );
    expect(args).toHaveLength(1);
    expect(args[0]).toMatchObject({ code: 'ENOTFOUND' });
  });

  it('works with promisify', async () => {
    const lookup = promisify(resolver.connectLookup) as (
      hostname: string,
      options: object
    ) => Promise<string>;
    expect(await lookup(`www.${ZONE}`, { family: 4 })).toBe('192.0.2.1');
  });
});

describe('end to end', () => {
  let tcp: net.Server;
  let web: http.Server;

  beforeAll(async () => {
    tcp = net.createServer(socket => socket.end('hello from tcp'));
    web = http.createServer((_, response) => response.end('hello from http'));
    await Promise.all([
      new Promise<void>(resolve => tcp.listen(0, '127.0.0.1', resolve)),
      new Promise<void>(resolve => web.listen(0, '127.0.0.1', resolve)),
    ]);
  });

  afterAll(async () => {
    await Promise.all([
      new Promise<void>(resolve => tcp.close(() => resolve())),
      new Promise<void>(resolve => web.close(() => resolve())),
    ]);
  });

  const read = (socket: net.Socket) =>
    new Promise<string>((resolve, reject) => {
      let text = '';
      socket.on('data', chunk => (text += String(chunk)));
      socket.on('end', () => resolve(text));
      socket.on('error', reject);
    });

  it.each([true, false])('net.connect, autoSelectFamily %s', async autoSelectFamily => {
    const socket = net.connect({
      host: `app.${ZONE}`,
      port: (tcp.address() as AddressInfo).port,
      lookup: resolver.connectLookup,
      autoSelectFamily,
    });
    expect(await read(socket)).toBe('hello from tcp');
    expect(socket.remoteAddress).toBe('127.0.0.1');
  });

  it('net.connect reports a name that does not exist', async () => {
    const socket = net.connect({
      host: `nx.${ZONE}`,
      port: (tcp.address() as AddressInfo).port,
      lookup: resolver.connectLookup,
    });
    await expect(read(socket)).rejects.toMatchObject({ code: 'ENOTFOUND', hostname: `nx.${ZONE}` });
  });

  it('http.Agent', async () => {
    const agent = new http.Agent({ lookup: resolver.connectLookup } as http.AgentOptions);
    const body = await new Promise<string>((resolve, reject) => {
      http
        .get(
          { host: `app.${ZONE}`, port: (web.address() as AddressInfo).port, agent },
          response => {
            let text = '';
            response.on('data', chunk => (text += String(chunk)));
            response.on('end', () => resolve(text));
          }
        )
        .on('error', reject);
    });
    agent.destroy();
    expect(body).toBe('hello from http');
  });

  it('undici', async () => {
    const dispatcher = new Agent({ connect: { lookup: resolver.connectLookup } });
    const response = await fetch(`http://app.${ZONE}:${(web.address() as AddressInfo).port}/`, {
      dispatcher,
    });
    expect(await response.text()).toBe('hello from http');
    await dispatcher.close();
  });
});

describe('the hosts file', () => {
  it('reads names, both families, comments and repeats', () => {
    const table = parseHosts(
      [
        '# a comment',
        '127.0.0.1   localhost loopback.test',
        '::1         localhost # trailing comment',
        '192.0.2.5   Mixed.Case.test',
        '192.0.2.5   mixed.case.test',
        'not-an-address  ignored.test',
        '',
      ].join('\n')
    );
    expect(table.get('localhost')).toEqual([
      { address: '127.0.0.1', family: 4 },
      { address: '::1', family: 6 },
    ]);
    expect(table.get('loopback.test')).toEqual([{ address: '127.0.0.1', family: 4 }]);
    expect(table.get('mixed.case.test')).toEqual([{ address: '192.0.2.5', family: 4 }]);
    expect(table.has('ignored.test')).toBe(false);
  });
});
