import * as nodeDns from 'node:dns/promises';
import { promisify } from 'node:util';
import * as facade from '../../src/promises/index';
import { Resolver } from '../../src/promises/index';
import { startFixtureServer } from '../support/fixture-server';
import type { FixtureServer } from '../support/fixture-server';
import { simulateNetwork } from '../support/simulated-network';
import { ZONE, zoneResponder } from '../support/zone';

// the facade against Node's own resolver, both asking the same in-process server: every
// method, every way of failing, the same result or the same error

let server: FixtureServer;
let node: nodeDns.Resolver;
let ours: Resolver;

beforeAll(async () => {
  server = await startFixtureServer(zoneResponder);
  const address = `${server.address}:${server.port}`;
  node = new nodeDns.Resolver({ timeout: 300, tries: 1 });
  node.setServers([address]);
  ours = new Resolver({ timeout: 300, tries: 1, cache: false });
  ours.setServers([address]);
});

afterAll(async () => {
  ours.close();
  await server.close();
});

// the parts of an error a caller looks at
// a thunk, so an argument error thrown before any promise exists is caught too
const errorOf = async (run: () => Promise<unknown>) => {
  try {
    await run();
  } catch (error) {
    const { message, code, errno, syscall, hostname, name } = error as Record<string, unknown>;
    return { message, code, errno, syscall, hostname, name, keys: Object.keys(error as object) };
  }
  throw new Error('expected a rejection');
};

type Method =
  | 'resolve'
  | 'resolve4'
  | 'resolve6'
  | 'resolveAny'
  | 'resolveCaa'
  | 'resolveCname'
  | 'resolveMx'
  | 'resolveNaptr'
  | 'resolveNs'
  | 'resolvePtr'
  | 'resolveSoa'
  | 'resolveSrv'
  | 'resolveTlsa'
  | 'resolveTxt'
  | 'reverse';

const call = (resolver: unknown, method: Method, args: unknown[]) =>
  (resolver as Record<Method, (...args: unknown[]) => Promise<unknown>>)[method](...args);

describe('the same answers as node:dns', () => {
  const cases: [Method, ...unknown[]][] = [
    ['resolve4', `www.${ZONE}`],
    ['resolve4', `www.${ZONE}`, { ttl: true }],
    ['resolve4', `alias.${ZONE}`],
    ['resolve4', `alias.${ZONE}`, { ttl: true }],
    ['resolve4', `WWW.${ZONE.toUpperCase()}`],
    ['resolve6', `www.${ZONE}`],
    ['resolve6', `www.${ZONE}`, { ttl: true }],
    ['resolveAny', ZONE],
    ['resolveCaa', ZONE],
    ['resolveCname', `alias.${ZONE}`],
    ['resolveMx', ZONE],
    ['resolveMx', `nullmx.${ZONE}`],
    ['resolveSrv', `_imap._tcp.${ZONE}`],
    ['resolveNaptr', `naptr.${ZONE}`],
    ['resolveNs', ZONE],
    ['resolvePtr', `ptr.${ZONE}`],
    ['resolveSoa', ZONE],
    ['resolveSrv', `_sip._tcp.${ZONE}`],
    ['resolveTlsa', `_443._tcp.www.${ZONE}`],
    ['resolveTxt', ZONE],
    ['reverse', '192.0.2.1'],
    ['reverse', '2001:db8::1'],
    ['resolve', `www.${ZONE}`],
    ['resolve', `www.${ZONE}`, 'AAAA'],
    ['resolve', ZONE, 'MX'],
    ['resolve', ZONE, 'SOA'],
    ['resolve', ZONE, 'TXT'],
    ['resolve', ZONE, 'NS'],
    ['resolve', `_sip._tcp.${ZONE}`, 'SRV'],
    // records, none of the type asked for: an empty list, not ENODATA
    ['resolve4', `dangling.${ZONE}`],
  ];

  // Node 24 puts `type` on MX, SRV and CAA results, as the facade does; Node 22.14 and
  // earlier do not, so against those the field is left out of the comparison
  const typed = (value: unknown) =>
    Array.isArray(value) && value.some(item => (item as { type?: string }).type !== undefined);
  const untyped = (value: unknown) =>
    Array.isArray(value)
      ? value.map(item => {
          if (typeof item !== 'object' || item === null || Array.isArray(item)) return item;
          const { type: _type, ...rest } = item as Record<string, unknown>;
          return rest;
        })
      : value;

  it.each(cases)('%s(%s)', async (method, ...args) => {
    // resolveTlsa is new in Node 22.15
    if (
      typeof (node as Partial<nodeDns.Resolver>).resolveTlsa !== 'function' &&
      method === 'resolveTlsa'
    )
      return;
    const theirs = await call(node, method, args);
    const mine = await call(ours, method, args);
    expect(method === 'resolveAny' || typed(theirs) ? mine : untyped(mine)).toEqual(theirs);
  });

  it('gives TLSA data as an ArrayBuffer', async () => {
    const [record] = await ours.resolveTlsa(`_443._tcp.www.${ZONE}`);
    expect(record).toMatchObject({ certUsage: 3, selector: 1, match: 1 });
    expect(record.data).toBeInstanceOf(ArrayBuffer);
    expect(Buffer.from(record.data).toString('hex')).toBe('0123456789abcdef'.repeat(4));
  });
});

describe('the same errors as node:dns', () => {
  const cases: [Method, ...unknown[]][] = [
    ['resolve4', `nx.${ZONE}`],
    ['resolve4', 'example.invalid'],
    ['resolveMx', `www.${ZONE}`],
    ['resolveSoa', `www.${ZONE}`],
    ['resolve6', `v4only.${ZONE}`],
    ['resolveAny', `nx.${ZONE}`],
    ['resolveTxt', `servfail.${ZONE}`],
    ['resolve4', `refused.${ZONE}`],
    ['resolve4', `formerr.${ZONE}`],
    ['resolve4', `notimp.${ZONE}`],
    ['resolve4', `garbage.${ZONE}`],
    ['resolve4', `silent.${ZONE}`],
    ['resolve4', 'bad..name'],
    ['resolve4', `${'x'.repeat(64)}.${ZONE}`],
    ['reverse', '192.0.2.99'],
    ['reverse', 'not an address'],
    ['resolve', `www.${ZONE}`, 'BOGUS'],
    ['resolve4', 5],
  ];

  it.each(cases)('%s(%s)', async (method, ...args) => {
    expect(await errorOf(() => call(ours, method, args))).toEqual(
      await errorOf(() => call(node, method, args))
    );
  });

  it('keeps the library error as the cause', async () => {
    const error = (await ours.resolve4(`silent.${ZONE}`).catch(e => e)) as Error;
    expect((error.cause as Error).name).toBe('TimeoutError');
  });

  it('is ECONNREFUSED when nothing listens', async () => {
    const closed = await startFixtureServer(() => undefined);
    const address = `${closed.address}:${closed.port}`;
    await closed.close();
    const refusedNode = new nodeDns.Resolver({ timeout: 300, tries: 1 });
    refusedNode.setServers([address]);
    const refusedOurs = new Resolver({ timeout: 300, tries: 1, transport: 'tcp' });
    refusedOurs.setServers([address]);
    expect(await errorOf(() => refusedOurs.resolve4(`www.${ZONE}`))).toMatchObject({
      code: 'ECONNREFUSED',
      syscall: 'queryA',
      message: `queryA ECONNREFUSED www.${ZONE}`,
    });
    refusedOurs.close();
  });
});

describe('servers', () => {
  it('formats them as node:dns does', () => {
    const servers = [
      '8.8.8.8',
      '[2001:4860::8888]:53',
      '1.1.1.1:5353',
      '[::1]',
      '2001:db8::2',
      '[2001:db8::3]:5353',
      '[192.0.2.53]:53',
    ];
    const theirs = new nodeDns.Resolver();
    const mine = new Resolver();
    theirs.setServers(servers);
    mine.setServers(servers);
    expect(mine.getServers()).toEqual(theirs.getServers());
  });

  it('rejects what is not an address, as node:dns does', () => {
    for (const bad of ['nope', 'dns.google', '1.1.1.1:x', '']) {
      const theirs = (() => {
        try {
          new nodeDns.Resolver().setServers([bad]);
        } catch (error) {
          return (error as { code: string }).code;
        }
      })();
      expect(() => new Resolver().setServers([bad]), bad).toThrow(
        expect.objectContaining({ code: theirs })
      );
    }
  });

  it('refuses port 0 and ports above 65535, which crash node:dns', () => {
    for (const bad of ['192.0.2.1:65536', '192.0.2.1:0']) {
      expect(() => new Resolver().setServers([bad])).toThrow(
        expect.objectContaining({ code: 'ERR_INVALID_IP_ADDRESS' })
      );
    }
  });

  it('asks no one after setServers([]), with the errors node:dns gives', async () => {
    const theirs = new nodeDns.Resolver({ timeout: 300, tries: 1 });
    theirs.setServers([]);
    const network = simulateNetwork({});
    const mine = new Resolver({ timeout: 300, tries: 1, transports: network.transports });
    mine.setServers([]);
    expect(mine.getServers()).toEqual([]);
    const cases: [Method, ...unknown[]][] = [
      ['resolve4', `www.${ZONE}`],
      ['resolveTxt', `www.${ZONE}`],
      ['resolveAny', `www.${ZONE}`],
      ['reverse', '192.0.2.99'],
    ];
    for (const [method, ...args] of cases) {
      expect(await errorOf(() => call(mine, method, args)), method).toEqual(
        await errorOf(() => call(theirs, method, args))
      );
    }
    // the same from a constructor given none
    const given = new Resolver({ servers: [], transports: network.transports });
    expect(given.getServers()).toEqual([]);
    expect(await errorOf(() => given.resolve4(`www.${ZONE}`))).toMatchObject({
      code: 'UNKNOWN_ARES_ERROR',
    });
    expect(network.queries).toEqual([]);
  });

  it("starts from the machine's own", () => {
    expect(new Resolver().getServers()).toEqual(nodeDns.getServers());
  });
});

describe('cancel', () => {
  it('rejects the calls in progress with ECANCELLED, as node:dns does', async () => {
    const theirs = new nodeDns.Resolver({ timeout: 2000, tries: 1 });
    theirs.setServers([`${server.address}:${server.port}`]);
    const mine = new Resolver({ timeout: 2000, tries: 1 });
    mine.setServers([`${server.address}:${server.port}`]);
    const errors = [theirs, mine].map(resolver =>
      errorOf(() => resolver.resolve4(`silent.${ZONE}`))
    );
    theirs.cancel();
    mine.cancel();
    const [nodeError, ourError] = await Promise.all(errors);
    expect(ourError).toEqual(nodeError);
    mine.close();
  });
});

describe('the top-level functions', () => {
  it('has every function node:dns/promises has, but lookupService', () => {
    const missing = Object.keys(nodeDns).filter(
      key => typeof (nodeDns as Record<string, unknown>)[key] === 'function' && !(key in facade)
    );
    expect(missing.sort()).toEqual(['lookupService']);
  });

  it("has node:dns's error codes", () => {
    for (const key of ['NODATA', 'NOTFOUND', 'SERVFAIL', 'REFUSED', 'TIMEOUT', 'BADRESP']) {
      expect((facade as Record<string, unknown>)[key]).toBe(
        (nodeDns as Record<string, unknown>)[key]
      );
    }
  });

  it('share one resolver', async () => {
    const before = facade.getServers();
    facade.setServers([`${server.address}:${server.port}`]);
    try {
      expect(await facade.resolve4(`www.${ZONE}`)).toEqual(['192.0.2.1', '192.0.2.2']);
      expect(await facade.lookup(`www.${ZONE}`, 4)).toEqual({ address: '192.0.2.1', family: 4 });
      const lookup = promisify(facade.connectLookup) as (
        hostname: string,
        options: object
      ) => Promise<string>;
      expect(await lookup(`www.${ZONE}`, { family: 4 })).toBe('192.0.2.1');
    } finally {
      facade.setServers(before);
    }
  });

  it('can stand in for node:dns/promises where its types are asked for', () => {
    // compile-time: each assignment fails to typecheck if a signature drifts from Node's
    const asNode: Pick<
      typeof nodeDns,
      | 'getServers'
      | 'lookup'
      | 'resolve'
      | 'resolve4'
      | 'resolve6'
      | 'resolveAny'
      | 'resolveCaa'
      | 'resolveCname'
      | 'resolveMx'
      | 'resolveNaptr'
      | 'resolveNs'
      | 'resolvePtr'
      | 'resolveSoa'
      | 'resolveSrv'
      | 'resolveTlsa'
      | 'resolveTxt'
      | 'reverse'
      | 'setServers'
    > = facade;
    const resolver: Omit<nodeDns.Resolver, 'setLocalAddress'> = new Resolver();
    expect(asNode).toBeDefined();
    expect(resolver).toBeDefined();
  });
});
