import { getServers } from 'node:dns';
import {
  ConnectionError,
  InvalidQueryError,
  InvalidResponseError,
  NoServerError,
  ParseError,
  TimeoutError,
} from '../src/errors';
import { AuthoritativeResolver, createLruCache, Resolver } from '../src/resolvers/index';
import type {
  AuthoritativeResolverOptions,
  ResolverOptions,
  TraceHop,
} from '../src/resolvers/index';
import { cacheLifetime } from '../src/resolvers/resolver';
import { toEndpoint } from '../src/transports/endpoint';
import type { DnsEvent } from '../src/transports/types';
import { decodeMessage, encodeMessage } from '../src/wire/index';
import { recursiveServer, simulateNetwork, zoneServer } from './support/simulated-network';
import type { SimulatedNetwork, SimulatedServer } from './support/simulated-network';

// the two resolvers, against a network that exists only in memory. What is being tested
// is which server gets asked what, and what is made of the answers

describe('Resolver', () => {
  const RECORDS: Parameters<typeof recursiveServer>[0] = [
    ['example.com', 'A', '192.0.2.1'],
    ['example.com', 'A', '192.0.2.2'],
    ['example.com', 'MX', '10 mail.example.com'],
    ['www.example.com', 'CNAME', 'example.com'],
    ['short.example.com', 'A', '192.0.2.9', 30],
  ];
  let network: SimulatedNetwork;

  function resolver(
    servers: Record<string, SimulatedServer> = { '10.0.0.1': recursiveServer(RECORDS) },
    options: ResolverOptions = {}
  ): Resolver {
    network = simulateNetwork(servers);
    return new Resolver({
      servers: Object.keys(servers),
      transports: network.transports,
      timeout: 100,
      ...options,
    });
  }

  afterEach(() => {
    vi.useRealTimers();
  });

  it('asks an ordinary recursive query and returns typed records', async () => {
    const answer = await resolver().query('example.com', 'MX');

    expect(network.queries).toEqual([
      {
        server: '10.0.0.1',
        name: 'example.com',
        type: 'MX',
        transport: 'udp',
        recursionDesired: true,
      },
    ]);
    expect(answer.rcodeName).toBe('NOERROR');
    // typed by the type asked for: no cast needed to read `exchange`
    expect(answer.records.map(record => `${record.preference} ${record.exchange}`)).toEqual([
      '10 mail.example.com',
    ]);
    expect(answer).toMatchObject({
      name: 'example.com',
      type: 'MX',
      class: 'IN',
      rcode: 0,
      server: '10.0.0.1',
      port: 53,
      transport: 'udp',
      attempts: 1,
      cached: false,
    });
    expect(answer.flags.ra).toBe(true);
    expect(answer.timestamp).toBeInstanceOf(Date);
    // and the raw response is there too
    expect(decodeMessage(answer.bytes).answers).toHaveLength(1);
    expect(answer.message.answers[0].rdata).toBeInstanceOf(Uint8Array);
    expect(answer.toDig()).toBe('dig @10.0.0.1 example.com MX');
  });

  it('returns a name that does not exist as an answer, not an error', async () => {
    const answer = await resolver().query('missing.example.com', 'A');
    expect(answer.rcodeName).toBe('NXDOMAIN');
    expect(answer.records).toEqual([]);
    expect(answer.authorities.map(record => record.type)).toEqual(['SOA']);
  });

  it('returns a name with no records of the type as an empty answer', async () => {
    const answer = await resolver().query('example.com', 'TXT');
    expect(answer.rcodeName).toBe('NOERROR');
    expect(answer.records).toEqual([]);
  });

  it('gives the records at the end of an alias, and the alias beside them', async () => {
    const answer = await resolver().query('www.example.com', 'A');
    expect(answer.records.map(record => record.address)).toEqual(['192.0.2.1', '192.0.2.2']);
    expect(answer.answers.map(record => record.type)).toEqual(['CNAME', 'A', 'A']);
    // asked for the alias itself, that is what comes back
    const alias = await resolver().query('www.example.com', 'CNAME');
    expect(alias.records.map(record => record.target)).toEqual(['example.com']);
  });

  it('accepts a type by number and a name in Unicode', async () => {
    const answer = await resolver().query('MÜNCHEN.example', 1);
    expect(network.queries[0]).toMatchObject({ name: 'xn--mnchen-3ya.example', type: 'A' });
    expect(answer.name).toBe('xn--mnchen-3ya.example');
  });

  it('rejects a question that cannot be asked', async () => {
    await expect(resolver().query('example.com', 'NOPE')).rejects.toBeInstanceOf(InvalidQueryError);
    expect(network.queries).toHaveLength(0);
  });

  describe('cache', () => {
    it('answers a repeated question without asking again', async () => {
      vi.useFakeTimers({ toFake: ['Date'] });
      const stub = resolver();
      const first = await stub.query('example.com', 'A');
      vi.setSystemTime(Date.now() + 100_000);
      const second = await stub.query('example.com', 'A');

      expect(network.queries).toHaveLength(1);
      expect(second.cached).toBe(true);
      expect(second.attempts).toBe(0);
      expect(second.timestamp).toEqual(first.timestamp);
      // what is left of the TTL, not what it was
      expect(first.records[0].ttl).toBe(300);
      expect(second.records[0].ttl).toBe(200);
      // the raw response is as it arrived
      expect(second.bytes).toEqual(first.bytes);
    });

    it('asks again once the TTL has run out', async () => {
      vi.useFakeTimers({ toFake: ['Date'] });
      const stub = resolver();
      await stub.query('short.example.com', 'A');
      vi.setSystemTime(Date.now() + 29_000);
      await stub.query('short.example.com', 'A');
      expect(network.queries).toHaveLength(1);
      vi.setSystemTime(Date.now() + 2000);
      const third = await stub.query('short.example.com', 'A');
      expect(network.queries).toHaveLength(2);
      expect(third.cached).toBe(false);
    });

    it('caps how long an answer is kept', async () => {
      vi.useFakeTimers({ toFake: ['Date'] });
      const stub = resolver(undefined, { maxTtl: 60 });
      await stub.query('example.com', 'A');
      vi.setSystemTime(Date.now() + 61_000);
      await stub.query('example.com', 'A');
      expect(network.queries).toHaveLength(2);
    });

    it('remembers that a name does not exist, for as long as the SOA says', async () => {
      vi.useFakeTimers({ toFake: ['Date'] });
      const stub = resolver();
      await stub.query('missing.example.com', 'A');
      // the simulated SOA has a TTL of 3600 and a minimum of 300: the smaller rules
      vi.setSystemTime(Date.now() + 299_000);
      const again = await stub.query('missing.example.com', 'A');
      expect(again.cached).toBe(true);
      expect(again.rcodeName).toBe('NXDOMAIN');
      vi.setSystemTime(Date.now() + 2000);
      await stub.query('missing.example.com', 'A');
      expect(network.queries).toHaveLength(2);
    });

    it('does not cache what it has no lifetime for', () => {
      const failed = decodeMessage(encodeMessage({ id: 1, flags: { qr: true }, rcode: 2 }));
      expect(cacheLifetime(failed)).toBe(0);
      const bare = decodeMessage(encodeMessage({ id: 1, flags: { qr: true }, rcode: 3 }));
      expect(cacheLifetime(bare)).toBe(0);
      const cut = decodeMessage(encodeMessage({ id: 1, flags: { qr: true, tc: true } }));
      expect(cacheLifetime(cut)).toBe(0);
    });

    it('keeps questions with different settings apart', async () => {
      const stub = resolver();
      await stub.query('example.com', 'A');
      await stub.query('example.com', 'A', { dnssecOk: true });
      await stub.query('example.com', 'AAAA');
      await stub.query('EXAMPLE.com.', 'A');
      expect(network.queries).toHaveLength(3);
    });

    it('hands out records nobody else holds', async () => {
      const stub = resolver();
      const first = await stub.query('example.com', 'A');
      first.records[0].address = 'changed';
      first.records.length = 0;
      const second = await stub.query('example.com', 'A');
      expect(second.records.map(record => record.address)).toEqual(['192.0.2.1', '192.0.2.2']);
    });

    it('can be turned off, or replaced', async () => {
      const uncached = resolver(undefined, { cache: false });
      await uncached.query('example.com', 'A');
      await uncached.query('example.com', 'A');
      expect(network.queries).toHaveLength(2);

      const own = createLruCache<never>({ max: 1 });
      const small = resolver(undefined, { cache: own });
      await small.query('example.com', 'A');
      await small.query('example.com', 'MX');
      // one slot: the first answer was pushed out
      await small.query('example.com', 'A');
      expect(network.queries).toHaveLength(3);
    });
  });

  it('sends one query for callers asking the same thing at once', async () => {
    const stub = resolver(undefined, { cache: false });
    const answers = await Promise.all(
      Array.from({ length: 6 }, () => stub.query('example.com', 'A'))
    );
    expect(network.queries).toHaveLength(1);
    expect(answers.every(answer => answer.records.length === 2)).toBe(true);
    // each caller has an answer of its own
    expect(answers[0].records).not.toBe(answers[1].records);
  });

  describe('several servers', () => {
    const good = recursiveServer(RECORDS);

    it('moves on from a server that cannot be reached', async () => {
      const stub = resolver({
        '10.0.0.1': () => new ConnectionError('refused'),
        '10.0.0.2': good,
      });
      const answer = await stub.query('example.com', 'A');
      expect(answer.server).toBe('10.0.0.2');
      expect(answer.records).toHaveLength(2);
      expect(network.log()).toEqual([
        // one retry on the first, then the second
        '10.0.0.1 example.com A',
        '10.0.0.1 example.com A',
        '10.0.0.2 example.com A',
      ]);
    });

    it('moves on from a server that answers with a failure', async () => {
      const stub = resolver({ '10.0.0.1': zoneServer({ zone: '.', rcode: 2 }), '10.0.0.2': good });
      const answer = await stub.query('example.com', 'A');
      expect(answer.server).toBe('10.0.0.2');
      expect(answer.rcodeName).toBe('NOERROR');
    });

    it('does not move on from a name that does not exist', async () => {
      const stub = resolver({ '10.0.0.1': good, '10.0.0.2': good });
      const answer = await stub.query('missing.example.com', 'A');
      expect(answer.rcodeName).toBe('NXDOMAIN');
      expect(network.queries).toHaveLength(1);
    });

    it('returns the failure when every server gives one', async () => {
      const failing = zoneServer({ zone: '.', rcode: 2 });
      const stub = resolver({ '10.0.0.1': failing, '10.0.0.2': failing });
      const answer = await stub.query('example.com', 'A');
      expect(answer.rcodeName).toBe('SERVFAIL');
      expect(answer.server).toBe('10.0.0.2');
      // and a failure is not remembered
      await stub.query('example.com', 'A');
      expect(network.queries).toHaveLength(4);
    });

    it('throws when no server answers at all', async () => {
      const stub = resolver({ '10.0.0.1': () => undefined, '10.0.0.2': () => undefined });
      const error = await stub.query('example.com', 'A', { timeout: 30, retries: 0 }).catch(e => e);
      expect(error).toBeInstanceOf(TimeoutError);
      expect(error.server).toBe('10.0.0.2');
    });
  });

  it('asks one particular server when told to, outside the cache', async () => {
    const stub = resolver({
      '10.0.0.1': recursiveServer(RECORDS),
      '10.0.0.9': recursiveServer([['example.com', 'A', '203.0.113.9']]),
    });
    const usual = await stub.query('example.com', 'A');
    const other = await stub.query('example.com', 'A', { server: '10.0.0.9' });
    expect(usual.records[0].address).toBe('192.0.2.1');
    expect(other.records[0].address).toBe('203.0.113.9');
    expect(other.server).toBe('10.0.0.9');
    expect(other.cached).toBe(false);
    // neither read from the cache nor written to it
    const after = await stub.query('example.com', 'A');
    expect(after.cached).toBe(true);
    expect(after.records[0].address).toBe('192.0.2.1');
    expect(network.log()).toEqual(['10.0.0.1 example.com A', '10.0.0.9 example.com A']);
  });

  it('passes query settings through, for every query or for one', async () => {
    network = simulateNetwork({ '10.0.0.1': recursiveServer(RECORDS) });
    const stub = new Resolver({
      servers: ['10.0.0.1'],
      transports: network.transports,
      transport: 'tcp',
      recursionDesired: false,
    });
    await stub.query('example.com', 'A');
    await stub.query('example.com', 'A', { transport: 'udp', recursionDesired: true });
    expect(network.queries.map(query => [query.transport, query.recursionDesired])).toEqual([
      ['tcp', false],
      ['udp', true],
    ]);
  });

  it('uses the resolvers the machine is set up with when given none', async () => {
    const [first] = getServers();
    if (!first) return;
    const address = toEndpoint(first, 'udp').host;
    network = simulateNetwork({ [address]: recursiveServer(RECORDS) });
    const stub = new Resolver({ transports: network.transports });
    const answer = await stub.query('example.com', 'A');
    expect(answer.server).toBe(address);
  });

  it('says so when there is nobody to ask', async () => {
    network = simulateNetwork({});
    const stub = new Resolver({ servers: [], transports: network.transports });
    // an empty list means "the system's", which the runtime here does have
    if (getServers().length === 0) {
      await expect(stub.query('example.com', 'A')).rejects.toBeInstanceOf(NoServerError);
    }
  });

  it('reports each query through onEvent', async () => {
    const events: DnsEvent[] = [];
    const stub = resolver(undefined, { onEvent: event => events.push(event) });
    await stub.query('example.com', 'A');
    await stub.query('example.com', 'A');
    // one network exchange; the cached answer made none
    expect(events.map(event => event.event)).toEqual(['query']);
  });

  it('reads malformed record data leniently unless told to be strict', async () => {
    // an A record three bytes long
    const broken: SimulatedServer = query =>
      encodeMessage({
        id: query.id,
        flags: { qr: true, ra: true },
        questions: query.questions,
        answers: [
          {
            name: 'example.com',
            type: 1,
            class: 1,
            ttl: 60,
            rdata: Uint8Array.of(192, 0, 2),
            section: 'answer',
          },
        ],
      });
    const lenient = await resolver({ '10.0.0.1': broken }).query('example.com', 'A');
    expect(lenient.answers[0]).toMatchObject({ type: 'TYPE1', data: 'c00002' });
    expect(lenient.records).toEqual([]);
    await expect(
      resolver({ '10.0.0.1': broken }, { strict: true }).query('example.com', 'A')
    ).rejects.toBeInstanceOf(ParseError);
  });

  it('stops when its signal aborts, and only that caller', async () => {
    const stub = resolver({ '10.0.0.1': () => undefined }, { timeout: 5000 });
    const controller = new AbortController();
    const reason = new Error('never mind');
    const pending = stub.query('example.com', 'A', { signal: controller.signal });
    controller.abort(reason);
    await expect(pending).rejects.toBe(reason);
  });
});

describe('AuthoritativeResolver', () => {
  // a small internet:
  //   .             10.0.0.1 (a.root), 10.0.0.2 (b.root)
  //   com           10.0.1.1 (a.gtld), 10.0.1.2 (b.gtld)
  //   net           10.0.2.1 (a.nettld)
  //   example.com   10.1.0.1 (ns1), 10.1.0.2 (ns2), with glue
  //   glueless.com  ns1.dnshost.net, no glue: its address has to be looked up
  //   dnshost.net   10.2.0.1 (ns.dnshost.net), with glue
  //   other.net     10.3.0.1 (ns.other.net), with glue
  const root = zoneServer({
    zone: '.',
    delegations: {
      com: { 'a.gtld.test': ['10.0.1.1'], 'b.gtld.test': ['10.0.1.2'] },
      net: { 'a.nettld.test': ['10.0.2.1'] },
    },
  });
  const com = zoneServer({
    zone: 'com',
    delegations: {
      'example.com': {
        'ns1.example.com': ['10.1.0.1', '2001:db8::1'],
        'ns2.example.com': ['10.1.0.2'],
      },
      'glueless.com': { 'ns1.dnshost.net': [] },
      'loop.com': { 'ns.loop.com': ['10.9.0.1'] },
      'many.com': {
        'ns1.many.com': ['10.4.0.1'],
        'ns2.many.com': ['10.4.0.2'],
        'ns3.many.com': ['10.4.0.3'],
        'ns4.many.com': ['10.4.0.4'],
      },
      'selfhosted.com': { 'ns.selfhosted.com': [] },
    },
  });
  const net = zoneServer({
    zone: 'net',
    delegations: {
      'dnshost.net': { 'ns.dnshost.net': ['10.2.0.1'] },
      'other.net': { 'ns.other.net': ['10.3.0.1'] },
    },
  });
  const example = zoneServer({
    zone: 'example.com',
    records: [
      ['example.com', 'A', '192.0.2.1'],
      ['example.com', 'NS', 'ns1.example.com'],
      ['example.com', 'NS', 'ns2.example.com'],
      ['www.example.com', 'CNAME', 'example.com'],
      ['away.example.com', 'CNAME', 'target.other.net'],
      ['round.example.com', 'CNAME', 'back.other.net'],
      ['deep.sub.example.com', 'TXT', 'hello'],
    ],
  });
  const dnshost = zoneServer({
    zone: 'dnshost.net',
    records: [['ns1.dnshost.net', 'A', '10.2.0.53']],
  });
  const glueless = zoneServer({
    zone: 'glueless.com',
    records: [['glueless.com', 'A', '192.0.2.77']],
  });
  const other = zoneServer({
    zone: 'other.net',
    records: [
      ['target.other.net', 'A', '203.0.113.5'],
      ['back.other.net', 'CNAME', 'round.example.com'],
    ],
  });

  const INTERNET: Record<string, SimulatedServer> = {
    '10.0.0.1': root,
    '10.0.0.2': root,
    '10.0.1.1': com,
    '10.0.1.2': com,
    '10.0.2.1': net,
    '10.1.0.1': example,
    '10.1.0.2': example,
    '2001:db8::1': example,
    '10.2.0.1': dnshost,
    '10.2.0.53': glueless,
    '10.3.0.1': other,
    // a server that refers its own zone back up to the parent
    '10.9.0.1': zoneServer({ zone: 'com', delegations: { 'loop.com': { 'ns.loop.com': [] } } }),
  };
  const ROOTS = [
    { name: 'a.root.test', ipv4: '10.0.0.1' },
    { name: 'b.root.test', ipv4: '10.0.0.2' },
  ];

  let network: SimulatedNetwork;

  function resolver(
    options: AuthoritativeResolverOptions = {},
    overrides: Record<string, SimulatedServer | undefined> = {}
  ): AuthoritativeResolver {
    const servers = { ...INTERNET };
    for (const [address, server] of Object.entries(overrides)) {
      if (server) servers[address] = server;
      else delete servers[address];
    }
    network = simulateNetwork(servers);
    return new AuthoritativeResolver({
      rootServers: ROOTS,
      transports: network.transports,
      timeout: 100,
      retries: 0,
      ...options,
    });
  }

  it('walks from the root to the zone and returns its answer with the path taken', async () => {
    const answer = await resolver().query('example.com', 'A');

    expect(network.log()).toEqual([
      '10.0.0.1 example.com A',
      '10.0.1.1 example.com A',
      '10.1.0.1 example.com A',
    ]);
    // nobody was asked to recurse
    expect(network.queries.every(query => !query.recursionDesired)).toBe(true);

    expect(answer.records.map(record => record.address)).toEqual(['192.0.2.1']);
    expect(answer.flags.aa).toBe(true);
    expect(answer).toMatchObject({
      name: 'example.com',
      type: 'A',
      rcodeName: 'NOERROR',
      server: '10.1.0.1',
      serverName: 'ns1.example.com',
      attempts: 3,
      cached: false,
    });
    expect(answer.trace).toMatchObject([
      {
        server: '10.0.0.1',
        serverName: 'a.root.test',
        zone: '.',
        referral: 'com',
        rcodeName: 'NOERROR',
      },
      { server: '10.0.1.1', serverName: 'a.gtld.test', zone: 'com', referral: 'example.com' },
      {
        server: '10.1.0.1',
        serverName: 'ns1.example.com',
        zone: 'example.com',
        name: 'example.com',
        type: 'A',
      },
    ]);
    // the answering hop is in the trace, and is not a referral
    expect(answer.trace?.[2]).not.toHaveProperty('referral');
    expect(answer.trace?.[2].bytes).toBe(answer.bytes.length);
    expect(answer.toDig()).toBe('dig +norecurse @10.1.0.1 example.com A');
  });

  it('returns a missing name and a missing type as answers', async () => {
    const missing = await resolver().query('nope.example.com', 'A');
    expect(missing.rcodeName).toBe('NXDOMAIN');
    expect(missing.records).toEqual([]);
    const empty = await resolver().query('example.com', 'MX');
    expect(empty.rcodeName).toBe('NOERROR');
    expect(empty.records).toEqual([]);
    expect(empty.authorities.map(record => record.type)).toEqual(['SOA']);
  });

  it('looks up a nameserver that came without an address', async () => {
    const answer = await resolver().query('glueless.com', 'A');

    expect(answer.records.map(record => record.address)).toEqual(['192.0.2.77']);
    expect(answer).toMatchObject({ server: '10.2.0.53', serverName: 'ns1.dnshost.net' });
    expect(network.log()).toEqual([
      '10.0.0.1 glueless.com A',
      '10.0.1.1 glueless.com A',
      // the delegation named ns1.dnshost.net and gave no address: find it, from the root
      '10.0.0.1 ns1.dnshost.net A',
      '10.0.2.1 ns1.dnshost.net A',
      '10.2.0.1 ns1.dnshost.net A',
      '10.2.0.53 glueless.com A',
    ]);
    // the trace is the path to the answer; the side trip is in the events, not here
    expect(answer.trace?.map(hop => hop.server)).toEqual(['10.0.0.1', '10.0.1.1', '10.2.0.53']);
    expect(answer.attempts).toBe(6);
  });

  it('takes a nameserver address from the host map before looking it up', async () => {
    const answer = await resolver({ hosts: { 'NS1.dnshost.net.': '10.2.0.53' } }).query(
      'glueless.com',
      'A'
    );
    expect(network.log()).toEqual([
      '10.0.0.1 glueless.com A',
      '10.0.1.1 glueless.com A',
      '10.2.0.53 glueless.com A',
    ]);
    expect(answer.serverName).toBe('ns1.dnshost.net');
  });

  it('asks a caller-supplied lookup for a nameserver address before resolving it', async () => {
    const asked: string[] = [];
    const answer = await resolver({
      resolveNameserver: name => {
        asked.push(name);
        return name === 'ns1.dnshost.net' ? ['10.2.0.53'] : undefined;
      },
    }).query('glueless.com', 'A');
    expect(asked).toEqual(['ns1.dnshost.net']);
    // no walk from the root for the nameserver's own name
    expect(network.log()).toEqual([
      '10.0.0.1 glueless.com A',
      '10.0.1.1 glueless.com A',
      '10.2.0.53 glueless.com A',
    ]);
    expect(answer.serverName).toBe('ns1.dnshost.net');
  });

  it('falls back to resolving from the root when the lookup has nothing', async () => {
    const answer = await resolver({ resolveNameserver: () => undefined }).query(
      'glueless.com',
      'A'
    );
    expect(answer.records).toHaveLength(1);
    expect(network.queries.some(query => query.name === 'ns1.dnshost.net')).toBe(true);
  });

  it('tries nameservers in the order it is given', async () => {
    // reverse order: ns2 before ns1
    const answer = await resolver({ nameserverOrder: (a, b) => b.localeCompare(a) }).query(
      'example.com',
      'A'
    );
    expect(answer.server).toBe('10.1.0.2');
    expect(answer.serverName).toBe('ns2.example.com');
  });

  it('names the answering server as the nameserver it asked, when two share an address', async () => {
    // ns1 and ns3 are the same machine. Asked as ns1, it is ns1 that answered
    const shared = zoneServer({
      zone: 'com',
      delegations: {
        'shared.com': { 'ns1.shared.com': ['10.5.0.1'], 'ns3.shared.com': ['10.5.0.1'] },
      },
    });
    const zone = zoneServer({ zone: 'shared.com', records: [['shared.com', 'A', '192.0.2.5']] });
    const answer = await resolver({}, { '10.0.1.1': shared, '10.5.0.1': zone }).query(
      'shared.com',
      'A'
    );
    expect(answer.server).toBe('10.5.0.1');
    expect(answer.serverName).toBe('ns1.shared.com');
    expect(answer.trace?.at(-1)?.serverName).toBe('ns1.shared.com');
  });

  it('tries the addresses of one nameserver in the same order on every run', async () => {
    // glue arrives in whatever order the parent sends it: lowest address first, or the
    // order the caller gives
    const parent = (addresses: string[]) =>
      zoneServer({ zone: 'com', delegations: { 'glued.com': { 'ns1.glued.com': addresses } } });
    const zone = zoneServer({ zone: 'glued.com', records: [['glued.com', 'A', '192.0.2.6']] });
    const servers = { '10.6.0.9': zone, '10.6.0.20': zone, '10.6.0.100': zone };

    for (const glue of [
      ['10.6.0.100', '10.6.0.9', '10.6.0.20'],
      ['10.6.0.20', '10.6.0.100', '10.6.0.9'],
    ]) {
      const answer = await resolver({}, { '10.0.1.1': parent(glue), ...servers }).query(
        'glued.com',
        'A'
      );
      expect(answer.server).toBe('10.6.0.9');
    }

    const answer = await resolver(
      { addressOrder: (a, b) => b.localeCompare(a) },
      { '10.0.1.1': parent(['10.6.0.100', '10.6.0.9', '10.6.0.20']), ...servers }
    ).query('glued.com', 'A');
    expect(answer.server).toBe('10.6.0.9');
    expect(
      (
        await resolver(
          { addressOrder: (a, b) => a.localeCompare(b) },
          { '10.0.1.1': parent(['10.6.0.100', '10.6.0.9', '10.6.0.20']), ...servers }
        ).query('glued.com', 'A')
      ).server
    ).toBe('10.6.0.100');
  });

  it('uses nothing but addresses as nameserver addresses', async () => {
    // a hint, a host map entry or a lookup result that is not an address is dropped: it
    // is never read as a name to resolve, or as a host with a port of its own
    const error = await resolver({
      rootServers: [{ name: 'evil.test', ipv4: '10.0.0.1:6379' }, { ipv6: 'localhost' }],
      addressFamily: 'both',
    })
      .query('example.com', 'A')
      .catch(caught => caught);
    expect(error).toBeInstanceOf(InvalidResponseError);
    expect(error.message).toContain('No usable nameserver address for the root');
    expect(network.queries).toHaveLength(0);

    await resolver({
      addressFamily: 'both',
      resolveNameserver: () => ['10.2.0.53:6379', '10.2.0.53'],
    }).query('glueless.com', 'A');
    expect(network.queries.map(query => query.server)).toEqual([
      '10.0.0.1',
      '10.0.1.1',
      '10.2.0.53',
    ]);
  });

  describe('servers that do not help', () => {
    it('moves on from one that cannot be reached, and says so in the trace', async () => {
      const answer = await resolver({}, { '10.1.0.1': undefined }).query('example.com', 'A');
      expect(answer.server).toBe('10.1.0.2');
      expect(answer.trace?.map(hop => [hop.server, hop.error?.name])).toEqual([
        ['10.0.0.1', undefined],
        ['10.0.1.1', undefined],
        ['10.1.0.1', 'ConnectionError'],
        ['10.1.0.2', undefined],
      ]);
    });

    it('moves on from one that refuses the zone', async () => {
      const lame = zoneServer({ zone: 'example.com', rcode: 5 });
      const answer = await resolver({}, { '10.1.0.1': lame }).query('example.com', 'A');
      expect(answer.server).toBe('10.1.0.2');
      expect(answer.rcodeName).toBe('NOERROR');
      expect(answer.trace?.[2]).toMatchObject({
        server: '10.1.0.1',
        rcodeName: 'REFUSED',
        error: { message: '10.1.0.1 answered REFUSED' },
      });
    });

    it('moves on from a root server that is down', async () => {
      const answer = await resolver({}, { '10.0.0.1': undefined }).query('example.com', 'A');
      expect(answer.records).toHaveLength(1);
      expect(answer.trace?.map(hop => hop.server).slice(0, 2)).toEqual(['10.0.0.1', '10.0.0.2']);
    });

    it('does not ask the other addresses of a server that has answered with a refusal', async () => {
      // ns1 has an IPv4 and an IPv6 address, and refuses on both
      const lame = zoneServer({ zone: 'example.com', rcode: 5 });
      const answer = await resolver(
        { addressFamily: 'both' },
        { '10.1.0.1': lame, '2001:db8::1': lame }
      ).query('example.com', 'A');
      expect(answer.server).toBe('10.1.0.2');
      // refused once is refused: straight on to ns2
      expect(network.queries.some(query => query.server === '2001:db8::1')).toBe(false);
    });

    it('returns the refusal when every server of the zone refuses', async () => {
      const lame = zoneServer({ zone: 'example.com', rcode: 5 });
      const answer = await resolver({}, { '10.1.0.1': lame, '10.1.0.2': lame }).query(
        'example.com',
        'A'
      );
      expect(answer.rcodeName).toBe('REFUSED');
      expect(answer.records).toEqual([]);
    });

    it('takes two servers refusing the same way as the answer of the zone', async () => {
      // four nameservers that all refuse, as an operator's servers do for a type it does
      // not serve: the second one settles it
      const refuses = zoneServer({ zone: 'many.com', rcode: 5 });
      const answer = await resolver(
        {},
        { '10.4.0.1': refuses, '10.4.0.2': refuses, '10.4.0.3': refuses, '10.4.0.4': refuses }
      ).query('many.com', 'RRSIG');
      expect(answer.rcodeName).toBe('REFUSED');
      expect(answer.server).toBe('10.4.0.2');
      expect(network.log().slice(2)).toEqual([
        '10.4.0.1 many.com RRSIG',
        '10.4.0.2 many.com RRSIG',
      ]);
    });

    it('keeps asking while the servers of a zone fail in different ways', async () => {
      const many = zoneServer({ zone: 'many.com', records: [['many.com', 'A', '192.0.2.9']] });
      const answer = await resolver(
        {},
        {
          '10.4.0.1': zoneServer({ zone: 'many.com', rcode: 5 }),
          '10.4.0.2': zoneServer({ zone: 'many.com', rcode: 2 }),
          '10.4.0.3': many,
          '10.4.0.4': many,
        }
      ).query('many.com', 'A');
      expect(answer.server).toBe('10.4.0.3');
      expect(answer.records.map(record => record.address)).toEqual(['192.0.2.9']);
    });

    it('throws when no server of the zone can be reached', async () => {
      const error = await resolver({}, { '10.1.0.1': undefined, '10.1.0.2': undefined })
        .query('example.com', 'A')
        .catch(caught => caught);
      expect(error).toBeInstanceOf(ConnectionError);
    });

    it('says how far it got when it fails', async () => {
      const error = await resolver({}, { '10.1.0.1': undefined, '10.1.0.2': undefined })
        .query('example.com', 'A')
        .catch(caught => caught);
      expect(
        error.trace.map((hop: TraceHop) => [hop.server, hop.rcodeName, hop.error?.name])
      ).toEqual([
        ['10.0.0.1', 'NOERROR', undefined],
        ['10.0.1.1', 'NOERROR', undefined],
        ['10.1.0.1', undefined, 'ConnectionError'],
        ['10.1.0.2', undefined, 'ConnectionError'],
      ]);
    });

    it('gives the whole query no longer than its total timeout', async () => {
      // four servers that say nothing, 40 ms of patience with each, 60 ms altogether:
      // the first is waited out, the second is cut short, and that is the time gone. A
      // timer can fire a moment early, so one more may be asked for what is left of it
      const silent = () => undefined;
      const started = Date.now();
      const error = await resolver(
        { timeout: 40, totalTimeout: 60 },
        { '10.4.0.1': silent, '10.4.0.2': silent, '10.4.0.3': silent, '10.4.0.4': silent }
      )
        .query('many.com', 'A')
        .catch(caught => caught);
      expect(error).toBeInstanceOf(TimeoutError);
      expect(Date.now() - started).toBeLessThan(120);
      const asked = network.log().slice(2);
      expect(asked.slice(0, 2)).toEqual(['10.4.0.1 many.com A', '10.4.0.2 many.com A']);
      expect(asked).not.toContain('10.4.0.4 many.com A');
      expect(error.trace.length).toBeGreaterThanOrEqual(4);
    });

    it('takes the total timeout for one query as well', async () => {
      const silent = () => undefined;
      const started = Date.now();
      const error = await resolver(
        { timeout: 200 },
        { '10.4.0.1': silent, '10.4.0.2': silent, '10.4.0.3': silent, '10.4.0.4': silent }
      )
        .query('many.com', 'A', { totalTimeout: 30 })
        .catch(caught => caught);
      expect(error).toBeInstanceOf(TimeoutError);
      // far short of the 200 ms one server would have been given
      expect(Date.now() - started).toBeLessThan(150);
      expect(network.log()).not.toContain('10.4.0.3 many.com A');
    });

    it('times out on a server that says nothing, then tries the next', async () => {
      const answer = await resolver({ timeout: 30 }, { '10.1.0.1': () => undefined }).query(
        'example.com',
        'A'
      );
      expect(answer.server).toBe('10.1.0.2');
      expect(answer.trace?.[2].error?.name).toBe('TimeoutError');
    });
  });

  describe('loops and limits', () => {
    it('treats a referral that leads back up as an error', async () => {
      const error = await resolver()
        .query('www.loop.com', 'A')
        .catch(caught => caught);
      expect(error).toBeInstanceOf(InvalidResponseError);
      expect(error.message).toContain('Referral loop');
      expect(error.message).toContain('not below loop.com');
    });

    it('gives up on a zone whose only nameserver is inside it with no address', async () => {
      // ns.selfhosted.com can only be found by asking ns.selfhosted.com
      const error = await resolver()
        .query('selfhosted.com', 'A')
        .catch(caught => caught);
      expect(error).toBeInstanceOf(InvalidResponseError);
      expect(error.message).toContain('No usable nameserver address for selfhosted.com');
    });

    it('stops after asking as many servers as it is allowed', async () => {
      const error = await resolver({ maxHops: 2 })
        .query('example.com', 'A')
        .catch(e => e);
      expect(error).toBeInstanceOf(InvalidResponseError);
      expect(error.message).toContain('after asking 2 servers');
      expect(network.queries).toHaveLength(2);
    });
  });

  describe('aliases', () => {
    it('returns an alias inside the zone with what it points at', async () => {
      const answer = await resolver().query('www.example.com', 'A');
      expect(answer.records.map(record => record.address)).toEqual(['192.0.2.1']);
      expect(answer.answers.map(record => record.type)).toEqual(['CNAME', 'A']);
    });

    it('stops at an alias into another zone by default', async () => {
      const answer = await resolver().query('away.example.com', 'A');
      // what the zone's server said: the alias, and no address
      expect(answer.rcodeName).toBe('NOERROR');
      expect(answer.records).toEqual([]);
      expect(answer.answers).toMatchObject([{ type: 'CNAME', target: 'target.other.net' }]);
      expect(answer.server).toBe('10.1.0.1');
      expect(network.queries.some(query => query.name === 'target.other.net')).toBe(false);
    });

    it('follows an alias into another zone when told to', async () => {
      const answer = await resolver({ followCnames: true }).query('away.example.com', 'A');

      expect(answer.name).toBe('away.example.com');
      expect(answer.records.map(record => record.address)).toEqual(['203.0.113.5']);
      expect(answer.answers.map(record => `${record.name} ${record.type}`)).toEqual([
        'away.example.com CNAME',
        'target.other.net A',
      ]);
      // the answer is the last server's; the trace is the whole journey
      expect(answer.server).toBe('10.3.0.1');
      expect(answer.trace?.map(hop => `${hop.zone} ${hop.name}`)).toEqual([
        '. away.example.com',
        'com away.example.com',
        'example.com away.example.com',
        '. target.other.net',
        'net target.other.net',
        'other.net target.other.net',
      ]);
    });

    it('treats an alias that leads back to itself as an error', async () => {
      const error = await resolver({ followCnames: true })
        .query('round.example.com', 'A')
        .catch(caught => caught);
      expect(error).toBeInstanceOf(InvalidResponseError);
      expect(error.message).toContain('Alias loop');
    });

    it('limits how long a chain of aliases may be', async () => {
      const error = await resolver({ followCnames: true, maxAliases: 1 })
        .query('round.example.com', 'A')
        .catch(caught => caught);
      expect(error).toBeInstanceOf(InvalidResponseError);
      expect(error.message).toContain('longer than 1');
    });
  });

  describe('what it remembers', () => {
    it('starts the next query from the deepest zone it already knows', async () => {
      const iterative = resolver();
      await iterative.query('example.com', 'A');
      network.queries.length = 0;
      await iterative.query('deep.sub.example.com', 'TXT');
      await iterative.query('other.com', 'A');
      expect(network.log()).toEqual([
        // straight to the zone's server
        '10.1.0.1 deep.sub.example.com TXT',
        // and for another name under com, straight to com
        '10.0.1.1 other.com A',
      ]);
    });

    it('forgets a delegation when its TTL runs out', async () => {
      vi.useFakeTimers({ toFake: ['Date'] });
      try {
        const iterative = resolver();
        await iterative.query('example.com', 'A');
        vi.setSystemTime(Date.now() + 172_801_000);
        network.queries.length = 0;
        await iterative.query('example.com', 'A');
        expect(network.queries).toHaveLength(3);
      } finally {
        vi.useRealTimers();
      }
    });

    it('starts from the root every time when told to remember nothing', async () => {
      const iterative = resolver({ cache: false });
      await iterative.query('example.com', 'A');
      await iterative.query('example.com', 'A');
      expect(network.queries).toHaveLength(6);
    });

    it('can be made to forget', async () => {
      const iterative = resolver();
      await iterative.query('example.com', 'A');
      iterative.clearCache();
      await iterative.query('example.com', 'A');
      expect(network.queries).toHaveLength(6);
    });
  });

  describe('addresses', () => {
    it('uses IPv4 addresses only by default', async () => {
      // ns1's IPv4 address is down; its IPv6 address is not tried
      const answer = await resolver({}, { '10.1.0.1': undefined }).query('example.com', 'A');
      expect(network.queries.some(query => query.server === '2001:db8::1')).toBe(false);
      expect(answer.server).toBe('10.1.0.2');
    });

    it('uses both families when told to, IPv4 first', async () => {
      const answer = await resolver({ addressFamily: 'both' }, { '10.1.0.1': undefined }).query(
        'example.com',
        'A'
      );
      expect(answer.server).toBe('2001:db8::1');
      expect(answer.serverName).toBe('ns1.example.com');
    });
  });

  it('spaces out queries to the same server when given a delay', async () => {
    const iterative = resolver({ serverDelay: 40 });
    await iterative.query('example.com', 'A');
    const started = performance.now();
    // three more questions for the same server, already known
    await Promise.all(
      ['example.com', 'www.example.com', 'nope.example.com'].map(name => iterative.query(name, 'A'))
    );
    expect(performance.now() - started).toBeGreaterThanOrEqual(75);
  });

  it('passes DNSSEC and transport settings to every hop', async () => {
    const seen: boolean[] = [];
    const recording =
      (server: SimulatedServer): SimulatedServer =>
      query => {
        seen.push(query.edns?.dnssecOk ?? false);
        return server(query);
      };
    const iterative = resolver(
      { transport: 'tcp', dnssecOk: true },
      { '10.0.0.1': recording(root), '10.0.1.1': recording(com), '10.1.0.1': recording(example) }
    );
    await iterative.query('example.com', 'A');
    expect(seen).toEqual([true, true, true]);
    expect(network.queries.every(query => query.transport === 'tcp')).toBe(true);
  });

  it('reports every query through onEvent, nameserver lookups included', async () => {
    const events: DnsEvent[] = [];
    await resolver({ onEvent: event => events.push(event) }).query('glueless.com', 'A');
    expect(events.filter(event => event.event === 'query')).toHaveLength(6);
  });

  it('stops when its signal aborts', async () => {
    const iterative = resolver({ timeout: 5000 }, { '10.0.1.1': () => undefined });
    const controller = new AbortController();
    const reason = new Error('never mind');
    const pending = iterative.query('example.com', 'A', { signal: controller.signal });
    setTimeout(() => controller.abort(reason), 20);
    await expect(pending).rejects.toBe(reason);
    // it did not go on to the zone's other servers
    expect(network.queries).toHaveLength(2);
  });

  it('rejects a question that cannot be asked', async () => {
    await expect(resolver().query('example.com', 'NOPE')).rejects.toBeInstanceOf(InvalidQueryError);
    expect(network.queries).toHaveLength(0);
  });
});
