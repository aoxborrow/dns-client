import { getServers } from 'node:dns';
import {
  ConnectionError,
  InvalidQueryError,
  InvalidResponseError,
  NoServerError,
  ParseError,
  TimeoutError,
} from '../../src/errors';
import { AuthoritativeResolver, createLruCache, Resolver, toDig } from '../../src/resolvers/index';
import type {
  AuthoritativeResolverOptions,
  CachedResponse,
  ResolverOptions,
  TraceHop,
} from '../../src/resolvers/index';
import { aliasTarget } from '../../src/resolvers/answer';
import { cacheLifetime } from '../../src/resolvers/resolver';
import { toEndpoint } from '../../src/transports/endpoint';
import { isNode } from '../../src/transports/runtime';
import type { DnsEvent } from '../../src/transports/types';
import { decodeMessage, encodeMessage, encodeName } from '../../src/wire/index';
import {
  late,
  recursiveServer,
  simulateNetwork,
  soaRecord,
  truncatedOverUdp,
  zoneServer,
} from '../support/simulated-network';
import type { SimulatedNetwork, SimulatedServer } from '../support/simulated-network';

// UDP where there is UDP, which is Node; TCP elsewhere
const DEFAULT_TRANSPORT = isNode() ? 'udp' : 'tcp';

// what Math.random is made to return for the authoritative resolver's shuffle to leave
// every list as it came: the root servers as given, a zone's nameservers and one
// nameserver's addresses in the order the referral listed them
const AS_GIVEN = 1 - Number.EPSILON;

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
        port: 53,
        name: 'example.com',
        type: 'MX',
        transport: DEFAULT_TRANSPORT,
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
      transport: DEFAULT_TRANSPORT,
      attempts: 1,
      cached: false,
    });
    expect(answer.flags.ra).toBe(true);
    expect(answer.timestamp).toBeInstanceOf(Date);
    // and the raw response is there too
    expect(decodeMessage(answer.bytes).answers).toHaveLength(1);
    expect(answer.message.answers[0].rdata).toBeInstanceOf(Uint8Array);
    expect(toDig(answer)).toBe(
      DEFAULT_TRANSPORT === 'udp'
        ? 'dig @10.0.0.1 example.com MX'
        : 'dig +tcp @10.0.0.1 example.com MX'
    );
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

  it('finds the records for a name written with escapes', async () => {
    const answer = await resolver().query('\\101xample.com', 'A');
    expect(answer.records.map(record => record.address)).toEqual(['192.0.2.1', '192.0.2.2']);
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

    it('keeps an empty answer reached through an alias for the negative lifetime', () => {
      const alias = {
        name: 'www.example.com',
        type: 5,
        class: 1,
        ttl: 3600,
        rdata: encodeName('host.example.com'),
        section: 'answer' as const,
      };
      const address = {
        name: 'host.example.com',
        type: 1,
        class: 1,
        ttl: 1800,
        rdata: Uint8Array.of(192, 0, 2, 1),
        section: 'answer' as const,
      };
      const lifetime = (parts: Parameters<typeof encodeMessage>[0]) =>
        cacheLifetime(
          decodeMessage(
            encodeMessage({ questions: [{ name: 'www.example.com', type: 1, class: 1 }], ...parts })
          )
        );
      const header = { id: 1, flags: { qr: true } };
      // the alias and its target's address: the shortest TTL
      expect(lifetime({ ...header, answers: [alias, address] })).toBe(1800);
      // the alias, and the target has no address: the SOA's minimum, not the alias's TTL
      expect(
        lifetime({
          ...header,
          answers: [alias],
          authorities: [soaRecord('example.com', 3600, 300)],
        })
      ).toBe(300);
      // nor longer than the alias lives
      expect(
        lifetime({
          ...header,
          answers: [{ ...alias, ttl: 60 }],
          authorities: [soaRecord('example.com', 3600, 300)],
        })
      ).toBe(60);
      // the target does not exist
      expect(
        lifetime({
          ...header,
          rcode: 3,
          answers: [alias],
          authorities: [soaRecord('example.com', 3600, 300)],
        })
      ).toBe(300);
      // with no SOA, nothing says how long the empty part lives
      expect(lifetime({ ...header, answers: [alias] })).toBe(0);
      // a question for the alias itself is answered by it
      expect(
        cacheLifetime(
          decodeMessage(
            encodeMessage({
              ...header,
              questions: [{ name: 'www.example.com', type: 5, class: 1 }],
              answers: [alias],
            })
          )
        )
      ).toBe(3600);
    });

    it('keeps questions with different settings apart', async () => {
      const stub = resolver();
      await stub.query('example.com', 'A');
      await stub.query('example.com', 'A', { dnssecOk: true });
      await stub.query('example.com', 'AAAA');
      await stub.query('EXAMPLE.com.', 'A');
      await stub.query('example.com', 'A', { port: 5353 });
      expect(network.queries).toHaveLength(4);
    });

    it('keeps questions with different EDNS options apart, in the cache and in flight', async () => {
      // two client subnets (option 8) can get two different answers
      const subnet = (last: number) => ({
        code: 8,
        data: Uint8Array.of(0, 1, 24, 0, 192, 0, 2, last),
      });
      const stub = resolver();
      await Promise.all([
        stub.query('example.com', 'A', { ednsOptions: [subnet(1)] }),
        stub.query('example.com', 'A', { ednsOptions: [subnet(2)] }),
        stub.query('example.com', 'A'),
      ]);
      expect(network.queries).toHaveLength(3);

      const again = await stub.query('example.com', 'A', { ednsOptions: [subnet(2)] });
      expect(again.cached).toBe(true);
      expect(network.queries).toHaveLength(3);
    });

    it('keeps questions with a different UDP buffer or TCP fallback apart, in the cache and in flight', async () => {
      // a 512-byte buffer can be truncated where 1232 is not, and without the fallback the
      // truncated answer is the one kept
      const stub = resolver();
      await Promise.all([
        stub.query('example.com', 'A'),
        stub.query('example.com', 'A', { udpPayloadSize: 512 }),
        stub.query('example.com', 'A', { tcpFallback: false }),
      ]);
      expect(network.queries).toHaveLength(3);

      // the default buffer written out is still the same question
      const same = await stub.query('example.com', 'A', { udpPayloadSize: 1232 });
      expect(same.cached).toBe(true);
      const again = await stub.query('example.com', 'A', { udpPayloadSize: 512 });
      expect(again.cached).toBe(true);
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

    it('hands out a raw response nobody else holds', async () => {
      const stub = resolver(undefined, { cache: createLruCache({ max: 10 }) });
      const [first, shared] = await Promise.all([
        stub.query('example.com', 'A'),
        stub.query('example.com', 'A'),
      ]);
      expect(network.queries).toHaveLength(1);
      first.message.answers[0].rdata.set([203, 0, 113, 1]);
      first.message.answers.length = 0;
      first.bytes.fill(0);

      const cached = await stub.query('example.com', 'A');
      expect(cached.cached).toBe(true);
      for (const answer of [shared, cached]) {
        expect(answer.records.map(record => record.address)).toEqual(['192.0.2.1', '192.0.2.2']);
        expect(answer.message.answers).toHaveLength(2);
        expect(decodeMessage(answer.bytes).answers).toHaveLength(2);
      }
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

  // only Node can read the machine's resolvers
  it.skipIf(!isNode())(
    'uses the resolvers the machine is set up with when given none',
    async () => {
      const [first] = getServers();
      if (!first) return;
      const address = toEndpoint(first, 'udp').host;
      network = simulateNetwork({ [address]: recursiveServer(RECORDS) });
      const stub = new Resolver({ transports: network.transports });
      const answer = await stub.query('example.com', 'A');
      expect(answer.server).toBe(address);
    }
  );

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

  it('hands back the name with no trailing dot, in the case it was written', async () => {
    const answer = await resolver().query('Example.COM.', 'A');
    expect(answer.name).toBe('Example.COM');
    expect(answer.query.name).toBe('Example.COM');
    expect(answer.records).toHaveLength(2);
  });

  it('returns plain data, which toDig reads', async () => {
    const answer = await resolver().query('example.com', 'A', {
      dnssecOk: true,
      checkingDisabled: true,
    });
    expect(answer.query).toEqual({
      name: 'example.com',
      type: 'A',
      class: 'IN',
      flags: { rd: true, cd: true, ad: false },
      edns: { udpPayloadSize: 1232, dnssecOk: true },
    });
    // nothing in it is a function: it survives a structured clone whole
    const copy = structuredClone(answer);
    expect(copy).toEqual(answer);
    expect(toDig(copy)).toBe(toDig(answer));
    // `+tcp` where the runtime has no UDP and TCP is the default, as on Workers
    expect(toDig(answer)).toMatch(/\+dnssec \+cd (\+tcp )?@10\.0\.0\.1 example\.com A/);
  });

  it('keeps when a cached response arrived as a Date', async () => {
    const stored: CachedResponse[] = [];
    const spying = resolver(undefined, {
      cache: {
        get: () => undefined,
        set: (_key, value) => stored.push(value),
        delete: () => undefined,
        clear: () => undefined,
      },
    });
    await spying.query('example.com', 'A');
    expect(stored[0].receivedAt).toBeInstanceOf(Date);
  });

  it('holds back queries to one server past serverConcurrency', async () => {
    let inFlight = 0;
    let most = 0;
    const answer = recursiveServer(RECORDS);
    const counted: SimulatedServer = async query => {
      inFlight++;
      most = Math.max(most, inFlight);
      await new Promise(resolve => setTimeout(resolve, 5));
      inFlight--;
      return answer(query);
    };
    const limited = resolver({ '10.0.0.1': counted }, { cache: false, serverConcurrency: 2 });
    const names = Array.from({ length: 6 }, (_, index) => `n${index}.example.com`);
    await Promise.all(names.map(name => limited.query(name, 'A')));
    expect(most).toBe(2);

    most = 0;
    const open = resolver({ '10.0.0.1': counted }, { cache: false, serverConcurrency: Infinity });
    await Promise.all(names.map(name => open.query(name, 'A')));
    expect(most).toBe(6);
  });

  it('limits queries to 16 at once to one server by default', async () => {
    let inFlight = 0;
    let most = 0;
    const answer = recursiveServer(RECORDS);
    const counted: SimulatedServer = async query => {
      inFlight++;
      most = Math.max(most, inFlight);
      await new Promise(resolve => setTimeout(resolve, 5));
      inFlight--;
      return answer(query);
    };
    const names = Array.from({ length: 20 }, (_, index) => `n${index}.example.com`);
    const stub = resolver({ '10.0.0.1': counted }, { cache: false });
    await Promise.all(names.map(name => stub.query(name, 'A')));
    expect(most).toBe(16);
  });

  it('lists what went wrong at every server on the error it throws', async () => {
    const error = await resolver({ '10.0.0.8': () => undefined, '10.0.0.9': () => undefined })
      .query('example.com', 'A')
      .catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(TimeoutError);
    const { failures } = error as TimeoutError;
    expect(failures?.map(failure => failure.server)).toEqual(['10.0.0.8', '10.0.0.9']);
    expect(failures?.every(failure => failure.error instanceof TimeoutError)).toBe(true);
    // the error thrown is the last server's, and is among them
    expect(failures?.at(-1)?.error).toBe(error);
  });

  describe('a truncated answer whose TCP retry fails', () => {
    it('comes back as it came, TC set, saying why, and is not cached', async () => {
      const events: DnsEvent[] = [];
      const stub = resolver(
        { '10.0.0.1': truncatedOverUdp(recursiveServer(RECORDS)) },
        { transport: 'udp', retries: 0, onEvent: event => events.push(event) }
      );
      const answer = await stub.query('example.com', 'A');
      expect(answer.flags.tc).toBe(true);
      expect(answer.transport).toBe('udp');
      expect(answer.records.map(record => record.address)).toEqual(['192.0.2.1', '192.0.2.2']);
      expect(answer.tcpFallbackError).toMatchObject({ name: 'ConnectionError' });
      expect(events.map(({ event }) => event)).toEqual([
        'query',
        'tcp-fallback',
        'query',
        'tcp-fallback-failed',
      ]);
      expect(network.queries.map(query => query.transport)).toEqual(['udp', 'tcp']);

      // a truncated answer is not the whole answer, and is asked again next time
      const again = await stub.query('example.com', 'A');
      expect(again.cached).toBe(false);
      expect(network.queries).toHaveLength(4);
    });

    it('comes back empty when the truncated answer was', async () => {
      const answer = await resolver(
        { '10.0.0.1': truncatedOverUdp(recursiveServer(RECORDS), true) },
        { transport: 'udp' }
      ).query('example.com', 'A');
      expect(answer.flags.tc).toBe(true);
      expect(answer.records).toEqual([]);
      expect(answer.tcpFallbackError?.name).toBe('ConnectionError');
    });

    it('is the answer: the next server is not asked', async () => {
      const answer = await resolver(
        {
          '10.0.0.1': truncatedOverUdp(recursiveServer(RECORDS)),
          '10.0.0.2': recursiveServer(RECORDS),
        },
        { transport: 'udp', retries: 0 }
      ).query('example.com', 'A');
      expect(answer.server).toBe('10.0.0.1');
      expect(answer.flags.tc).toBe(true);
      expect(network.queries.map(query => query.server)).toEqual(['10.0.0.1', '10.0.0.1']);
    });

    it('still rejects with the reason when the caller aborts', async () => {
      const controller = new AbortController();
      const reason = new Error('never mind');
      const hanging: SimulatedServer = (query, transport) =>
        transport === 'udp' ? truncatedOverUdp(recursiveServer(RECORDS))(query, 'udp') : undefined;
      const pending = resolver({ '10.0.0.1': hanging }, { transport: 'udp', timeout: 5000 }).query(
        'example.com',
        'A',
        { signal: controller.signal }
      );
      setTimeout(() => controller.abort(reason), 20);
      await expect(pending).rejects.toBe(reason);
    });
  });
});

describe('aliasTarget', () => {
  const base = { class: 'IN', ttl: 300 } as const;
  const dname = {
    ...base,
    name: 'old.example.com',
    type: 'DNAME',
    target: 'new.example.net',
  } as const;

  it('rewrites the suffix of a name below a DNAME, and not the DNAME owner itself', () => {
    expect(aliasTarget('a.b.old.example.com', [dname])).toBe('a.b.new.example.net');
    expect(aliasTarget('old.example.com', [dname])).toBe('old.example.com');
    expect(aliasTarget('a.example.com', [dname])).toBe('a.example.com');
  });

  it('takes the synthesized CNAME over the DNAME beside it, then keeps following', () => {
    const cname = {
      ...base,
      name: 'www.old.example.com',
      type: 'CNAME',
      target: 'x.example.org',
    } as const;
    expect(aliasTarget('www.old.example.com', [dname, cname])).toBe('x.example.org');
    const onward = {
      ...base,
      name: 'www.new.example.net',
      type: 'CNAME',
      target: 'end.example.org',
    } as const;
    expect(aliasTarget('www.old.example.com', [dname, onward])).toBe('end.example.org');
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

  // the same servers in the same order on every run. The default order has cases of its own
  beforeEach(() => {
    vi.spyOn(Math, 'random').mockReturnValue(AS_GIVEN);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

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
      // IPv4 only, which most of these cases are written against. The defaults have cases
      // of their own
      addressFamily: 'ipv4',
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
    expect(toDig(answer)).toBe(
      DEFAULT_TRANSPORT === 'udp'
        ? 'dig +norecurse @10.1.0.1 example.com A'
        : 'dig +norecurse +tcp @10.1.0.1 example.com A'
    );
  });

  it('resolves a name written with escapes', async () => {
    const answer = await resolver().query('\\101xample.com', 'A');
    expect(answer.name).toBe('example.com');
    expect(answer.records.map(record => record.address)).toEqual(['192.0.2.1']);
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

  it('starts where the query says, and still looks nameservers up from the root', async () => {
    const iterative = resolver();
    const answer = await iterative.query('glueless.com', 'A', {
      startAt: [{ name: 'b.gtld.test', ipv4: '10.0.1.2' }],
    });
    expect(answer.records.map(record => record.address)).toEqual(['192.0.2.77']);
    expect(network.log()).toEqual([
      '10.0.1.2 glueless.com A',
      '10.0.0.1 ns1.dnshost.net A',
      '10.0.2.1 ns1.dnshost.net A',
      '10.2.0.1 ns1.dnshost.net A',
      '10.2.0.53 glueless.com A',
    ]);
    expect(answer.trace?.map(hop => [hop.server, hop.serverName])).toEqual([
      ['10.0.1.2', 'b.gtld.test'],
      ['10.2.0.53', 'ns1.dnshost.net'],
    ]);

    // what that walk was told is not kept for a query from the root
    network.queries.length = 0;
    await iterative.query('glueless.com', 'A');
    expect(network.log()).toEqual([
      '10.0.0.1 glueless.com A',
      '10.0.1.1 glueless.com A',
      '10.2.0.53 glueless.com A',
    ]);
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

  it('gives a nameserver lookup what is left of the total timeout, and names it when that runs out', async () => {
    // dnshost.net's server says nothing, so ns1.dnshost.net cannot be found in time
    const error = await resolver({ totalTimeout: 100 }, { '10.2.0.1': () => undefined })
      .query('glueless.com', 'A')
      .catch(caught => caught);
    expect(error).toBeInstanceOf(TimeoutError);
    expect(error.server).toBe('ns1.dnshost.net');
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

  it('names a nameserver as its zone wrote it', async () => {
    // the delegation spells the name with capitals, and its glue in lower case
    const parent = zoneServer({
      zone: 'com',
      delegations: { 'cased.com': { 'NS1.Cased.COM': ['10.7.0.1'] } },
    });
    const zone = zoneServer({ zone: 'cased.com', records: [['cased.com', 'A', '192.0.2.7']] });
    const answer = await resolver({}, { '10.0.1.1': parent, '10.7.0.1': zone }).query(
      'cased.com',
      'A'
    );
    expect(answer.server).toBe('10.7.0.1');
    expect(answer.serverName).toBe('NS1.Cased.COM');
    expect(answer.trace?.at(-1)?.serverName).toBe('NS1.Cased.COM');
  });

  it('tries the addresses of one nameserver in the order the shuffle leaves them', async () => {
    // glue arrives in whatever order the parent sends it, and the shuffle starts from that
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
      expect(answer.server).toBe(glue[0]);
    }

    // with the draw always at the bottom, the shuffle turns 100, 9, 20 into 9, 20, 100
    vi.spyOn(Math, 'random').mockReturnValue(0);
    const glued = parent(['10.6.0.100', '10.6.0.9', '10.6.0.20']);
    const answer = await resolver({}, { '10.0.1.1': glued, '10.0.1.2': glued, ...servers }).query(
      'glued.com',
      'A'
    );
    expect(answer.server).toBe('10.6.0.9');
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
      hosts: { 'ns1.dnshost.net': ['10.2.0.53:6379', '10.2.0.53'] },
    }).query('glueless.com', 'A');
    expect(network.queries.map(query => query.server)).toEqual([
      '10.0.0.1',
      '10.0.1.1',
      '10.2.0.53',
    ]);
  });

  it('ignores glue for a nameserver outside the zone that sent it, and looks it up', async () => {
    // com hands out an address for ns1.dnshost.net, a name in net it has no authority for
    const offside = zoneServer({
      zone: 'com',
      delegations: { 'glueless.com': { 'ns1.dnshost.net': ['10.6.6.6'] } },
    });
    const impostor = zoneServer({
      zone: 'glueless.com',
      records: [['glueless.com', 'A', '203.0.113.9']],
    });
    const answer = await resolver(
      {},
      { '10.0.1.1': offside, '10.0.1.2': offside, '10.6.6.6': impostor }
    ).query('glueless.com', 'A');

    expect(answer.records.map(record => record.address)).toEqual(['192.0.2.77']);
    expect(answer).toMatchObject({ server: '10.2.0.53', serverName: 'ns1.dnshost.net' });
    expect(network.log()).toEqual([
      '10.0.0.1 glueless.com A',
      '10.0.1.1 glueless.com A',
      '10.0.0.1 ns1.dnshost.net A',
      '10.0.2.1 ns1.dnshost.net A',
      '10.2.0.1 ns1.dnshost.net A',
      '10.2.0.53 glueless.com A',
    ]);
  });

  it('follows a referral that comes with records its server has no authority for', async () => {
    // com puts an address for the name in the answer section, not authoritative, beside
    // the usual delegation to example.com's servers
    const forward: SimulatedServer = query => {
      const referral = decodeMessage(com(query) as Uint8Array);
      return encodeMessage({
        ...referral,
        answers: [
          {
            name: 'example.com',
            type: 1,
            class: 1,
            ttl: 300,
            rdata: Uint8Array.of(203, 0, 113, 9),
            section: 'answer',
          },
        ],
      });
    };
    const answer = await resolver({}, { '10.0.1.1': forward, '10.0.1.2': forward }).query(
      'example.com',
      'A'
    );

    expect(answer.records.map(record => record.address)).toEqual(['192.0.2.1']);
    expect(answer).toMatchObject({ server: '10.1.0.1', serverName: 'ns1.example.com' });
    expect(answer.flags.aa).toBe(true);
    expect(network.log()).toEqual([
      '10.0.0.1 example.com A',
      '10.0.1.1 example.com A',
      '10.1.0.1 example.com A',
    ]);
    expect(answer.trace?.[1]).toMatchObject({ zone: 'com', referral: 'example.com' });
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

    describe('a truncated answer whose TCP retry fails', () => {
      it("returns the zone's own answer as it came, TC set", async () => {
        const answer = await resolver({}, { '10.1.0.1': truncatedOverUdp(example) }).query(
          'example.com',
          'A'
        );
        expect(answer.server).toBe('10.1.0.1');
        expect(answer.flags).toMatchObject({ aa: true, tc: true });
        expect(answer.records.map(record => record.address)).toEqual(['192.0.2.1']);
        expect(answer.tcpFallbackError).toMatchObject({ name: 'ConnectionError' });
        expect(answer.trace?.at(-1)).toMatchObject({
          server: '10.1.0.1',
          transport: 'udp',
          tcpFallbackError: { name: 'ConnectionError' },
        });
        expect(answer.trace?.at(-1)?.error).toBeUndefined();
      });

      it('returns an empty authoritative answer too, TC set', async () => {
        const answer = await resolver({}, { '10.1.0.1': truncatedOverUdp(example, true) }).query(
          'example.com',
          'A'
        );
        expect(answer.server).toBe('10.1.0.1');
        expect(answer.flags.tc).toBe(true);
        expect(answer.records).toEqual([]);
      });

      it('follows the delegation a truncated referral still carries', async () => {
        const events: DnsEvent[] = [];
        const answer = await resolver(
          { onEvent: event => events.push(event) },
          { '10.0.1.1': truncatedOverUdp(com) }
        ).query('example.com', 'A');
        expect(network.log()).toEqual([
          '10.0.0.1 example.com A',
          '10.0.1.1 example.com A',
          '10.0.1.1 example.com A',
          '10.1.0.1 example.com A',
        ]);
        expect(answer.server).toBe('10.1.0.1');
        expect(answer.flags.tc).toBe(false);
        expect(answer.tcpFallbackError).toBeUndefined();
        expect(answer.trace?.[1]).toMatchObject({
          server: '10.0.1.1',
          referral: 'example.com',
          tcpFallbackError: { name: 'ConnectionError' },
        });
        expect(events.filter(({ event }) => event === 'tcp-fallback-failed')).toMatchObject([
          { server: '10.0.1.1', query: 'example.com', error: { name: 'ConnectionError' } },
        ]);
      });

      it("moves on to the zone's next server from a truncated referral with nothing in it", async () => {
        const answer = await resolver({}, { '10.0.1.1': truncatedOverUdp(com, true) }).query(
          'example.com',
          'A'
        );
        expect(answer.server).toBe('10.1.0.1');
        expect(answer.flags.tc).toBe(false);
        expect(answer.trace?.map(hop => [hop.server, hop.error?.name])).toEqual([
          ['10.0.0.1', undefined],
          ['10.0.1.1', 'ConnectionError'],
          ['10.0.1.2', undefined],
          ['10.1.0.1', undefined],
        ]);
      });

      it('throws the TCP failure when every server of the zone sends an empty truncated referral', async () => {
        const error = await resolver(
          {},
          {
            '10.0.1.1': truncatedOverUdp(com, true),
            '10.0.1.2': truncatedOverUdp(com, true),
          }
        )
          .query('example.com', 'A')
          .catch((caught: unknown) => caught);
        expect(error).toBeInstanceOf(ConnectionError);
        expect((error as ConnectionError).failures?.map(failure => failure.server)).toEqual([
          '10.0.1.1',
          '10.0.1.2',
        ]);
      });
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

    it('throws the first failure when no server of the zone answers', async () => {
      // ns1 says nothing and ns2 cannot be reached: the error is from the server that
      // would have answered, and the other is in the trace
      const error = await resolver(
        { timeout: 30 },
        { '10.1.0.1': () => undefined, '10.1.0.2': undefined }
      )
        .query('example.com', 'A')
        .catch(caught => caught);
      expect(error).toBeInstanceOf(TimeoutError);
      expect(error.server).toBe('10.1.0.1');
      expect(error.trace.at(-1)).toMatchObject({
        server: '10.1.0.2',
        error: { name: 'ConnectionError' },
      });
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

    it('counts retries against the total timeout', async () => {
      // every server silent, a second of patience with each and two retries, 100 ms
      // altogether: the first server's retries are cut off with the rest
      const silent = () => undefined;
      const started = Date.now();
      const error = await resolver(
        { timeout: 1000, retries: 2, totalTimeout: 100 },
        { '10.0.0.1': silent, '10.0.0.2': silent }
      )
        .query('example.com', 'A')
        .catch(caught => caught);
      expect(error).toBeInstanceOf(TimeoutError);
      expect(Date.now() - started).toBeLessThan(180);
      // the first server's retries are cut off, and the second may be asked once for what
      // is left when its timer fires a moment early
      expect(network.log().length).toBeLessThan(3);
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

  describe('the last server a zone has to ask', () => {
    // on a fake clock, so the timers and the clock the walk reads agree
    beforeEach(() => vi.useFakeTimers());
    afterEach(() => vi.useRealTimers());

    // the query, and when it settled on the fake clock
    function timed<T>(pending: Promise<T>): { result: Promise<T>; settledAt: () => number } {
      const started = Date.now();
      let settled: number | undefined;
      const result = pending.finally(() => (settled = Date.now() - started));
      result.catch(() => {});
      return { result, settledAt: () => settled ?? Infinity };
    }

    it('gives a lone starting server the whole time, not the patience with one', async () => {
      // the one place to start, answering after 60% of the time: the patience with one
      // server is half of it, and there is nobody to save the other half for
      const { result, settledAt } = timed(
        resolver(
          {
            rootServers: [{ name: 'ns1.example.com', ipv4: '10.1.0.1' }],
            timeout: 100,
            totalTimeout: 200,
          },
          { '10.1.0.1': late(120, example) }
        ).query('example.com', 'A')
      );
      await vi.advanceTimersByTimeAsync(200);
      const answer = await result;
      expect(answer.server).toBe('10.1.0.1');
      expect(answer.records.map(record => record.address)).toEqual(['192.0.2.1']);
      expect(settledAt()).toBe(120);
    });

    it('says how long the lone server was given when it does not answer', async () => {
      const { result } = timed(
        resolver(
          {
            rootServers: [{ name: 'ns1.example.com', ipv4: '10.1.0.1' }],
            timeout: 100,
            totalTimeout: 200,
          },
          { '10.1.0.1': () => undefined }
        ).query('example.com', 'A')
      );
      await vi.advanceTimersByTimeAsync(200);
      const error = await result.catch(caught => caught);
      expect(error).toBeInstanceOf(TimeoutError);
      expect(error.message).toBe('No answer from 10.1.0.1 within 200 ms');
    });

    it('gives the one nameserver of a delegation what is left of the time', async () => {
      // other.net has one nameserver, which answers after more than the patience with one
      // server and well inside what the walk has left
      const { result, settledAt } = timed(
        resolver({ timeout: 100, totalTimeout: 300 }, { '10.3.0.1': late(150, other) }).query(
          'target.other.net',
          'A'
        )
      );
      await vi.advanceTimersByTimeAsync(300);
      const answer = await result;
      expect(answer.server).toBe('10.3.0.1');
      expect(answer.records.map(record => record.address)).toEqual(['203.0.113.5']);
      expect(settledAt()).toBe(150);
    });

    it('still gives each server of a zone with two the patience with one', async () => {
      // both of example.com's servers answer late. The first is given up on when its
      // patience runs out, for the second, which is the last and has the rest
      const { result, settledAt } = timed(
        resolver(
          { timeout: 100, totalTimeout: 300 },
          { '10.1.0.1': late(120, example), '10.1.0.2': late(120, example) }
        ).query('example.com', 'A')
      );
      await vi.advanceTimersByTimeAsync(300);
      const answer = await result;
      expect(answer.server).toBe('10.1.0.2');
      expect(answer.trace?.slice(2).map(hop => [hop.server, hop.error?.message])).toEqual([
        ['10.1.0.1', 'No answer from 10.1.0.1 within 100 ms'],
        ['10.1.0.2', undefined],
      ]);
      expect(settledAt()).toBe(220);
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

    it('follows a DNAME that came without a synthesized CNAME', async () => {
      // the server answers with the DNAME alone, as RFC 6672 servers should not but some do
      const dname: SimulatedServer = query =>
        encodeMessage({
          id: query.id,
          flags: { qr: true, aa: true },
          questions: query.questions,
          answers: [
            {
              name: 'old.example.com',
              type: 39,
              class: 1,
              ttl: 300,
              rdata: encodeName('other.net'),
              section: 'answer',
            },
          ],
        });
      const answer = await resolver({ followCnames: true }, { '10.1.0.1': dname }).query(
        'target.old.example.com',
        'A'
      );

      expect(answer.name).toBe('target.old.example.com');
      expect(answer.records.map(record => record.address)).toEqual(['203.0.113.5']);
      expect(answer.answers.map(record => `${record.name} ${record.type}`)).toEqual([
        'old.example.com DNAME',
        'target.other.net A',
      ]);
      expect(answer.server).toBe('10.3.0.1');

      // without followCnames the walk stops at the DNAME, as it does at a CNAME
      const stopped = await resolver({}, { '10.1.0.1': dname }).query(
        'target.old.example.com',
        'A'
      );
      expect(stopped.server).toBe('10.1.0.1');
      expect(stopped.records).toEqual([]);
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

    it('does not keep a delegation whose TTL is zero', async () => {
      // com hands out example.com's servers with a TTL of 0
      const forgetful: SimulatedServer = query => {
        const reply = com(query);
        if (!(reply instanceof Uint8Array)) return reply;
        const message = decodeMessage(reply);
        return encodeMessage({
          ...message,
          authorities: message.authorities.map(record => ({ ...record, ttl: 0 })),
        });
      };
      const iterative = resolver({}, { '10.0.1.1': forgetful, '10.0.1.2': forgetful });
      await iterative.query('example.com', 'A');
      network.queries.length = 0;
      await iterative.query('example.com', 'A');
      // com is still known, example.com is asked about again
      expect(network.log()).toEqual(['10.0.1.1 example.com A', '10.1.0.1 example.com A']);
    });

    it('looks up a nameserver address again once its own TTL runs out', async () => {
      vi.useFakeTimers({ toFake: ['Date'] });
      try {
        const iterative = resolver();
        await iterative.query('glueless.com', 'A');
        network.queries.length = 0;
        // ns1.dnshost.net's address has a TTL of 300; the delegation to it, two days
        vi.setSystemTime(Date.now() + 299_000);
        await iterative.query('glueless.com', 'A');
        expect(network.log()).toEqual(['10.2.0.53 glueless.com A']);
        network.queries.length = 0;
        vi.setSystemTime(Date.now() + 2000);
        await iterative.query('glueless.com', 'A');
        expect(network.log()).toEqual(['10.2.0.1 ns1.dnshost.net A', '10.2.0.53 glueless.com A']);
      } finally {
        vi.useRealTimers();
      }
    });

    it('looks up a nameserver address again after a lookup that failed', async () => {
      let down = true;
      const flaky: SimulatedServer = query =>
        down ? new ConnectionError('Cannot reach 10.2.0.1') : dnshost(query);
      const iterative = resolver({}, { '10.2.0.1': flaky });
      await expect(iterative.query('glueless.com', 'A')).rejects.toThrow(
        'No usable nameserver address for glueless.com'
      );
      down = false;
      const answer = await iterative.query('glueless.com', 'A');
      expect(answer.records.map(record => record.address)).toEqual(['192.0.2.77']);
    });

    it('lists the failures of a nameserver lookup, shared or not, on the error', async () => {
      const down: SimulatedServer = () => new ConnectionError('Cannot reach 10.2.0.1');
      const failed = async (options: AuthoritativeResolverOptions) => {
        const error = (await resolver(options, { '10.2.0.1': down })
          .query('glueless.com', 'A')
          .catch(e => e)) as ConnectionError;
        return error.failures?.map(failure => [failure.server, failure.error.name]);
      };
      const alone = await failed({ nameserverCache: false });
      expect(alone).toContainEqual(['10.2.0.1', 'ConnectionError']);
      expect(await failed({})).toEqual(alone);

      // a query that joined the lookup another started hears of the same failures
      const shared = resolver({}, { '10.2.0.1': down });
      const errors = (await Promise.all(
        ['A', 'MX'].map(type => shared.query('glueless.com', type).catch(e => e))
      )) as ConnectionError[];
      for (const error of errors) {
        expect(error.failures?.map(failure => [failure.server, failure.error.name])).toContainEqual(
          ['10.2.0.1', 'ConnectionError']
        );
      }
    });

    it('keeps nameserver addresses when told to remember no delegations', async () => {
      const iterative = resolver({ cache: false });
      await iterative.query('glueless.com', 'A');
      const second = await iterative.query('glueless.com', 'A');
      // the second walk starts at the root again, and asks ns1.dnshost.net straight away
      expect(network.log().slice(6)).toEqual([
        '10.0.0.1 glueless.com A',
        '10.0.1.1 glueless.com A',
        '10.2.0.53 glueless.com A',
      ]);
      expect(second.trace?.map(hop => hop.zone)).toEqual(['.', 'com', 'glueless.com']);
      expect(second.serverName).toBe('ns1.dnshost.net');
      expect(network.queries.filter(query => query.name === 'ns1.dnshost.net')).toHaveLength(3);
    });

    it('looks a nameserver up for every query when told to remember no addresses', async () => {
      const iterative = resolver({ cache: false, nameserverCache: false });
      await iterative.query('glueless.com', 'A');
      await iterative.query('glueless.com', 'A');
      expect(network.queries.filter(query => query.name === 'ns1.dnshost.net')).toHaveLength(6);
    });

    it('forgets nameserver addresses on clearCache', async () => {
      const iterative = resolver({ cache: false });
      await iterative.query('glueless.com', 'A');
      iterative.clearCache();
      await iterative.query('glueless.com', 'A');
      expect(network.queries.filter(query => query.name === 'ns1.dnshost.net')).toHaveLength(6);
    });

    it('shares one lookup of a nameserver among queries asked at the same time', async () => {
      const slow =
        (server: SimulatedServer): SimulatedServer =>
        async query => {
          await new Promise(resolve => setTimeout(resolve, 5));
          return server(query);
        };
      const iterative = resolver({ cache: false }, { '10.2.0.1': slow(dnshost) });
      const answers = await Promise.all(
        ['A', 'MX', 'TXT'].map(type => iterative.query('glueless.com', type))
      );
      expect(answers.map(answer => answer.serverName)).toEqual([
        'ns1.dnshost.net',
        'ns1.dnshost.net',
        'ns1.dnshost.net',
      ]);
      expect(network.log().filter(line => line.includes('ns1.dnshost.net'))).toEqual([
        '10.0.0.1 ns1.dnshost.net A',
        '10.0.2.1 ns1.dnshost.net A',
        '10.2.0.1 ns1.dnshost.net A',
      ]);
    });

    it('tells each query only of the queries it sent', async () => {
      const iterative = resolver({ cache: false });
      const seen: Record<string, string[]> = { A: [], MX: [] };
      await Promise.all(
        (['A', 'MX'] as const).map(type =>
          iterative.query('glueless.com', type, {
            onEvent: event => {
              if (event.event === 'query')
                seen[type].push(`${event.server} ${event.query} ${event.type}`);
            },
          })
        )
      );
      // A met ns1.dnshost.net first and looked it up; MX waited for that lookup
      expect(seen.A).toEqual([
        '10.0.0.1 glueless.com A',
        '10.0.1.1 glueless.com A',
        '10.0.0.1 ns1.dnshost.net A',
        '10.0.2.1 ns1.dnshost.net A',
        '10.2.0.1 ns1.dnshost.net A',
        '10.2.0.53 glueless.com A',
      ]);
      expect(seen.MX).toEqual([
        '10.0.0.1 glueless.com MX',
        '10.0.1.1 glueless.com MX',
        '10.2.0.53 glueless.com MX',
      ]);
    });

    describe('a lookup shared by queries with different time left', () => {
      // on a fake clock, so the timers and the clock the walk reads agree
      beforeEach(() => vi.useFakeTimers());
      afterEach(() => vi.useRealTimers());

      it('keeps looking for a query with time left after the one that started it gives up', async () => {
        // dnshost.net's server takes 150 ms. A starts the lookup with 100 ms to live; B
        // joins it 50 ms later with plenty left
        const iterative = resolver(
          { cache: false, timeout: 500, totalTimeout: 1000 },
          { '10.2.0.1': late(150, dnshost) }
        );
        const first = iterative.query('glueless.com', 'A', { totalTimeout: 100 });
        first.catch(() => {});
        await vi.advanceTimersByTimeAsync(50);
        const second = iterative.query('glueless.com', 'MX');
        second.catch(() => {});
        await vi.advanceTimersByTimeAsync(1000);

        await expect(first).rejects.toBeInstanceOf(TimeoutError);
        const answer = await second;
        expect(answer.serverName).toBe('ns1.dnshost.net');
        // still one lookup between them
        expect(network.log().filter(line => line.includes('ns1.dnshost.net'))).toEqual([
          '10.0.0.1 ns1.dnshost.net A',
          '10.0.2.1 ns1.dnshost.net A',
          '10.2.0.1 ns1.dnshost.net A',
        ]);
      });

      it('looks a nameserver up again for a query with time left when the shared lookup ran out of its own', async () => {
        // the lookup has the resolver's 200 ms. B joins it with 1000 ms of its own, sees it
        // run out, and looks the nameserver up itself, by when dnshost.net answers
        let silent = true;
        const iterative = resolver(
          { cache: false, timeout: 500, totalTimeout: 200 },
          { '10.2.0.1': query => (silent ? undefined : dnshost(query)) }
        );
        const first = iterative.query('glueless.com', 'A');
        first.catch(() => {});
        await vi.advanceTimersByTimeAsync(150);
        const second = iterative.query('glueless.com', 'MX', { totalTimeout: 1000 });
        second.catch(() => {});
        await vi.advanceTimersByTimeAsync(40);
        silent = false;
        await vi.advanceTimersByTimeAsync(1000);

        await expect(first).rejects.toBeInstanceOf(TimeoutError);
        const answer = await second;
        expect(answer.serverName).toBe('ns1.dnshost.net');
      });

      it('stops a shared lookup once every query waiting on it has given up', async () => {
        const iterative = resolver(
          { cache: false, timeout: 5000, totalTimeout: 10_000 },
          { '10.2.0.1': late(1000, dnshost) }
        );
        const pending = iterative.query('glueless.com', 'A', { totalTimeout: 100 });
        pending.catch(() => {});
        await vi.advanceTimersByTimeAsync(100);
        await expect(pending).rejects.toBeInstanceOf(TimeoutError);
        // a later query does not join the abandoned lookup; it starts its own
        await vi.advanceTimersByTimeAsync(10);
        const later = iterative.query('glueless.com', 'MX');
        later.catch(() => {});
        await vi.advanceTimersByTimeAsync(2000);
        expect((await later).serverName).toBe('ns1.dnshost.net');
        expect(network.log().filter(line => line === '10.2.0.1 ns1.dnshost.net A')).toHaveLength(2);
      });
    });
  });

  describe('delegations shared between queries', () => {
    const zones = (answer: { trace?: readonly { zone: string }[] }) =>
      answer.trace?.map(hop => hop.zone);
    const asked = (prefix: string) =>
      network.queries.filter(query => query.server.startsWith(prefix)).length;

    it('walks a fresh query from the root, and the next query from what it learned', async () => {
      const iterative = resolver();
      const first = await iterative.query('example.com', 'A', { fresh: true });
      const second = await iterative.query('example.com', 'MX', { fresh: true });
      expect(zones(first)).toEqual(['.', 'com', 'example.com']);
      // every server on the way again, though the resolver knows the zone
      expect(zones(second)).toEqual(['.', 'com', 'example.com']);
      network.queries.length = 0;
      const later = await iterative.query('deep.sub.example.com', 'TXT');
      expect(network.log()).toEqual(['10.1.0.1 deep.sub.example.com TXT']);
      expect(zones(later)).toEqual(['example.com']);
    });

    it('asks the root and com once for 50 names under one zone asked at the same time', async () => {
      const iterative = resolver();
      const answers = await Promise.all(
        Array.from({ length: 50 }, (_, index) => iterative.query(`n${index}.example.com`, 'A'))
      );
      expect(asked('10.0.0.')).toBe(1);
      expect(asked('10.0.1.')).toBe(1);
      expect(asked('10.1.0.')).toBe(50);
      expect(answers.every(answer => answer.rcodeName === 'NXDOMAIN')).toBe(true);
      // the first walked the whole way; the others waited for it and asked only the zone
      expect(zones(answers[0])).toEqual(['.', 'com', 'example.com']);
      expect(answers.slice(1).every(answer => zones(answer)?.join() === 'example.com')).toBe(true);
    });

    it('asks the root and com once per fresh query, and once for all the others', async () => {
      const iterative = resolver();
      const types = ['A', 'MX', 'TXT', 'NS', 'SOA'];
      const answers = await Promise.all([
        ...types.map(type => iterative.query('example.com', type, { fresh: true })),
        ...Array.from({ length: 45 }, (_, index) => iterative.query(`n${index}.example.com`, 'A')),
      ]);
      expect(asked('10.0.0.')).toBe(5);
      expect(asked('10.0.1.')).toBe(5);
      expect(answers.slice(0, 5).every(answer => zones(answer)?.[0] === '.')).toBe(true);
      expect(answers.slice(5).every(answer => zones(answer)?.join() === 'example.com')).toBe(true);
    });

    it('does not wait at the zone above a name for another question about the same name', async () => {
      // com may answer for example.com itself, so each type asks it
      const iterative = resolver();
      await Promise.all(['A', 'MX'].map(type => iterative.query('example.com', type)));
      expect(asked('10.0.0.')).toBe(1);
      expect(asked('10.0.1.')).toBe(2);
    });

    it('keeps the delegations a walk from somewhere else finds to itself', async () => {
      const iterative = resolver();
      await iterative.query('example.com', 'A', { startAt: [{ ipv4: '10.0.1.1' }] });
      network.queries.length = 0;
      await iterative.query('example.com', 'MX');
      expect(network.log()).toEqual([
        '10.0.0.1 example.com MX',
        '10.0.1.1 example.com MX',
        '10.1.0.1 example.com MX',
      ]);
    });

    it('forgets the delegations it learned on clearCache', async () => {
      const iterative = resolver();
      await iterative.query('example.com', 'A', { fresh: true });
      iterative.clearCache();
      const answer = await iterative.query('example.com', 'MX');
      expect(zones(answer)).toEqual(['.', 'com', 'example.com']);
    });

    describe('a waiter with more time than the query it waits on', () => {
      beforeEach(() => vi.useFakeTimers());
      afterEach(() => vi.useRealTimers());

      it('asks for itself once the other query gives up', async () => {
        // com's servers take 150 ms. The first query has 100 ms; the second waits for it at
        // com, sees it give up, and asks com itself
        const iterative = resolver(
          { timeout: 500, totalTimeout: 1000 },
          { '10.0.1.1': late(150, com), '10.0.1.2': late(150, com) }
        );
        const first = iterative.query('example.com', 'A', { fresh: true, totalTimeout: 100 });
        first.catch(() => {});
        const second = iterative.query('deep.sub.example.com', 'TXT');
        second.catch(() => {});
        await vi.advanceTimersByTimeAsync(1000);

        await expect(first).rejects.toBeInstanceOf(TimeoutError);
        const answer = await second;
        expect(answer.records.map(record => record.strings)).toEqual([['hello']]);
        // it waited at the root, which answered the first query at once, and asked from com
        expect(zones(answer)).toEqual(['com', 'example.com']);
        expect(asked('10.0.0.')).toBe(1);
        expect(asked('10.0.1.')).toBe(2);
      });

      it('gives up when its own time runs out while it waits', async () => {
        const iterative = resolver(
          { timeout: 500, totalTimeout: 1000 },
          { '10.0.1.1': late(400, com), '10.0.1.2': late(400, com) }
        );
        const first = iterative.query('example.com', 'A', { fresh: true });
        first.catch(() => {});
        const second = iterative.query('deep.sub.example.com', 'TXT', { totalTimeout: 100 });
        second.catch(() => {});
        await vi.advanceTimersByTimeAsync(1000);

        await expect(second).rejects.toBeInstanceOf(TimeoutError);
        expect((await first).records.map(record => record.address)).toEqual(['192.0.2.1']);
        // it never asked com itself
        expect(asked('10.0.1.')).toBe(1);
      });
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
      const answer = await resolver(
        { addressFamily: 'both' },
        { '10.1.0.1': undefined, '10.1.0.2': undefined }
      ).query('example.com', 'A');
      expect(answer.server).toBe('2001:db8::1');
      expect(answer.serverName).toBe('ns1.example.com');
    });

    it("asks the zone's next server before a server's second address", async () => {
      // ns1 has an IPv4 and an IPv6 address and says nothing on either. The time it is
      // given would be gone on its two addresses, so ns2 is asked after its first
      const silent = () => undefined;
      const answer = await resolver(
        { addressFamily: 'both', timeout: 50, totalTimeout: 90 },
        { '10.1.0.1': silent, '2001:db8::1': silent }
      ).query('example.com', 'A');
      expect(answer.server).toBe('10.1.0.2');
      expect(answer.trace?.map(hop => [hop.server, hop.error?.name]).slice(2)).toEqual([
        ['10.1.0.1', 'TimeoutError'],
        ['10.1.0.2', undefined],
      ]);
    });

    it("comes back to a server's second address when the zone's others fail", async () => {
      const answer = await resolver(
        { addressFamily: 'both' },
        { '10.1.0.1': undefined, '10.1.0.2': undefined }
      ).query('example.com', 'A');
      expect(network.log().slice(2)).toEqual([
        '10.1.0.1 example.com A',
        '10.1.0.2 example.com A',
        '2001:db8::1 example.com A',
      ]);
      expect(answer.server).toBe('2001:db8::1');
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
  describe('defaults', () => {
    afterEach(() => {
      vi.restoreAllMocks();
    });

    it('tries servers in a random order', async () => {
      // with the draw always at the bottom, the shuffle reverses two servers; at the top it
      // leaves them as they are
      vi.spyOn(Math, 'random').mockReturnValue(0);
      await resolver().query('example.com', 'A');
      expect(network.log()).toEqual([
        '10.0.0.2 example.com A',
        '10.0.1.2 example.com A',
        '10.1.0.2 example.com A',
      ]);

      vi.spyOn(Math, 'random').mockReturnValue(0.999);
      await resolver().query('example.com', 'A');
      expect(network.log()).toEqual([
        '10.0.0.1 example.com A',
        '10.0.1.1 example.com A',
        '10.1.0.1 example.com A',
      ]);
    });

    it('puts IPv4 first whatever the shuffle draws', async () => {
      // with the draw always at the bottom, every list of two is reversed: ns2 before ns1,
      // and ns1's IPv6 address before its IPv4 one, until IPv4 is put first
      vi.spyOn(Math, 'random').mockReturnValue(0);
      const answer = await resolver(
        { addressFamily: 'both' },
        { '10.1.0.1': undefined, '10.1.0.2': undefined }
      ).query('example.com', 'A');
      expect(network.log().slice(2)).toEqual([
        '10.1.0.2 example.com A',
        '10.1.0.1 example.com A',
        '2001:db8::1 example.com A',
      ]);
      expect(answer.server).toBe('2001:db8::1');
    });

    it('uses both address families, IPv4 first', async () => {
      const answer = await resolver(
        { addressFamily: undefined },
        { '10.1.0.1': undefined, '10.1.0.2': undefined }
      ).query('example.com', 'A');
      expect(answer.server).toBe('2001:db8::1');
      expect(network.log().slice(2)).toEqual([
        '10.1.0.1 example.com A',
        '10.1.0.2 example.com A',
        '2001:db8::1 example.com A',
      ]);
    });

    it('lists what went wrong at every server on the error a failed walk throws', async () => {
      const error = await resolver(
        {},
        { '10.1.0.1': undefined, '10.1.0.2': () => new ConnectionError('reset') }
      )
        .query('example.com', 'A')
        .catch((caught: unknown) => caught);
      // the first failure is thrown, as its own class
      expect(error).toBeInstanceOf(ConnectionError);
      const { failures } = error as ConnectionError;
      expect(failures?.map(failure => [failure.server, failure.error.name])).toEqual([
        ['10.1.0.1', 'ConnectionError'],
        ['10.1.0.2', 'ConnectionError'],
      ]);
      expect(failures?.[0].error).toBe(error);
    });

    it('lists a server that refused among the failures', async () => {
      const refusing = () => encodeMessage({ id: 0, flags: { qr: true }, rcode: 5 });
      const reset = () => new ConnectionError('reset');
      const error = await resolver(
        {},
        { '10.0.0.1': refusing, '10.0.1.1': reset, '10.0.1.2': reset }
      )
        .query('example.com', 'A')
        .catch((caught: unknown) => caught);
      expect(error).toBeInstanceOf(ConnectionError);
      const { failures } = error as ConnectionError;
      expect(failures?.map(failure => [failure.server, failure.error.name])).toEqual([
        ['10.0.0.1', 'InvalidResponseError'],
        ['10.0.1.1', 'ConnectionError'],
        ['10.0.1.2', 'ConnectionError'],
      ]);
      expect(failures?.[0].error).toMatchObject({ rcode: 5, rcodeName: 'REFUSED' });
    });

    it('hands back names with no trailing dot, in the case the server sent', async () => {
      const parent = zoneServer({
        zone: 'com',
        delegations: { 'Cased.COM': { 'ns1.cased.com': ['10.7.0.1'] } },
      });
      const zone = zoneServer({ zone: 'cased.com', records: [['cased.com', 'A', '192.0.2.7']] });
      const answer = await resolver({}, { '10.0.1.1': parent, '10.7.0.1': zone }).query(
        'Cased.Com.',
        'A'
      );
      expect(answer.name).toBe('Cased.Com');
      expect(answer.trace?.map(hop => [hop.zone, hop.referral])).toEqual([
        ['.', 'com'],
        ['com', 'Cased.COM'],
        ['Cased.COM', undefined],
      ]);
    });

    it('limits queries to 8 at once to one server address', async () => {
      let inFlight = 0;
      let most = 0;
      const counted: SimulatedServer = async query => {
        inFlight++;
        most = Math.max(most, inFlight);
        await new Promise(resolve => setTimeout(resolve, 5));
        inFlight--;
        return root(query);
      };
      const shared = resolver({ cache: false }, { '10.0.0.1': counted });
      const names = Array.from({ length: 12 }, (_, index) => `n${index}.example.com`);
      await Promise.all(names.map(name => shared.query(name, 'A')));
      expect(most).toBe(8);

      most = 0;
      const open = resolver({ cache: false, serverConcurrency: 0 }, { '10.0.0.1': counted });
      await Promise.all(names.map(name => open.query(name, 'A')));
      expect(most).toBe(12);
    });

    it('forgets the names it learned on clearCache, and keeps no more than its bound', async () => {
      const iterative = resolver();
      await iterative.query('example.com', 'A');
      const names = (iterative as unknown as { names: Map<string, string> }).names;
      expect(names.get('10.1.0.1')).toBe('ns1.example.com');
      iterative.clearCache();
      expect(names.size).toBe(0);

      const learn = (
        iterative as unknown as { learnName(address: string, name: string): void }
      ).learnName.bind(iterative);
      for (let index = 0; index < 10_005; index++) learn(`10.${index}`, `ns${index}.test`);
      expect(names.size).toBe(10_000);
      // the oldest went first
      expect(names.has('10.0')).toBe(false);
      expect(names.get('10.10004')).toBe('ns10004.test');
    });
  });
});
