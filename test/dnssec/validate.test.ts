import { afterEach, describe, expect, it, vi } from 'vitest';
import { AuthoritativeResolver, Resolver } from '../../src/index';
import type { Answer } from '../../src/index';
import { late, simulateNetwork, truncatedOverUdp } from '../support/simulated-network';
import type { SimulatedServer } from '../support/simulated-network';
import { ecdsaKey, revokedKey, signedNetwork, unverifiableKey } from '../support/signed-zones';
import type { SignedZone } from '../support/signed-zones';
import { computeDsDigest } from '../../src/dnssec/canonical';
import { toHex } from '../../src/wire/bytes';
import { decodeMessage, encodeMessage, encodeName } from '../../src/wire/index';

// validation end to end: signed zones built in memory, served over the simulated network,
// asked through both resolvers with `validate: true`

const DAY = 86_400_000;

function setUp(zones: SignedZone[]) {
  const signed = signedNetwork(zones);
  const network = simulateNetwork(signed.servers);
  const authoritative = new AuthoritativeResolver({
    transports: network.transports,
    rootServers: signed.rootServers,
    trustAnchors: signed.trustAnchors,
    validate: true,
  });
  const recursive = new Resolver({
    transports: network.transports,
    servers: [signed.recursive],
    trustAnchors: signed.trustAnchors,
    validate: true,
  });
  return { signed, network, authoritative, recursive };
}

// both resolvers, asked the same question, and what each made of it
async function both(zones: SignedZone[], name: string, type: string) {
  const { authoritative, recursive } = setUp(zones);
  return Promise.all([authoritative.query(name, type), recursive.query(name, type)]);
}

const root: SignedZone = { zone: '.' };
const tld: SignedZone = { zone: 'example' };

function expectStatus(answers: Answer[], status: string, code?: string) {
  for (const answer of answers) {
    expect(
      answer.security?.status,
      `${answer.server}: ${JSON.stringify(answer.security?.reason)}`
    ).toBe(status);
    if (code) expect(answer.security?.reason.code).toBe(code);
  }
}

afterEach(() => {
  vi.useRealTimers();
});

describe('validate: a signed answer', () => {
  it('is secure when every link from the root verifies', async () => {
    const answers = await both(
      [root, tld, { zone: 'secure.example', records: [['www.secure.example', 'A', '192.0.2.1']] }],
      'www.secure.example',
      'A'
    );
    expectStatus(answers, 'secure', 'verified');
    for (const answer of answers) {
      expect(answer.records).toMatchObject([{ type: 'A', address: '192.0.2.1' }]);
      expect(
        answer.security?.chain.filter(link => link.kind === 'keys').map(link => link.zone)
      ).toEqual(['.', 'example', 'secure.example']);
      expect(answer.security?.failure).toBeUndefined();
    }
  });

  it('leaves the answer alone without `validate`', async () => {
    const signed = signedNetwork([
      root,
      tld,
      { zone: 'secure.example', records: [['www.secure.example', 'A', '192.0.2.1']] },
    ]);
    const network = simulateNetwork(signed.servers);
    const resolver = new AuthoritativeResolver({
      transports: network.transports,
      rootServers: signed.rootServers,
    });
    const answer = await resolver.query('www.secure.example', 'A');
    expect(answer.security).toBeUndefined();
    expect(network.log().some(line => line.endsWith('DNSKEY') || line.endsWith(' DS'))).toBe(false);
    expect(answer.answers.map(record => record.type)).toEqual(['A']);
  });
});

const secure = (zone: string, records: SignedZone['records'] = []): SignedZone => ({
  zone,
  records,
});

// a server that truncates its answers about `type` over UDP, records and signatures kept,
// and cannot be reached over TCP
function truncating(server: SimulatedServer, type: number): SimulatedServer {
  const cut = truncatedOverUdp(server);
  return (query, transport) =>
    query.questions[0].type === type ? cut(query, transport) : server(query, transport);
}

describe('validate: a truncated answer whose TCP retry failed', () => {
  const zones = [root, tld, secure('secure.example', [['www.secure.example', 'A', '192.0.2.1']])];

  it('is indeterminate from a recursive resolver, never secure', async () => {
    const signed = signedNetwork(zones);
    signed.servers[signed.recursive] = truncating(signed.servers[signed.recursive], 1);
    const network = simulateNetwork(signed.servers);
    const resolver = new Resolver({
      transports: network.transports,
      servers: [signed.recursive],
      trustAnchors: signed.trustAnchors,
      validate: true,
    });
    const answer = await resolver.query('www.secure.example', 'A');
    expect(answer.flags.tc).toBe(true);
    expect(answer.records).toMatchObject([{ type: 'A', address: '192.0.2.1' }]);
    expect(answer.security?.status).toBe('indeterminate');
    expect(answer.security?.reason).toMatchObject({ code: 'response-missing' });
    expect(answer.security?.failure).toMatchObject({ name: 'www.secure.example', type: 'A' });
  });

  it('is indeterminate from the zone server', async () => {
    const signed = signedNetwork(zones);
    // secure.example is the third zone
    signed.servers['10.53.0.3'] = truncating(signed.servers['10.53.0.3'], 1);
    const network = simulateNetwork(signed.servers);
    const resolver = new AuthoritativeResolver({
      transports: network.transports,
      rootServers: signed.rootServers,
      trustAnchors: signed.trustAnchors,
      validate: true,
    });
    const answer = await resolver.query('www.secure.example', 'A');
    expect(answer.flags.tc).toBe(true);
    expect(answer.tcpFallbackError?.name).toBe('ConnectionError');
    expect(answer.security?.status).toBe('indeterminate');
    expect(answer.security?.reason).toMatchObject({ code: 'response-missing' });
  });

  it('leaves a key set it truncated undecided, not bogus', async () => {
    const signed = signedNetwork(zones);
    // DNSKEY = 48
    signed.servers[signed.recursive] = truncating(signed.servers[signed.recursive], 48);
    const network = simulateNetwork(signed.servers);
    const resolver = new Resolver({
      transports: network.transports,
      servers: [signed.recursive],
      trustAnchors: signed.trustAnchors,
      validate: true,
    });
    const answer = await resolver.query('www.secure.example', 'A');
    expect(answer.flags.tc).toBe(false);
    expect(answer.security?.status).toBe('indeterminate');
    expect(answer.security?.reason).toMatchObject({ code: 'response-missing' });
  });

  it('takes the outcome of a zone that does not sign', async () => {
    const signed = signedNetwork([
      root,
      tld,
      { zone: 'plain.example', unsigned: true, records: [['www.plain.example', 'A', '192.0.2.9']] },
    ]);
    signed.servers[signed.recursive] = truncating(signed.servers[signed.recursive], 1);
    const network = simulateNetwork(signed.servers);
    const resolver = new Resolver({
      transports: network.transports,
      servers: [signed.recursive],
      trustAnchors: signed.trustAnchors,
      validate: true,
    });
    const answer = await resolver.query('www.plain.example', 'A');
    expect(answer.flags.tc).toBe(true);
    expect(answer.security?.status).toBe('insecure');
  });
});

describe('validate: aliases', () => {
  it('follows a CNAME into another secure zone', async () => {
    const zones = [
      root,
      tld,
      secure('a.example', [['www.a.example', 'CNAME', 'host.b.example']]),
      secure('b.example', [['host.b.example', 'A', '192.0.2.7']]),
    ];
    const signed = signedNetwork(zones);
    const network = simulateNetwork(signed.servers);
    const options = { transports: network.transports, trustAnchors: signed.trustAnchors };
    const authoritative = new AuthoritativeResolver({
      ...options,
      rootServers: signed.rootServers,
      validate: true,
      followCnames: true,
    });
    const recursive = new Resolver({ ...options, servers: [signed.recursive], validate: true });
    const answers = await Promise.all([
      authoritative.query('www.a.example', 'A'),
      recursive.query('www.a.example', 'A'),
    ]);
    expectStatus(answers, 'secure', 'verified');
    for (const answer of answers) {
      expect(answer.records).toMatchObject([{ name: 'host.b.example', address: '192.0.2.7' }]);
      const data = answer.security!.chain.filter(link => link.kind === 'rrset');
      expect(data.map(link => [link.zone, link.type])).toEqual([
        ['a.example', 'CNAME'],
        ['b.example', 'A'],
      ]);
    }
  });

  it('is insecure when the CNAME leads into an unsigned zone', async () => {
    const [authoritative, recursive] = await both(
      [
        root,
        tld,
        secure('a.example', [['www.a.example', 'CNAME', 'host.plain.example']]),
        {
          zone: 'plain.example',
          unsigned: true,
          records: [['host.plain.example', 'A', '192.0.2.8']],
        },
      ],
      'www.a.example',
      'A'
    );
    // the authoritative resolver stops at the alias, which is signed; the recursive one
    // follows it into the unsigned zone
    expect(authoritative.security?.status).toBe('secure');
    expect(recursive.security?.status).toBe('insecure');
    expect(recursive.security?.reason).toMatchObject({ code: 'no-ds', zone: 'plain.example' });
  });

  it('is bogus when the CNAME leads to a record with a broken signature', async () => {
    const [, recursive] = await both(
      [
        root,
        tld,
        secure('a.example', [['www.a.example', 'CNAME', 'host.b.example']]),
        {
          ...secure('b.example', [['host.b.example', 'A', '192.0.2.7']]),
          inception: new Date(Date.now() - 30 * DAY),
          expiration: new Date(Date.now() - DAY),
        },
      ],
      'www.a.example',
      'A'
    );
    expect(recursive.security?.status).toBe('bogus');
    expect(recursive.security?.failure).toMatchObject({ zone: 'b.example' });
  });

  it('accepts the unsigned CNAME a DNAME synthesizes', async () => {
    const answers = await both(
      [
        root,
        tld,
        secure('old.example', [['old.example', 'DNAME', 'new.example']]),
        secure('new.example', [['www.new.example', 'A', '192.0.2.9']]),
      ],
      'www.old.example',
      'A'
    );
    expectStatus(answers, 'secure');
    const [, recursive] = answers;
    expect(recursive.records).toMatchObject([{ name: 'www.new.example', address: '192.0.2.9' }]);
    expect(
      recursive.security?.chain.filter(link => link.kind === 'rrset').map(l => l.type)
    ).toEqual(['DNAME', 'CNAME', 'A']);
  });

  it('rejects a CNAME beside a DNAME that does not make it', async () => {
    const zones = [root, tld, secure('old.example', [['old.example', 'DNAME', 'new.example']])];
    const signed = signedNetwork(zones);
    const address = Object.keys(signed.servers).find(key => key === '10.53.0.3')!;
    const honest = signed.servers[address];
    // the DNAME is signed, and the CNAME that comes with it points somewhere else
    signed.servers[address] = async query => {
      const reply = await honest(query);
      if (!(reply instanceof Uint8Array)) return reply;
      const message = decodeMessage(reply);
      for (const record of message.answers) {
        if (record.type === 5) record.rdata = encodeName('www.elsewhere.example');
      }
      return encodeMessage(message);
    };
    const network = simulateNetwork(signed.servers);
    const resolver = new AuthoritativeResolver({
      transports: network.transports,
      rootServers: signed.rootServers,
      trustAnchors: signed.trustAnchors,
      validate: true,
    });
    const answer = await resolver.query('www.old.example', 'A');
    expect(answer.security?.status).toBe('bogus');
    expect(answer.security?.reason).toMatchObject({ code: 'rrsigs-missing', type: 'CNAME' });
  });
});

// a server that answers questions for `type` as `server` does, with the records of the type
// (and their signatures) and the authority section taken out, as an attacker on the path
// could
function stripping(server: SimulatedServer, type: number): SimulatedServer {
  return async query => {
    const reply = await server(query);
    if (!(reply instanceof Uint8Array) || query.questions[0].type !== type) return reply;
    const message = decodeMessage(reply);
    message.answers = message.answers.filter(
      record =>
        record.type !== type &&
        !(record.type === 46 && ((record.rdata[0] << 8) | record.rdata[1]) === type)
    );
    message.authorities = [];
    return encodeMessage(message);
  };
}

describe('validate: an alias without its target', () => {
  const zones = [
    root,
    tld,
    secure('a.example', [
      ['www.a.example', 'CNAME', 'host.b.example'],
      ['inner.a.example', 'CNAME', 'host.a.example'],
      ['host.a.example', 'A', '192.0.2.6'],
    ]),
    secure('b.example', [['host.b.example', 'A', '192.0.2.7']]),
  ];

  it('is bogus from a recursive resolver that hands over the signed CNAME alone', async () => {
    const signed = signedNetwork(zones);
    signed.servers[signed.recursive] = stripping(signed.servers[signed.recursive], 1);
    const network = simulateNetwork(signed.servers);
    const resolver = new Resolver({
      transports: network.transports,
      servers: [signed.recursive],
      trustAnchors: signed.trustAnchors,
      validate: true,
    });
    const answer = await resolver.query('www.a.example', 'A');
    expect(answer.rcodeName).toBe('NOERROR');
    expect(answer.records).toEqual([]);
    expect(answer.security?.status).toBe('bogus');
    expect(answer.security?.reason).toMatchObject({ code: 'denial-missing', ede: 12 });
    expect(answer.security?.failure).toMatchObject({ kind: 'denial', name: 'host.b.example' });
  });

  it('is secure from a recursive resolver that proves the target has no records', async () => {
    const signed = signedNetwork([
      root,
      tld,
      secure('a.example', [['www.a.example', 'CNAME', 'host.b.example']]),
      secure('b.example', [['host.b.example', 'TXT', 'only text']]),
    ]);
    const network = simulateNetwork(signed.servers);
    const resolver = new Resolver({
      transports: network.transports,
      servers: [signed.recursive],
      trustAnchors: signed.trustAnchors,
      validate: true,
    });
    const answer = await resolver.query('www.a.example', 'A');
    expect(answer.records).toEqual([]);
    expect(answer.security?.status).toBe('secure');
    expect(answer.security?.chain.at(-1)).toMatchObject({
      kind: 'denial',
      name: 'host.b.example',
      status: 'secure',
    });
  });

  it('is bogus from a zone server that leaves out the data of an alias inside its zone', async () => {
    const signed = signedNetwork(zones);
    // a.example is the third zone
    const server = '10.53.0.3';
    signed.servers[server] = stripping(signed.servers[server], 1);
    const network = simulateNetwork(signed.servers);
    const resolver = new AuthoritativeResolver({
      transports: network.transports,
      rootServers: signed.rootServers,
      trustAnchors: signed.trustAnchors,
      validate: true,
    });
    const answer = await resolver.query('inner.a.example', 'A');
    expect(answer.records).toEqual([]);
    expect(answer.security?.status).toBe('bogus');
    expect(answer.security?.failure).toMatchObject({ kind: 'denial', name: 'host.a.example' });
  });

  it.each([
    ['has no records of the type', 'TXT', 'NOERROR'],
    ['does not exist', 'A', 'NXDOMAIN'],
  ])(
    'is secure from a zone server that proves an alias inside its zone %s',
    async (_case, type, rcode) => {
      const signed = signedNetwork([
        root,
        tld,
        secure('a.example', [
          ['inner.a.example', 'CNAME', 'host.a.example'],
          ['missing.a.example', 'CNAME', 'nothing.a.example'],
          ['host.a.example', 'A', '192.0.2.6'],
        ]),
      ]);
      const network = simulateNetwork(signed.servers);
      const resolver = new AuthoritativeResolver({
        transports: network.transports,
        rootServers: signed.rootServers,
        trustAnchors: signed.trustAnchors,
        validate: true,
      });
      const name = rcode === 'NXDOMAIN' ? 'missing.a.example' : 'inner.a.example';
      const answer = await resolver.query(name, type);
      expect(answer.rcodeName).toBe(rcode);
      expect(answer.records).toEqual([]);
      expect(answer.security?.status).toBe('secure');
      expect(answer.security?.chain.at(-1)).toMatchObject({ kind: 'denial', status: 'secure' });
    }
  );

  it('is secure from a zone server whose alias leads out of its zone', async () => {
    const signed = signedNetwork(zones);
    const network = simulateNetwork(signed.servers);
    const resolver = new AuthoritativeResolver({
      transports: network.transports,
      rootServers: signed.rootServers,
      trustAnchors: signed.trustAnchors,
      validate: true,
    });
    const answer = await resolver.query('www.a.example', 'A');
    expect(answer.security?.status).toBe('secure');
  });
});

describe('validate: proofs of non-existence', () => {
  const zones = (nsec3?: SignedZone['nsec3']): SignedZone[] => [
    root,
    tld,
    { ...secure('secure.example', [['www.secure.example', 'A', '192.0.2.1']]), nsec3 },
  ];

  it.each([
    ['NSEC', undefined],
    ['NSEC3', { iterations: 0 }],
  ])('proves a name does not exist with %s', async (_kind, nsec3) => {
    const answers = await both(zones(nsec3), 'nothing.secure.example', 'A');
    expectStatus(answers, 'secure', 'verified');
    for (const answer of answers) {
      expect(answer.rcodeName).toBe('NXDOMAIN');
      expect(answer.security?.chain.at(-1)).toMatchObject({
        kind: 'denial',
        name: 'nothing.secure.example',
      });
    }
  });

  it.each([
    ['NSEC', undefined],
    ['NSEC3', { iterations: 0 }],
  ])('proves a name has no records of a type with %s', async (_kind, nsec3) => {
    const answers = await both(zones(nsec3), 'www.secure.example', 'TXT');
    expectStatus(answers, 'secure', 'verified');
    for (const answer of answers) expect(answer.records).toEqual([]);
  });

  it('is bogus when a negative answer comes without its proof', async () => {
    const answers = await both(
      [root, tld, { ...secure('secure.example'), dropProofs: true }],
      'nothing.secure.example',
      'A'
    );
    // the DS question for the name finds no proof first: either way, NSEC Missing
    expectStatus(answers, 'bogus');
    for (const answer of answers) expect(answer.security?.reason.ede).toBe(12);
  });

  it('is bogus when the NODATA for an empty non-terminal comes back as NXDOMAIN', async () => {
    const signed = signedNetwork([
      root,
      tld,
      secure('secure.example', [['x.ent.secure.example', 'A', '192.0.2.4']]),
    ]);
    // secure.example is the third zone; the rcode is not signed
    const honest = signed.servers['10.53.0.3'];
    signed.servers['10.53.0.3'] = async query => {
      const reply = await honest(query);
      if (!(reply instanceof Uint8Array) || query.questions[0].type !== 1) return reply;
      const message = decodeMessage(reply);
      message.rcode = 3;
      return encodeMessage(message);
    };
    const network = simulateNetwork(signed.servers);
    const resolver = new AuthoritativeResolver({
      transports: network.transports,
      rootServers: signed.rootServers,
      trustAnchors: signed.trustAnchors,
      validate: true,
    });
    const answer = await resolver.query('ent.secure.example', 'A');
    expect(answer.rcodeName).toBe('NXDOMAIN');
    expect(answer.security?.status).toBe('bogus');
    expect(answer.security?.failure).toMatchObject({ kind: 'denial', name: 'ent.secure.example' });
  });

  // the rcode is not signed: a positive answer relabelled NXDOMAIN keeps its signed RRset
  const relabelled =
    (server: SimulatedServer): SimulatedServer =>
    async query => {
      const reply = await server(query);
      if (!(reply instanceof Uint8Array) || query.questions[0].type !== 1) return reply;
      const message = decodeMessage(reply);
      if (!message.answers.length) return reply;
      message.rcode = 3;
      return encodeMessage(message);
    };

  it('is bogus when a signed positive answer comes back as NXDOMAIN', async () => {
    const signed = signedNetwork(zones());
    // secure.example is the third zone
    signed.servers['10.53.0.3'] = relabelled(signed.servers['10.53.0.3']);
    signed.servers[signed.recursive] = relabelled(signed.servers[signed.recursive]);
    const network = simulateNetwork(signed.servers);
    const options = { transports: network.transports, trustAnchors: signed.trustAnchors };
    const answers = await Promise.all([
      new AuthoritativeResolver({
        ...options,
        rootServers: signed.rootServers,
        validate: true,
      }).query('www.secure.example', 'A'),
      new Resolver({ ...options, servers: [signed.recursive], validate: true }).query(
        'www.secure.example',
        'A'
      ),
    ]);
    for (const answer of answers) {
      expect(answer.rcodeName).toBe('NXDOMAIN');
      expect(answer.records).toMatchObject([{ type: 'A', address: '192.0.2.1' }]);
      expect(answer.security?.status, answer.server).toBe('bogus');
      expect(answer.security?.failure).toMatchObject({
        kind: 'denial',
        name: 'www.secure.example',
      });
    }
  });

  it('proves the end of an alias chain that ends in NXDOMAIN does not exist', async () => {
    const signed = signedNetwork([
      root,
      tld,
      secure('a.example', [['www.a.example', 'CNAME', 'gone.b.example']]),
      secure('b.example', [['host.b.example', 'A', '192.0.2.7']]),
    ]);
    const network = simulateNetwork(signed.servers);
    const resolver = new Resolver({
      transports: network.transports,
      servers: [signed.recursive],
      trustAnchors: signed.trustAnchors,
      validate: true,
    });
    const answer = await resolver.query('www.a.example', 'A');
    expect(answer.rcodeName).toBe('NXDOMAIN');
    expect(answer.security?.status).toBe('secure');
    expect(answer.security?.chain.at(-1)).toMatchObject({
      kind: 'denial',
      name: 'gone.b.example',
      status: 'secure',
    });
  });

  it('is bogus when an alias chain ending in NXDOMAIN comes without the denial', async () => {
    const signed = signedNetwork([
      root,
      tld,
      secure('a.example', [['www.a.example', 'CNAME', 'gone.b.example']]),
      secure('b.example', [['host.b.example', 'A', '192.0.2.7']]),
    ]);
    const honest = signed.servers[signed.recursive];
    signed.servers[signed.recursive] = async query => {
      const reply = await honest(query);
      if (!(reply instanceof Uint8Array) || query.questions[0].type !== 1) return reply;
      return encodeMessage({ ...decodeMessage(reply), authorities: [] });
    };
    const network = simulateNetwork(signed.servers);
    const resolver = new Resolver({
      transports: network.transports,
      servers: [signed.recursive],
      trustAnchors: signed.trustAnchors,
      validate: true,
    });
    const answer = await resolver.query('www.a.example', 'A');
    expect(answer.rcodeName).toBe('NXDOMAIN');
    expect(answer.security?.status).toBe('bogus');
    expect(answer.security?.failure).toMatchObject({ kind: 'denial', name: 'gone.b.example' });
  });

  it('is insecure past the NSEC3 iteration count validators hash (RFC 9276)', async () => {
    const answers = await both(zones({ iterations: 150 }), 'nothing.secure.example', 'A');
    expectStatus(answers, 'insecure', 'nsec3-iterations');
    for (const answer of answers) expect(answer.security?.reason.ede).toBe(27);
  });
});

describe('validate: wildcards', () => {
  it.each([
    ['NSEC', undefined],
    ['NSEC3', { iterations: 0 }],
  ])('accepts an answer from a wildcard with its %s proof', async (_kind, nsec3) => {
    const answers = await both(
      [root, tld, { ...secure('wild.example', [['*.wild.example', 'A', '192.0.2.5']]), nsec3 }],
      'anything.wild.example',
      'A'
    );
    expectStatus(answers, 'secure', 'verified');
    for (const answer of answers) {
      expect(answer.records).toMatchObject([
        { name: 'anything.wild.example', address: '192.0.2.5' },
      ]);
      expect(answer.security?.chain.some(link => link.kind === 'denial')).toBe(true);
    }
  });

  it('is bogus when a wildcard answer comes without the proof the name is not there', async () => {
    const answers = await both(
      [
        root,
        tld,
        {
          ...secure('wild.example', [['*.wild.example', 'A', '192.0.2.5']]),
          dropProofs: 'wildcard',
        },
      ],
      'anything.wild.example',
      'A'
    );
    expectStatus(answers, 'bogus', 'denial-missing');
    for (const answer of answers) {
      expect(answer.security?.failure).toMatchObject({
        kind: 'denial',
        name: 'anything.wild.example',
      });
    }
  });
});

describe('validate: delegations', () => {
  const plain: SignedZone = {
    zone: 'plain.example',
    unsigned: true,
    records: [['www.plain.example', 'A', '192.0.2.3']],
  };

  it('is insecure below a delegation with no DS', async () => {
    const answers = await both([root, tld, plain], 'www.plain.example', 'A');
    expectStatus(answers, 'insecure', 'no-ds');
    for (const answer of answers) {
      expect(answer.security?.reason.zone).toBe('plain.example');
      expect(answer.security?.failure).toBeUndefined();
    }
  });

  it('is insecure below an NSEC3 opt-out range', async () => {
    const answers = await both(
      [root, { zone: 'example', nsec3: { iterations: 0, optOut: true } }, plain],
      'www.plain.example',
      'A'
    );
    expectStatus(answers, 'insecure', 'opt-out');
  });

  it('is bogus when the DS does not match the key', async () => {
    const answers = await both(
      [
        root,
        tld,
        { ...secure('broken.example', [['www.broken.example', 'A', '192.0.2.4']]), badDs: true },
      ],
      'www.broken.example',
      'A'
    );
    expectStatus(answers, 'bogus', 'ds-digest-mismatch');
    for (const answer of answers) {
      expect(answer.security?.failure).toMatchObject({ kind: 'keys', zone: 'broken.example' });
      expect(answer.security?.reason.ede).toBe(9);
    }
  });

  it('is bogus when the parent has a DS and the zone serves no keys', async () => {
    const answers = await both(
      [
        root,
        tld,
        {
          zone: 'unkeyed.example',
          unsigned: true,
          ds: [ecdsaKey()],
          records: [['www.unkeyed.example', 'A', '192.0.2.6']],
        },
      ],
      'www.unkeyed.example',
      'A'
    );
    expectStatus(answers, 'bogus', 'dnskey-missing');
    for (const answer of answers) expect(answer.security?.reason.ede).toBe(9);
  });

  it('treats a zone signed only in an algorithm it cannot verify as unsigned (RFC 6840 §5.2)', async () => {
    const answers = await both(
      [
        root,
        tld,
        {
          zone: 'gost.example',
          keys: [unverifiableKey()],
          records: [['www.gost.example', 'A', '192.0.2.2']],
        },
      ],
      'www.gost.example',
      'A'
    );
    expectStatus(answers, 'insecure', 'unsupported-algorithm');
    for (const answer of answers) {
      expect(answer.security?.reason).toMatchObject({ algorithm: 12, ede: 1 });
    }
  });
});

describe('validate: signatures', () => {
  const now = Date.now();

  it('is bogus when the signatures have expired', async () => {
    const answers = await both(
      [
        root,
        tld,
        {
          ...secure('stale.example', [['www.stale.example', 'A', '192.0.2.1']]),
          inception: new Date(now - 30 * DAY),
          expiration: new Date(now - DAY),
        },
      ],
      'www.stale.example',
      'A'
    );
    expectStatus(answers, 'bogus', 'signature-expired');
    for (const answer of answers) expect(answer.security?.reason.ede).toBe(7);
  });

  it('is bogus when the signatures are not valid yet', async () => {
    const answers = await both(
      [
        root,
        tld,
        {
          ...secure('early.example', [['www.early.example', 'A', '192.0.2.1']]),
          inception: new Date(now + DAY),
          expiration: new Date(now + 30 * DAY),
        },
      ],
      'www.early.example',
      'A'
    );
    expectStatus(answers, 'bogus', 'signature-not-yet-valid');
    for (const answer of answers) expect(answer.security?.reason.ede).toBe(8);
  });

  it('is bogus when a signed zone serves its data without signatures', async () => {
    const answers = await both(
      [
        root,
        tld,
        {
          ...secure('bare.example', [['www.bare.example', 'A', '192.0.2.1']]),
          stripSignatures: true,
        },
      ],
      'www.bare.example',
      'A'
    );
    expectStatus(answers, 'bogus');
    for (const answer of answers) expect(answer.security?.reason.ede).toBe(10);
  });

  it('does not use a trust anchor whose key is published revoked (RFC 5011)', async () => {
    const old = ecdsaKey();
    const current = ecdsaKey();
    const revoked = revokedKey(old);
    const signed = signedNetwork([
      { zone: '.', keys: [revoked, current], signers: [revoked, current] },
      tld,
      secure('secure.example', [['www.secure.example', 'A', '192.0.2.1']]),
    ]);
    const network = simulateNetwork(signed.servers);
    const anchor = (id: string, key: typeof old) => ({
      id,
      keyTag: key.keyTag,
      algorithm: 13,
      digestType: 2,
      digest: toHex(computeDsDigest('.', key.rdata, 2)!),
    });
    const resolver = (trustAnchors: ReturnType<typeof anchor>[]) =>
      new AuthoritativeResolver({
        transports: network.transports,
        rootServers: signed.rootServers,
        trustAnchors,
        validate: true,
      });

    // anchored on both, the old key revoked and still signing: the new one carries the chain
    const both_ = await resolver([anchor('old', old), anchor('current', current)]).query(
      'www.secure.example',
      'A'
    );
    expect(both_.security?.status).toBe('secure');

    // anchored on the old key alone: once it is revoked, nothing anchors the root
    const alone = await resolver([anchor('old', old)]).query('www.secure.example', 'A');
    expect(alone.security?.status).toBe('bogus');
    expect(alone.security?.reason.code).toBe('no-trust-anchor');
  });
});

describe('validate: the key cache', () => {
  const zones: SignedZone[] = [
    root,
    tld,
    {
      ...secure('secure.example', [
        ['www.secure.example', 'A', '192.0.2.1'],
        ['mail.secure.example', 'A', '192.0.2.2'],
      ]),
      keyTtl: 600,
    },
  ];
  const fetches = (network: { log(): string[] }, suffix: string) =>
    network.log().filter(line => line.endsWith(suffix)).length;

  it('keeps validated key sets for their TTL, and asks again after', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    const { network, authoritative } = setUp(zones);

    expect((await authoritative.query('www.secure.example', 'A')).security?.status).toBe('secure');
    expect(fetches(network, ' secure.example DNSKEY')).toBe(1);

    // another name in the same zone: its keys are known
    expect((await authoritative.query('mail.secure.example', 'A')).security?.status).toBe('secure');
    expect(fetches(network, ' secure.example DNSKEY')).toBe(1);

    // past the key set's TTL, it is fetched again
    vi.setSystemTime(Date.now() + 601_000);
    expect((await authoritative.query('mail.secure.example', 'A')).security?.status).toBe('secure');
    expect(fetches(network, ' secure.example DNSKEY')).toBe(2);
  });

  it('forgets them on clearCache()', async () => {
    const { network, recursive } = setUp(zones);
    await recursive.query('www.secure.example', 'A');
    await recursive.query('www.secure.example', 'A');
    expect(fetches(network, ' secure.example DNSKEY')).toBe(1);
    recursive.clearCache();
    await recursive.query('www.secure.example', 'A');
    expect(fetches(network, ' secure.example DNSKEY')).toBe(2);
  });
});

describe('validate: empty answers at names that exist only below or by a wildcard', () => {
  it.each([
    ['NSEC', undefined],
    ['NSEC3', { iterations: 0 }],
  ])(
    'proves a wildcard holds no records of a type with %s (RFC 4035 §3.1.3.4, RFC 5155 §8.7)',
    async (_kind, nsec3) => {
      const answers = await both(
        [root, tld, { ...secure('wild.example', [['*.wild.example', 'A', '192.0.2.5']]), nsec3 }],
        'anything.wild.example',
        'TXT'
      );
      expectStatus(answers, 'secure', 'verified');
      for (const answer of answers) {
        expect(answer.rcodeName).toBe('NOERROR');
        expect(answer.records).toEqual([]);
        expect(answer.security?.chain.at(-1)).toMatchObject({
          kind: 'denial',
          name: 'anything.wild.example',
          type: 'TXT',
        });
      }
    }
  );

  it.each([
    ['NSEC', undefined],
    ['NSEC3', { iterations: 0 }],
  ])('is bogus when the wildcard holds the type it denies, with %s', async (_kind, nsec3) => {
    const signed = signedNetwork([
      root,
      tld,
      {
        ...secure('wild.example', [
          ['*.wild.example', 'TXT', 'here'],
          ['*.wild.example', 'MX', '10 mail.wild.example'],
        ]),
        nsec3,
      },
    ]);
    const honest = signed.servers['10.53.0.3'];
    // the server answers the TXT question with the empty answer for AAAA, which the
    // wildcard does not hold, and its proof
    signed.servers['10.53.0.3'] = async query => {
      const [question] = query.questions;
      if (question.type !== 16) return honest(query);
      const reply = await honest({ ...query, questions: [{ ...question, type: 28 }] });
      if (!(reply instanceof Uint8Array)) return reply;
      return encodeMessage({ ...decodeMessage(reply), questions: query.questions });
    };
    const network = simulateNetwork(signed.servers);
    const resolver = new AuthoritativeResolver({
      transports: network.transports,
      rootServers: signed.rootServers,
      trustAnchors: signed.trustAnchors,
      validate: true,
    });
    const answer = await resolver.query('anything.wild.example', 'TXT');
    expect(answer.records).toEqual([]);
    expect(answer.security?.status).toBe('bogus');
    expect(answer.security?.reason.code).toBe('denial-invalid');
  });

  it.each([
    ['NSEC', undefined],
    ['NSEC3', { iterations: 0 }],
  ])('proves an empty non-terminal holds nothing with %s', async (_kind, nsec3) => {
    const answers = await both(
      [
        root,
        tld,
        { ...secure('secure.example', [['a.b.secure.example', 'A', '192.0.2.1']]), nsec3 },
      ],
      'b.secure.example',
      'A'
    );
    expectStatus(answers, 'secure', 'verified');
    for (const answer of answers) expect(answer.rcodeName).toBe('NOERROR');
  });

  it('answers a question for the wildcard itself without asking for a wildcard proof', async () => {
    const answers = await both(
      [root, tld, secure('wild.example', [['*.wild.example', 'A', '192.0.2.5']])],
      '*.wild.example',
      'A'
    );
    expectStatus(answers, 'secure', 'verified');
    for (const answer of answers) {
      expect(answer.security?.chain.some(link => link.kind === 'denial')).toBe(false);
    }
  });

  it('judges a wildcard proof from one zone beside a denial from another', async () => {
    // a wildcard CNAME in one zone pointing at a name missing from another: the recursive
    // answer carries both zones' proofs
    const signed = signedNetwork([
      root,
      tld,
      { ...secure('a.example', [['*.a.example', 'CNAME', 'gone.b.example']]), nsec3: {} },
      secure('b.example', [['www.b.example', 'A', '192.0.2.7']]),
    ]);
    const network = simulateNetwork(signed.servers);
    const resolver = new Resolver({
      transports: network.transports,
      servers: [signed.recursive],
      trustAnchors: signed.trustAnchors,
      validate: true,
    });
    const answer = await resolver.query('x.a.example', 'A');
    expect(answer.rcodeName).toBe('NXDOMAIN');
    expect(answer.security?.status, JSON.stringify(answer.security?.reason)).toBe('secure');
    expect(
      answer.security?.chain.filter(link => link.kind === 'denial').map(link => link.zone)
    ).toEqual(['a.example', 'b.example']);
  });
});

describe('validate: DS questions', () => {
  const plain: SignedZone = {
    zone: 'plain.example',
    unsigned: true,
    records: [['www.plain.example', 'A', '192.0.2.3']],
  };

  it('is secure when the parent proves an unsigned delegation has no DS', async () => {
    const answers = await both([root, tld, plain], 'plain.example', 'DS');
    expectStatus(answers, 'secure', 'verified');
    for (const answer of answers) {
      expect(answer.records).toEqual([]);
      expect(answer.security?.chain.at(-1)).toMatchObject({ kind: 'denial', zone: 'example' });
    }
  });

  it('is insecure when an opt-out range covers the delegation (RFC 5155 §8.6)', async () => {
    const answers = await both(
      [root, { zone: 'example', nsec3: { iterations: 0, optOut: true } }, plain],
      'plain.example',
      'DS'
    );
    expectStatus(answers, 'insecure', 'opt-out');
  });

  it('is secure for a signed delegation', async () => {
    const answers = await both(
      [root, tld, secure('secure.example', [['www.secure.example', 'A', '192.0.2.1']])],
      'secure.example',
      'DS'
    );
    expectStatus(answers, 'secure', 'verified');
  });
});

describe('validate: opt-out', () => {
  const zone = (optOut: (name: string) => boolean): SignedZone => ({
    ...secure('secure.example', [['www.secure.example', 'A', '192.0.2.1']]),
    nsec3: { iterations: 0, optOut },
  });

  // the chain holds two names, the apex and www: for the missing name below, the apex's
  // NSEC3 matches the closest encloser and www's covers the next closer name
  it('is secure when only the closest encloser NSEC3 sets opt-out (RFC 5155 §8.4)', async () => {
    const answers = await both(
      [root, tld, zone(name => name === 'secure.example')],
      'nothing.secure.example',
      'A'
    );
    expectStatus(answers, 'secure', 'verified');
    for (const answer of answers) expect(answer.rcodeName).toBe('NXDOMAIN');
  });

  it('is insecure when the NSEC3 covering the next closer name sets opt-out', async () => {
    const answers = await both(
      [root, tld, zone(name => name !== 'secure.example')],
      'nothing.secure.example',
      'A'
    );
    expectStatus(answers, 'insecure', 'opt-out');
  });

  it('is insecure for a wildcard answer whose next closer name is in an opt-out range', async () => {
    const answers = await both(
      [
        root,
        tld,
        {
          ...secure('wild.example', [['*.wild.example', 'A', '192.0.2.5']]),
          nsec3: { iterations: 0, optOut: true },
        },
      ],
      'anything.wild.example',
      'A'
    );
    expectStatus(answers, 'insecure', 'opt-out');
  });
});

describe('validate: limits on the work one answer may cause', () => {
  it('gives up on an RRset signed more times over than it will check (KeyTrap)', async () => {
    // ten keys sign everything; the first nine signatures over the A RRset are broken
    const keys = [ecdsaKey(257), ...Array.from({ length: 9 }, () => ecdsaKey(256))];
    const signed = signedNetwork([
      root,
      tld,
      { ...secure('many.example', [['www.many.example', 'A', '192.0.2.1']]), keys },
    ]);
    const honest = signed.servers['10.53.0.3'];
    signed.servers['10.53.0.3'] = async query => {
      const reply = await honest(query);
      if (!(reply instanceof Uint8Array) || query.questions[0].type !== 1) return reply;
      const message = decodeMessage(reply);
      for (const record of message.answers.filter(rr => rr.type === 46).slice(0, 9)) {
        record.rdata = Uint8Array.from(record.rdata);
        record.rdata[record.rdata.length - 1] ^= 0xff;
      }
      return encodeMessage(message);
    };
    const network = simulateNetwork(signed.servers);
    const resolver = new AuthoritativeResolver({
      transports: network.transports,
      rootServers: signed.rootServers,
      trustAnchors: signed.trustAnchors,
      validate: true,
    });
    const answer = await resolver.query('www.many.example', 'A');
    expect(answer.security?.status).toBe('bogus');
    expect(answer.security?.reason).toMatchObject({ code: 'validation-limit', type: 'A', ede: 6 });
  });
});

describe('validate: how long what was learned is kept', () => {
  it('keeps a key set no longer than its signature is valid (RFC 4035 §5.3.3)', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    const { network, authoritative } = setUp([
      root,
      tld,
      {
        ...secure('secure.example', [['www.secure.example', 'A', '192.0.2.1']]),
        keyTtl: 3600,
        expiration: new Date(Date.now() + 120_000),
      },
    ]);
    const dnskeys = () => network.log().filter(line => line.endsWith(' secure.example DNSKEY'));
    expect((await authoritative.query('www.secure.example', 'A')).security?.status).toBe('secure');
    expect(dnskeys()).toHaveLength(1);

    // the TTL says an hour; the signatures run out in two minutes
    vi.setSystemTime(Date.now() + 121_000);
    const later = await authoritative.query('www.secure.example', 'A');
    expect(dnskeys()).toHaveLength(2);
    expect(later.security?.status).toBe('bogus');
    expect(later.security?.reason.code).toBe('signature-expired');
  });
});

// what both resolvers take, to ask either in one loop
interface Asking {
  query(
    name: string,
    type: string,
    options?: { transport?: 'tcp'; port?: number; signal?: AbortSignal }
  ): Promise<Answer>;
}

describe('validate: the chain is asked the way the data was', () => {
  const zones = [root, tld, secure('secure.example', [['www.secure.example', 'A', '192.0.2.1']])];

  it('sends every chain query with the per-query transport and port', async () => {
    const { network, authoritative, recursive } = setUp(zones);
    for (const resolver of [authoritative, recursive] as Asking[]) {
      network.queries.length = 0;
      const answer = await resolver.query('www.secure.example', 'A', {
        transport: 'tcp',
        port: 5353,
      });
      expect(answer.security?.status).toBe('secure');
      expect(network.queries.some(query => query.type === 'DNSKEY')).toBe(true);
      for (const query of network.queries) {
        expect(query).toMatchObject({ transport: 'tcp', port: 5353 });
      }
    }
  });

  it.each(['recursive', 'authoritative'] as const)(
    'rejects with the reason when the %s query is aborted while the chain is fetched',
    async kind => {
      const controller = new AbortController();
      const reason = new Error('never mind');
      const signed = signedNetwork(zones);
      // every server stops answering, and the caller gives up, once the chain is asked for
      for (const [address, server] of Object.entries(signed.servers)) {
        signed.servers[address] = query => {
          if (query.questions[0].type !== 48) return server(query);
          controller.abort(reason);
          return undefined;
        };
      }
      const network = simulateNetwork(signed.servers);
      const resolver: Asking =
        kind === 'recursive'
          ? new Resolver({
              transports: network.transports,
              servers: [signed.recursive],
              trustAnchors: signed.trustAnchors,
              validate: true,
            })
          : new AuthoritativeResolver({
              transports: network.transports,
              rootServers: signed.rootServers,
              trustAnchors: signed.trustAnchors,
              validate: true,
            });
      await expect(
        resolver.query('www.secure.example', 'A', { signal: controller.signal })
      ).rejects.toBe(reason);
    }
  );
});

describe('validate: one deadline for the whole query', () => {
  // each server answers 20 ms after it is asked: the data takes two hops, the chain three
  // more
  const slowNetwork = () => {
    const signed = signedNetwork([root, secure('example', [['www.example', 'A', '192.0.2.1']])]);
    for (const [address, server] of Object.entries(signed.servers)) {
      signed.servers[address] = late(20, server);
    }
    return { signed, network: simulateNetwork(signed.servers) };
  };

  it('gives the chain only what the data left, and times out when it runs out', async () => {
    const { signed, network } = slowNetwork();
    const resolver = new AuthoritativeResolver({
      transports: network.transports,
      rootServers: signed.rootServers,
      trustAnchors: signed.trustAnchors,
      validate: true,
      totalTimeout: 60,
    });
    const started = Date.now();
    const error = (await resolver.query('www.example', 'A').catch(e => e)) as Error;
    const elapsed = Date.now() - started;
    expect(error.name).toBe('TimeoutError');
    expect(error.message).toContain('60 ms');
    expect(elapsed).toBeLessThan(90);
  });

  it('takes the per-query totalTimeout as the deadline too', async () => {
    const { signed, network } = slowNetwork();
    const resolver = new AuthoritativeResolver({
      transports: network.transports,
      rootServers: signed.rootServers,
      trustAnchors: signed.trustAnchors,
      validate: true,
    });
    await expect(resolver.query('www.example', 'A', { totalTimeout: 60 })).rejects.toMatchObject({
      name: 'TimeoutError',
    });
    // with the time it needs, the same query is secure
    const answer = await resolver.query('www.example', 'A', { totalTimeout: 1000 });
    expect(answer.security?.status).toBe('secure');
  });
});
