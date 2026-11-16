import { afterAll, describe, expect, it } from 'vitest';
import { AuthoritativeResolver, Resolver } from '../../src/index';
import type { Answer, Server } from '../../src/index';

// the live suite: the resolvers against the real network. Public resolvers over every
// transport, a walk from the root, and DNSSEC validation of names whose verdict is known,
// each verdict compared with what Cloudflare (1.1.1.1) and Google (8.8.8.8) say: AD set
// for secure, SERVFAIL for bogus, neither for insecure.
//
// not part of `yarn test`. Run it with `yarn test:live`; CI runs
// it on a schedule (.github/workflows/dns-live.yml). A query that throws, or a verdict of
// `indeterminate` because a response never came, is tried once more. A verdict is never
// retried: a wrong one fails the run. Only IPv4 is used, as CI runners have no IPv6

type Verdict = 'secure' | 'insecure' | 'bogus';

interface Case {
  name: string;
  type: string;
  verdict: Verdict;
  // the reason code every validator has to give, where it is worth pinning
  reason?: string;
  // what the case is
  about: string;
}

const CASES: Case[] = [
  // signed zones, from the root down
  { name: 'isc.org', type: 'A', verdict: 'secure', about: 'signed, NSEC' },
  { name: 'ietf.org', type: 'A', verdict: 'secure', about: 'signed by Cloudflare' },
  { name: 'cloudflare.com', type: 'A', verdict: 'secure', about: 'signed by Cloudflare' },
  { name: 'nic.cz', type: 'A', verdict: 'secure', about: 'signed, NSEC3' },
  { name: 'internetsociety.org', type: 'A', verdict: 'secure', about: 'signed' },
  { name: 'iis.se', type: 'A', verdict: 'secure', about: '.se' },
  { name: 'sidn.nl', type: 'A', verdict: 'secure', about: '.nl, NSEC' },
  { name: 'isc.org', type: 'DS', verdict: 'secure', about: 'a DS answer, the parent’s data' },

  // unsigned zones
  {
    name: 'google.com',
    type: 'A',
    verdict: 'insecure',
    reason: 'opt-out',
    about: 'unsigned, under .com’s NSEC3 opt-out',
  },
  {
    name: 'amazon.com',
    type: 'A',
    verdict: 'insecure',
    reason: 'opt-out',
    about: 'unsigned, under .com’s NSEC3 opt-out',
  },
  {
    name: 'google.com',
    type: 'DS',
    verdict: 'insecure',
    reason: 'opt-out',
    about: 'no DS, proven only by an opt-out range',
  },
  {
    name: 'unsigned.extended-dns-errors.com',
    type: 'A',
    verdict: 'insecure',
    reason: 'no-ds',
    about: 'a delegation proven to have no DS',
  },
  {
    name: 'ds-unassigned-digest-algo.extended-dns-errors.com',
    type: 'A',
    verdict: 'insecure',
    reason: 'unsupported-digest',
    about: 'a DS in a digest type nothing computes',
  },

  // broken on purpose
  { name: 'dnssec-failed.org', type: 'A', verdict: 'bogus', about: 'Comcast’s bogus test zone' },
  {
    name: 'sigfail.verteiltesysteme.net',
    type: 'A',
    verdict: 'bogus',
    about: 'a bad signature, behind a CNAME',
  },
  {
    name: 'rrsig-exp-all.extended-dns-errors.com',
    type: 'A',
    verdict: 'bogus',
    reason: 'signature-expired',
    about: 'every signature expired',
  },
  {
    name: 'rrsig-not-yet-all.extended-dns-errors.com',
    type: 'A',
    verdict: 'bogus',
    reason: 'signature-not-yet-valid',
    about: 'every signature not yet valid',
  },
  {
    name: 'no-dnskey-256.extended-dns-errors.com',
    type: 'A',
    verdict: 'bogus',
    about: 'the zone-signing key missing',
  },
  {
    name: 'no-dnskey-257.extended-dns-errors.com',
    type: 'A',
    verdict: 'bogus',
    about: 'the key-signing key missing',
  },
  {
    name: 'ds-bad-tag.extended-dns-errors.com',
    type: 'A',
    verdict: 'bogus',
    about: 'a DS naming no published key',
  },
  {
    name: 'ds-bad-key-algo.extended-dns-errors.com',
    type: 'A',
    verdict: 'bogus',
    about: 'a DS with the wrong algorithm',
  },
  { name: 'fail01.dnssec.works', type: 'A', verdict: 'bogus', about: 'dnssec.works failure 1' },
  { name: 'fail02.dnssec.works', type: 'A', verdict: 'bogus', about: 'dnssec.works failure 2' },
  { name: 'fail03.dnssec.works', type: 'A', verdict: 'bogus', about: 'dnssec.works failure 3' },
  { name: 'fail04.dnssec.works', type: 'A', verdict: 'bogus', about: 'dnssec.works failure 4' },
  { name: 'fail05.dnssec.works', type: 'A', verdict: 'bogus', about: 'dnssec.works failure 5' },
  { name: 'brokendnssec.net', type: 'A', verdict: 'bogus', about: 'a bogus test zone' },

  // names and types that are not there
  {
    name: 'nxdomain-live-check.isc.org',
    type: 'A',
    verdict: 'secure',
    about: 'NXDOMAIN, NSEC',
  },
  {
    name: 'nxdomain-live-check.sidn.nl',
    type: 'A',
    verdict: 'secure',
    about: 'NXDOMAIN, NSEC',
  },
  {
    name: 'nxdomain-live-check.nic.cz',
    type: 'A',
    verdict: 'secure',
    about: 'NXDOMAIN, NSEC3',
  },
  { name: 'isc.org', type: 'TLSA', verdict: 'secure', about: 'NODATA, NSEC' },
  { name: 'nic.cz', type: 'TLSA', verdict: 'secure', about: 'NODATA, NSEC3' },
  {
    name: 'nxdomain-live-check.ietf.org',
    type: 'A',
    verdict: 'secure',
    about: 'Cloudflare’s compact denial: NODATA for a missing name',
  },

  // wildcards and aliases
  {
    name: 'wildcard-live-check.dnsviz.net',
    type: 'A',
    verdict: 'secure',
    about: 'a wildcard CNAME, NSEC',
  },
  {
    name: 'a.b.wildcard-live-check.dnsviz.net',
    type: 'A',
    verdict: 'secure',
    about: 'a wildcard CNAME several labels down',
  },
  {
    name: 'www.icann.org',
    type: 'A',
    verdict: 'secure',
    about: 'a CNAME into another signed zone (cloudflare.net)',
  },
  {
    name: 'www.ripe.net',
    type: 'A',
    verdict: 'insecure',
    about: 'a CNAME into an unsigned zone (edgekey.net)',
  },
];

// ---- the resolvers

// either resolver, as the suite uses it
interface Validating {
  query(name: string, type: string): Promise<Answer>;
  close(): void;
}

const validators: Record<string, Validating> = {
  '1.1.1.1 udp': new Resolver({ servers: ['1.1.1.1'], transport: 'udp', validate: true }),
  '1.1.1.1 tcp': new Resolver({ servers: ['1.1.1.1'], transport: 'tcp', validate: true }),
  '8.8.8.8 udp': new Resolver({ servers: ['8.8.8.8'], transport: 'udp', validate: true }),
  '8.8.8.8 tcp': new Resolver({ servers: ['8.8.8.8'], transport: 'tcp', validate: true }),
  'root': new AuthoritativeResolver({ validate: true, followCnames: true, addressFamily: 'ipv4' }),
};

// what the public resolvers say, asked plainly with DO set: the reference verdict
const references: Record<string, Resolver> = {
  '1.1.1.1': new Resolver({ servers: ['1.1.1.1'], cache: false }),
  '8.8.8.8': new Resolver({ servers: ['8.8.8.8'], cache: false }),
};

// a transient failure is tried once more, after a pause
async function once<T>(attempt: () => Promise<T>, transient: (value: T) => boolean): Promise<T> {
  try {
    const value = await attempt();
    if (!transient(value)) return value;
  } catch {
    // tried again below
  }
  await new Promise(resolve => setTimeout(resolve, 1000));
  return attempt();
}

async function validated(resolver: Validating, { name, type }: Case): Promise<Answer> {
  return once(
    () => resolver.query(name, type),
    answer =>
      answer.security?.status === 'indeterminate' &&
      answer.security.reason.code === 'response-missing'
  );
}

async function referenceVerdict(resolver: Resolver, { name, type }: Case): Promise<Verdict> {
  const answer = await once(
    () => resolver.query(name, type, { dnssecOk: true, authenticData: true }),
    () => false
  );
  if (answer.rcodeName === 'SERVFAIL') return 'bogus';
  return answer.flags.ad ? 'secure' : 'insecure';
}

// ---- the report

const rows: Record<string, string>[] = [];

afterAll(() => {
  for (const resolver of [...Object.values(validators), ...Object.values(references)]) {
    resolver.close();
  }
  // the table of results, for the log, written past vitest's console capture
  if (rows.length === 0) return;
  const columns = Object.keys(rows[0]);
  const line = (cells: string[]) => `| ${cells.join(' | ')} |\n`;
  process.stdout.write(
    '\n' +
      line(columns) +
      line(columns.map(() => '---')) +
      rows.map(row => line(columns.map(column => row[column] ?? ''))).join('')
  );
});

describe('validation against the real network', () => {
  it.each(CASES.map(c => [`${c.name} ${c.type}: ${c.verdict} (${c.about})`, c] as const))(
    '%s',
    async (_title, testCase) => {
      const labels = Object.keys(validators);
      const [answers, refs] = await Promise.all([
        Promise.all(labels.map(label => validated(validators[label], testCase))),
        Promise.all(
          Object.entries(references).map(async ([label, resolver]) => [
            label,
            await referenceVerdict(resolver, testCase),
          ])
        ),
      ]);

      const row: Record<string, string> = {
        name: testCase.name,
        type: testCase.type,
        expected: testCase.verdict,
      };
      answers.forEach((answer, index) => {
        const security = answer.security;
        row[labels[index]] = security ? `${security.status} (${security.reason.code})` : 'none';
      });
      for (const [label, verdict] of refs) row[`ref ${label}`] = verdict;
      rows.push(row);

      // the world still agrees with the table
      for (const [label, verdict] of refs) {
        expect(verdict, `${label} says ${verdict}`).toBe(testCase.verdict);
      }
      // and so does every validator
      answers.forEach((answer, index) => {
        const reason = answer.security?.reason;
        const said = `${labels[index]}: ${JSON.stringify(reason)}`;
        expect(answer.security?.status, said).toBe(testCase.verdict);
        if (testCase.reason) expect(reason?.code, said).toBe(testCase.reason);
      });
    }
  );
});

// ---- the transports and the walk, without validation

const DOH: Record<string, string> = {
  '1.1.1.1': 'https://cloudflare-dns.com/dns-query',
  '8.8.8.8': 'https://dns.google/dns-query',
  '9.9.9.9': 'https://dns.quad9.net/dns-query',
};

describe('the resolver over every transport', () => {
  const resolver = new Resolver({ cache: false });
  afterAll(() => resolver.close());

  const servers: [string, string, string | Server][] = [];
  for (const address of Object.keys(DOH)) {
    servers.push(['udp', address, address], ['tcp', address, address]);
    servers.push(['tls', address, { address }], ['doh', address, DOH[address]]);
  }

  it.each(servers)('answers over %s from %s', async (transport, _address, server) => {
    const answer = await once(
      () =>
        resolver.query('isc.org', 'NS', {
          server,
          ...(transport !== 'doh' && { transport: transport as 'udp' | 'tcp' | 'tls' }),
        }),
      () => false
    );
    expect(answer.rcodeName).toBe('NOERROR');
    expect(answer.transport).toBe(transport);
    expect(answer.records.length).toBeGreaterThan(0);
    expect(answer.records.every(record => record.type === 'NS')).toBe(true);
  });

  it('says a missing name does not exist', async () => {
    const answer = await once(
      () => resolver.query('nxdomain-live-check.isc.org', 'A', { server: '1.1.1.1' }),
      () => false
    );
    expect(answer.rcodeName).toBe('NXDOMAIN');
    expect(answer.records).toEqual([]);
  });
});

describe('the walk from the root', () => {
  const resolver = new AuthoritativeResolver({ addressFamily: 'ipv4' });
  afterAll(() => resolver.close());

  it('follows referrals from the root to the zone’s own servers', async () => {
    const answer = await once(
      () => resolver.query('isc.org', 'NS'),
      () => false
    );
    expect(answer.rcodeName).toBe('NOERROR');
    expect(answer.flags.aa).toBe(true);
    expect(answer.trace?.[0]).toMatchObject({ zone: '.' });
    expect(answer.trace?.map(hop => hop.zone)).toContain('org');
    expect(answer.records.length).toBeGreaterThan(0);
  });

  it('stops at an alias into another zone, and follows it when asked', async () => {
    const stopped = await once(
      () => resolver.query('www.icann.org', 'A'),
      () => false
    );
    expect(stopped.records).toEqual([]);
    expect(stopped.answers.map(record => record.type)).toContain('CNAME');

    const following = new AuthoritativeResolver({ addressFamily: 'ipv4', followCnames: true });
    try {
      const followed = await once(
        () => following.query('www.icann.org', 'A'),
        () => false
      );
      expect(followed.records.length).toBeGreaterThan(0);
    } finally {
      following.close();
    }
  });
});
