import { analyze } from '../../src/dnssec/index';
import fixture from '../fixtures/dnssec.json';
import { ALIAS_INTO_BROKEN_ZONE, DNSSEC_CASES } from '../support/dnssec-cases';
import type { DnssecCase } from '../support/dnssec-cases';
import { replayTransports } from '../support/replay-transports';
import type { RecordedExchange } from '../support/replay-transports';

// the whole analysis, offline: real zones, one per signing algorithm, DS digest type and
// failure state, analyzed over the responses recorded from them and judged against the
// clock they were recorded at. Each case pins the verdict and the reason for it: a zone
// reported broken for the wrong reason is as wrong as one reported sound.
//
// to refresh the recording: yarn run -T tsx scripts/record-dnssec.ts

const exchanges = fixture.exchanges as RecordedExchange[];
const recordedAt = new Date(fixture.recordedAt);

// Ed448 is the one algorithm some runtimes lack (Cloudflare Workers). There a zone signed
// with it cannot be checked, which has to read as indeterminate and never as secure
const hasEd448 = await crypto.subtle.generateKey({ name: 'Ed448' }, false, ['sign', 'verify']).then(
  () => true,
  () => false
);

function expected(dnssecCase: DnssecCase): DnssecCase {
  if (dnssecCase.algorithm === 16 && !hasEd448) {
    return { ...dnssecCase, status: 'indeterminate', findings: ['algorithm-not-supported'] };
  }
  return dnssecCase;
}

async function run(name: string, now = recordedAt) {
  const transports = replayTransports(exchanges);
  const report = await analyze(name, { now, transports });
  return { report, misses: transports.misses };
}

describe('analyze, over recorded zones', () => {
  it.each(DNSSEC_CASES.map(dnssecCase => [dnssecCase.id, dnssecCase] as const))(
    '%s',
    async (_id, given) => {
      const dnssecCase = expected(given);
      const { report, misses } = await run(dnssecCase.name);

      // nothing was asked that the recording does not hold
      expect(misses).toEqual([]);
      expect(report.overallStatus).toBe(dnssecCase.status);

      const slugs = report.findings.map(finding => finding.slug);
      for (const slug of dnssecCase.findings ?? []) expect(slugs).toContain(slug);
      for (const slug of dnssecCase.absent ?? []) expect(slugs).not.toContain(slug);

      // the chain starts at the root, which is always sound, and ends at the zone
      expect(report.chain[0]).toMatchObject({ zone: '.', status: 'secure' });
      const zone = report.chain.at(-1)!;
      if (dnssecCase.algorithm !== undefined) {
        expect(zone.dnskeys.map(key => key.algorithm)).toContain(dnssecCase.algorithm);
      }
      if (dnssecCase.status === 'secure') {
        // secure means every link, not only the last
        expect(report.chain.map(link => link.status)).toEqual(report.chain.map(() => 'secure'));
      }
      if (dnssecCase.status === 'bogus') {
        // a broken zone says where it broke
        expect(report.chain.some(link => link.status === 'bogus' && Boolean(link.reason))).toBe(
          true
        );
      }
    }
  );

  it('has a case for every algorithm the library verifies', () => {
    const covered = new Set(DNSSEC_CASES.map(dnssecCase => dnssecCase.algorithm));
    for (const algorithm of [5, 7, 8, 10, 13, 14, 15, 16]) expect(covered).toContain(algorithm);
  });
});

describe('analyze, and the clock', () => {
  it('finds the same signatures expired when they are read a year later', async () => {
    const later = new Date(recordedAt);
    later.setUTCFullYear(later.getUTCFullYear() + 1);
    const { report } = await run('cloudflare.com', later);
    expect(report.overallStatus).toBe('bogus');
    expect(report.findings.map(finding => finding.slug)).toContain('signature-expired');
  });

  it('finds them not yet valid when they are read a year earlier', async () => {
    const earlier = new Date(recordedAt);
    earlier.setUTCFullYear(earlier.getUTCFullYear() - 1);
    const { report } = await run('cloudflare.com', earlier);
    expect(report.overallStatus).toBe('bogus');
    expect(report.findings.map(finding => finding.slug)).toContain('signature-not-yet-valid');
  });
});

describe('analyze, and what it cannot reach', () => {
  it('does not call a zone secure when its servers cannot be asked', async () => {
    // the same recording without the zone's own answers: the root and the TLD still answer
    const withoutZone = exchanges.filter(
      exchange => !Buffer.from(exchange.query, 'base64').includes(Buffer.from('\ncloudflare'))
    );
    const transports = replayTransports(withoutZone);
    const report = await analyze('cloudflare.com', { now: recordedAt, transports });
    expect(report.overallStatus).not.toBe('secure');
  });
});

describe('analyze, and an alias into another zone', () => {
  // a known limit, pinned so that changing it is a decision: the analysis reports on the
  // zone the name is in and does not follow an alias out of it. Here the alias is validly
  // signed and the record it points at, in another zone, is not; a validating resolver
  // refuses the name, and the three asked for comparison all do
  it('reports the zone the alias is in, and does not follow it', async () => {
    const { report, misses } = await run(ALIAS_INTO_BROKEN_ZONE);
    expect(misses).toEqual([]);
    expect(report.chain.at(-1)?.zone).toBe('verteiltesysteme.net');
    expect(report.overallStatus).toBe('secure');
    // the disagreement is in the report, for whoever reads that far
    expect(report.crossCheck.map(resolver => resolver.rcode)).toEqual([
      'SERVFAIL',
      'SERVFAIL',
      'SERVFAIL',
    ]);
  });
});
