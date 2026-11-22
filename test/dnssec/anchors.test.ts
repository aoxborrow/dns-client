import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  anchorChanges,
  hintChanges,
  parseRootAnchors,
  parseRootHints,
} from '../../scripts/iana-data';
import { ROOT_TRUST_ANCHORS, ROOT_TRUST_ANCHORS_INFO } from '../../src/dnssec/index';
import { ROOT_HINTS, ROOT_HINTS_INFO } from '../../src/index';

// the bundled root trust anchors and root hints against copies of IANA's files, saved in
// test/fixtures/iana when the bundle was last refreshed. The weekly CI job runs the same
// comparison against the live files (scripts/refresh-anchors.ts --check)

const xml = readFileSync(new URL('../fixtures/iana/root-anchors.xml', import.meta.url), 'utf8');
const named = readFileSync(new URL('../fixtures/iana/named.root', import.meta.url), 'utf8');
const today = ROOT_TRUST_ANCHORS_INFO.refreshed;

describe('the bundled root trust anchors', () => {
  it('match what IANA published when they were refreshed', () => {
    expect(anchorChanges(ROOT_TRUST_ANCHORS, parseRootAnchors(xml), today)).toEqual([]);
    expect(ROOT_TRUST_ANCHORS_INFO.version! <= today).toBe(true);
  });

  it('hold KSK-2017 without a validUntil, as IANA does before its revocation', () => {
    const ksk2017 = ROOT_TRUST_ANCHORS.find(anchor => anchor.keyTag === 20326);
    expect(ksk2017?.validUntil).toBeUndefined();
    expect(
      parseRootAnchors(xml).find(anchor => anchor.keyTag === 20326)?.validUntil
    ).toBeUndefined();
  });

  // KSK-2017 is due to be revoked on 2027-01-11, and IANA then gives it a validUntil
  it.each([
    ['in the future', '2027-04-11', '2027-01-20'],
    ['already past', '2027-01-11', '2027-02-01'],
  ])('are told apart from IANA once KSK-2017 gets a validUntil %s', (_when, until, on) => {
    const retired = xml.replace(
      '<KeyDigest id="Klajeyz" validFrom="2017-02-02T00:00:00+00:00">',
      `<KeyDigest id="Klajeyz" validFrom="2017-02-02T00:00:00+00:00" validUntil="${until}T00:00:00+00:00">`
    );
    expect(retired).not.toBe(xml);
    const changes = anchorChanges(ROOT_TRUST_ANCHORS, parseRootAnchors(retired), on);
    expect(changes.join('\n')).toContain('key tag 20326');
  });

  it('are told apart from IANA when a new anchor is published', () => {
    const added = xml.replace(
      '</TrustAnchor>',
      `<KeyDigest id="Knew" validFrom="2029-01-01T00:00:00+00:00"><KeyTag>12345</KeyTag><Algorithm>8</Algorithm><DigestType>2</DigestType><Digest>${'AB'.repeat(32)}</Digest></KeyDigest></TrustAnchor>`
    );
    expect(anchorChanges(ROOT_TRUST_ANCHORS, parseRootAnchors(added), today)).toEqual([
      expect.stringContaining('key tag 12345'),
    ]);
  });

  it('leave out the retired KSK-2010 on both sides', () => {
    expect(parseRootAnchors(xml).map(anchor => anchor.keyTag)).toContain(19036);
    expect(ROOT_TRUST_ANCHORS.map(anchor => anchor.keyTag)).not.toContain(19036);
  });
});

describe('the bundled root hints', () => {
  it('match what IANA published when they were refreshed', () => {
    const { hints, version } = parseRootHints(named);
    expect(hints).toHaveLength(13);
    expect(hintChanges(ROOT_HINTS, hints)).toEqual([]);
    expect(version).toBe(ROOT_HINTS_INFO.version);
  });

  it('are told apart from IANA when a root server moves', () => {
    const moved = named.replace('170.247.170.2', '192.0.2.53');
    expect(hintChanges(ROOT_HINTS, parseRootHints(moved).hints)).toHaveLength(2);
  });
});
