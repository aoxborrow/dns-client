import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  parseAlgorithmRegistry,
  parseDigestRegistry,
  registryChanges,
  registryLiteral,
  registryStanding,
} from '../../scripts/iana-data';
import { DNSSEC_ALGORITHMS, DS_DIGEST_TYPES } from '../../src/dnssec/index';

// reading IANA's DNSSEC algorithm and DS digest registries, from copies saved in
// test/fixtures/iana. The weekly CI job compares the bundled tables with the live
// registries (scripts/refresh-algorithms.ts --check)

const fixture = (file: string) =>
  readFileSync(new URL(`../fixtures/iana/${file}`, import.meta.url), 'utf8');
const algorithmXml = fixture('dns-sec-alg-numbers.xml');
const digestXml = fixture('ds-rr-types.xml');
const algorithms = parseAlgorithmRegistry(algorithmXml);
const digests = parseDigestRegistry(digestXml);
const standing = (entries: typeof algorithms, number: number) =>
  registryStanding(entries.find(entry => entry.number === number)!);

describe('the DNSSEC algorithm registry', () => {
  it('reads as the signing algorithms, less the private ones', () => {
    const numbers = algorithms.map(entry => entry.number);
    expect(numbers).toEqual(expect.arrayContaining([1, 3, 5, 8, 13, 15, 16, 23]));
    expect(numbers).not.toContain(0);
    expect(numbers).not.toContain(253);
    expect(numbers).not.toContain(254);
    expect(algorithms.find(entry => entry.number === 13)?.name).toBe('ECDSAP256SHA256');
  });

  it('gives each row a standing from its columns', () => {
    expect(standing(algorithms, 1)).toBe('prohibited');
    expect(standing(algorithms, 5)).toBe('deprecated');
    expect(standing(algorithms, 13)).toBe('recommended');
    expect(standing(algorithms, 14)).toBe('supported');
    expect(standing(algorithms, 23)).toBe('regional');
  });

  it('tells the bundle apart when IANA changes a row', () => {
    const before = registryChanges('algorithm', DNSSEC_ALGORITHMS, algorithms);
    const moved = algorithmXml.replace(
      /(<mnemonic>ED448<\/mnemonic>[\s\S]*?<usevalid>)RECOMMENDED/,
      '$1MUST NOT'
    );
    expect(moved).not.toBe(algorithmXml);
    const after = registryChanges('algorithm', DNSSEC_ALGORITHMS, parseAlgorithmRegistry(moved));
    expect(after.filter(line => !before.includes(line))).toEqual([
      'algorithm IANA publishes and the bundle lacks: 16 ED448 (prohibited)',
      'algorithm the bundle has and IANA does not: 16 ED448 (supported)',
    ]);
  });

  it('rewrites the table with IANA names and standings, keeping what the library verifies', () => {
    const literal = registryLiteral('DNSSEC_ALGORITHMS', DNSSEC_ALGORITHMS, algorithms);
    expect(literal).toContain(
      "13: { name: 'ECDSAP256SHA256', verify: true, standing: ALGORITHM_STANDINGS.RECOMMENDED },"
    );
    expect(literal).toContain(
      "23: { name: 'ECC-GOST12', verify: false, standing: ALGORITHM_STANDINGS.REGIONAL },"
    );
    expect(literal).toMatch(/^export const DNSSEC_ALGORITHMS = \{\n[\s\S]*\n\} as const;$/);
  });
});

describe('the DS digest registry', () => {
  it('reads as the assigned digest types, without IANA notes in their names', () => {
    expect(digests.map(entry => [entry.number, entry.name])).toEqual([
      [1, 'SHA-1'],
      [2, 'SHA-256'],
      [3, 'GOST R 34.11-94'],
      [4, 'SHA-384'],
      [5, 'GOST R 34.11-2012'],
      [6, 'SM3'],
    ]);
  });

  it('gives each row a standing from its columns', () => {
    expect(standing(digests, 1)).toBe('deprecated');
    expect(standing(digests, 2)).toBe('recommended');
    expect(standing(digests, 4)).toBe('supported');
    expect(standing(digests, 6)).toBe('regional');
  });

  it('rewrites the table keeping each digest strength', () => {
    const literal = registryLiteral('DS_DIGEST_TYPES', DS_DIGEST_TYPES, digests);
    expect(literal).toContain(
      "2: { name: 'SHA-256', verify: true, strength: 3, standing: ALGORITHM_STANDINGS.RECOMMENDED },"
    );
    expect(literal).toContain(
      "4: { name: 'SHA-384', verify: true, strength: 4, standing: ALGORITHM_STANDINGS.SUPPORTED },"
    );
  });
});
