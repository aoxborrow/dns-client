// the zones the offline DNSSEC tests analyze, one per signing algorithm, DS digest type and
// failure state. Their responses are recorded together (scripts/record-dnssec.ts) into
// test/fixtures/dnssec.json and replayed with the clock they were recorded at.
//
// most are the RootCanary algorithm test zones (`<state>.d<digest>a<algorithm>n<nsec>`),
// which exist to be signed, and broken, in exactly one way each

export interface DnssecCase {
  id: string;
  name: string;
  // what the analysis has to conclude
  status: 'secure' | 'insecure' | 'bogus' | 'indeterminate';
  // the algorithm the zone signs with, where it is signed
  algorithm?: number;
  // findings that have to be there: the reason, not only the verdict
  findings?: string[];
  // findings that must not be
  absent?: string[];
}

// a validly signed alias into another zone, where the record it points at has a broken
// signature (the `bogus-record-signature` zone below). Recorded for the test of what the
// analysis does with an alias; not one of the cases, because its verdict is a known limit
export const ALIAS_INTO_BROKEN_ZONE = 'sigfail.verteiltesysteme.net';

export const DNSSEC_CASES: DnssecCase[] = [
  // ---- one per algorithm ----
  {
    id: 'rsasha1',
    name: 'secure.d2a5n1.rootcanary.net',
    status: 'secure',
    algorithm: 5,
    findings: ['algorithm-deprecated'],
  },
  {
    id: 'rsasha1-nsec3',
    name: 'secure.d2a7n3.rootcanary.net',
    status: 'secure',
    algorithm: 7,
    findings: ['algorithm-deprecated'],
  },
  {
    id: 'rsasha256',
    name: 'secure.d2a8n3.rootcanary.net',
    status: 'secure',
    algorithm: 8,
    absent: ['algorithm-deprecated', 'signature-invalid'],
  },
  {
    id: 'rsasha512',
    name: 'secure.d2a10n3.rootcanary.net',
    status: 'secure',
    algorithm: 10,
    absent: ['algorithm-deprecated', 'signature-invalid'],
  },
  {
    id: 'ecdsap256',
    name: 'secure.d2a13n3.rootcanary.net',
    status: 'secure',
    algorithm: 13,
    absent: ['signature-invalid'],
  },
  {
    id: 'ecdsap384',
    name: 'secure.d2a14n3.rootcanary.net',
    status: 'secure',
    algorithm: 14,
    absent: ['signature-invalid'],
  },
  {
    id: 'ed25519',
    name: 'secure.d2a15n3.rootcanary.net',
    status: 'secure',
    algorithm: 15,
    absent: ['signature-invalid'],
  },
  {
    id: 'ed448',
    name: 'secure.d2a16n3.rootcanary.net',
    status: 'secure',
    algorithm: 16,
    absent: ['signature-invalid'],
  },
  // an algorithm nothing here can verify: never a pass, and never a failure either
  {
    id: 'gost-unsupported',
    name: 'secure.d2a12n3.rootcanary.net',
    status: 'indeterminate',
    algorithm: 12,
    findings: ['algorithm-not-supported'],
    absent: ['signature-invalid'],
  },

  // ---- DS digest types ----
  {
    id: 'ds-sha1',
    name: 'secure.d1a13n3.rootcanary.net',
    status: 'secure',
    algorithm: 13,
    findings: ['ds-digest-deprecated'],
  },
  {
    id: 'ds-sha384',
    name: 'secure.d4a13n3.rootcanary.net',
    status: 'secure',
    algorithm: 13,
    absent: ['ds-digest-deprecated'],
  },
  // NSEC where the others use NSEC3
  {
    id: 'nsec',
    name: 'secure.d2a13n1.rootcanary.net',
    status: 'secure',
    algorithm: 13,
  },

  // ---- signed zones in ordinary use ----
  { id: 'cloudflare', name: 'cloudflare.com', status: 'secure', algorithm: 13 },
  { id: 'ed25519-nl', name: 'ed25519.nl', status: 'secure', algorithm: 15 },

  // ---- failure states, each for its own reason ----
  {
    id: 'bogus-signature-rsa',
    name: 'bogus.d2a8n3.rootcanary.net',
    status: 'bogus',
    algorithm: 8,
    findings: ['signature-invalid'],
  },
  {
    id: 'bogus-signature-ecdsa',
    name: 'bogus.d2a13n3.rootcanary.net',
    status: 'bogus',
    algorithm: 13,
    findings: ['signature-invalid'],
  },
  {
    id: 'bogus-signature-ed25519',
    name: 'bogus.d2a15n3.rootcanary.net',
    status: 'bogus',
    algorithm: 15,
    findings: ['signature-invalid'],
  },
  {
    id: 'bogus-expired',
    name: 'rhybar.cz',
    status: 'bogus',
    findings: ['signature-expired'],
  },
  {
    id: 'bogus-ds-mismatch',
    name: 'dnssec-failed.org',
    status: 'bogus',
    findings: ['ds-no-matching-dnskey'],
  },
  {
    id: 'bogus-no-child-key',
    name: 'brokendnssec.net',
    status: 'bogus',
    findings: ['ds-present-child-unsigned'],
  },

  // one record of an otherwise sound zone carries a signature that does not verify: the
  // name asked about is broken, not the zone's keys
  {
    id: 'bogus-record-signature',
    name: 'sigfail.rsa2048-sha256.ippacket.stream',
    status: 'bogus',
    algorithm: 8,
    findings: ['signature-invalid'],
  },
  {
    id: 'sound-record-signature',
    name: 'sigok.rsa2048-sha256.ippacket.stream',
    status: 'secure',
    algorithm: 8,
    absent: ['signature-invalid'],
  },

  // ---- not signed, and proven so ----
  {
    id: 'insecure-opt-out',
    name: 'github.com',
    status: 'insecure',
    absent: ['signature-invalid', 'ds-no-matching-dnskey'],
  },
];
