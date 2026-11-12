// every cryptographic check reports one of three outcomes. `unchecked` exists so the
// tool can never render a green badge for something it did not actually verify
export const VERIFICATION_RESULTS = {
  VERIFIED: 'verified',
  FAILED: 'failed',
  UNCHECKED: 'unchecked',
} as const;

export const PROOF_STATUSES = {
  VERIFIED: 'verified',
  MISSING: 'missing',
  INCOMPLETE: 'incomplete',
  OPT_OUT: 'opt-out',
  INVALID_HASH: 'invalid-hash',
  UNSUPPORTED_ALGORITHM: 'unsupported-algorithm',
} as const;

// the kind of denial-of-existence proof a zone returned
export const PROOF_TYPES = {
  NSEC: 'NSEC',
  NSEC3: 'NSEC3',
} as const;

// what a proof was asked to establish
export const PROOF_PURPOSES = {
  NO_DS: 'no-ds',
  NXDOMAIN: 'nxdomain',
  NODATA: 'nodata',
  WILDCARD: 'wildcard',
} as const;

// how the tool rates an algorithm's standing, sourced from the IANA DNSSEC algorithm
// registry per RFC 9904 rather than a static RFC table
export const ALGORITHM_STANDINGS = {
  RECOMMENDED: 'recommended',
  SUPPORTED: 'supported',
  DEPRECATED: 'deprecated',
  PROHIBITED: 'prohibited',
  REGIONAL: 'regional',
} as const;

// the date the algorithm/digest assessments below were last checked against IANA
export const ALGORITHM_REGISTRY_REFRESHED = '2026-07-27';

// DNSSEC signing algorithms. `verify` is whether *this tool* can check a signature made
// with the algorithm — an algorithm we cannot verify yields `indeterminate`, never a pass
export const DNSSEC_ALGORITHMS = {
  1: { name: 'RSAMD5', verify: false, standing: ALGORITHM_STANDINGS.PROHIBITED },
  3: { name: 'DSA', verify: false, standing: ALGORITHM_STANDINGS.PROHIBITED },
  5: { name: 'RSASHA1', verify: true, standing: ALGORITHM_STANDINGS.DEPRECATED },
  6: { name: 'DSA-NSEC3-SHA1', verify: false, standing: ALGORITHM_STANDINGS.PROHIBITED },
  7: { name: 'RSASHA1-NSEC3-SHA1', verify: true, standing: ALGORITHM_STANDINGS.DEPRECATED },
  8: { name: 'RSASHA256', verify: true, standing: ALGORITHM_STANDINGS.SUPPORTED },
  10: { name: 'RSASHA512', verify: true, standing: ALGORITHM_STANDINGS.SUPPORTED },
  12: { name: 'ECC-GOST', verify: false, standing: ALGORITHM_STANDINGS.PROHIBITED },
  13: { name: 'ECDSAP256SHA256', verify: true, standing: ALGORITHM_STANDINGS.RECOMMENDED },
  14: { name: 'ECDSAP384SHA384', verify: true, standing: ALGORITHM_STANDINGS.SUPPORTED },
  15: { name: 'ED25519', verify: true, standing: ALGORITHM_STANDINGS.SUPPORTED },
  16: { name: 'ED448', verify: true, standing: ALGORITHM_STANDINGS.SUPPORTED },
  23: { name: 'ECC-GOST12', verify: false, standing: ALGORITHM_STANDINGS.REGIONAL },
} as const;

// expected signature length in bytes for the fixed-width algorithms. a wrong-length
// signature is a distinct, diagnosable fault rather than a generic "invalid"
export const SIGNATURE_LENGTHS: Record<number, number> = {
  13: 64, // ECDSAP256SHA256 — r‖s, 32 bytes each
  14: 96, // ECDSAP384SHA384 — r‖s, 48 bytes each
  15: 64, // Ed25519
  16: 114, // Ed448
};

// DS digest types. `strength` orders them for the RFC 4509 §3 strongest-supported-wins
// selection rule; unsupported types have no strength because they can never be selected
export const DS_DIGEST_TYPES = {
  1: { name: 'SHA-1', verify: true, strength: 1, standing: ALGORITHM_STANDINGS.DEPRECATED },
  2: { name: 'SHA-256', verify: true, strength: 3, standing: ALGORITHM_STANDINGS.RECOMMENDED },
  3: {
    name: 'GOST R 34.11-94',
    verify: false,
    strength: 0,
    standing: ALGORITHM_STANDINGS.REGIONAL,
  },
  4: { name: 'SHA-384', verify: true, strength: 4, standing: ALGORITHM_STANDINGS.SUPPORTED },
  5: {
    name: 'GOST R 34.11-2012',
    verify: false,
    strength: 0,
    standing: ALGORITHM_STANDINGS.REGIONAL,
  },
  6: { name: 'SM3', verify: false, strength: 0, standing: ALGORITHM_STANDINGS.REGIONAL },
} as const;

// NSEC3 hash algorithms (RFC 5155 — only SHA-1 is defined)
export const NSEC3_HASH_ALGORITHMS = {
  1: { name: 'SHA-1', verify: true },
} as const;

// DNSKEY RDATA flag bits (RFC 4034 §2.1.1, RFC 5011 §3)
export const DNSKEY_FLAGS = {
  ZONE: 0x0100, // bit 7 — the key may sign the zone's RRsets
  REVOKE: 0x0080, // bit 8 — RFC 5011 revoke bit
  SEP: 0x0001, // bit 15 — secure entry point, the key the parent's DS points at
} as const;

// the only protocol value DNSSEC permits (RFC 4034 §2.1.2)
export const DNSKEY_PROTOCOL = 3;

// NSEC3 flag bits (RFC 5155 §3.1.2)
export const NSEC3_FLAGS = {
  OPT_OUT: 0x01,
} as const;

// RFC 9276 §3.1: NSEC3 iterations MUST be 0. validators commonly treat higher counts as
// insecure, and higher still as outright SERVFAIL
export const NSEC3_ITERATIONS_INSECURE_THRESHOLD = 100;
export const NSEC3_ITERATIONS_SERVFAIL_THRESHOLD = 500;
