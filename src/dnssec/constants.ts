// the four RFC 4035 §4.3 validation states, replacing the old three-state
// secure/insecure/invalid model. the distinction that matters: `insecure` is the
// normal state for most domains, `bogus` is an outage
export const DNSSEC_STATUSES = {
  SECURE: 'secure',
  INSECURE: 'insecure',
  BOGUS: 'bogus',
  INDETERMINATE: 'indeterminate',
} as const;

// every cryptographic check reports one of three outcomes. `unchecked` exists so the
// tool can never render a green badge for something it did not actually verify
export const VERIFICATION_RESULTS = {
  VERIFIED: 'verified',
  FAILED: 'failed',
  UNCHECKED: 'unchecked',
} as const;

// finding severity ladder (kept from the previous engine — the UI already renders it)
export const FINDING_SEVERITIES = {
  ERROR: 'error',
  WARNING: 'warning',
  INFO: 'info',
} as const;

// recommendation priorities (also kept)
export const DNSSEC_RECOMMENDATION_PRIORITIES = {
  CRITICAL: 'critical',
  IMPORTANT: 'important',
  ADVISORY: 'advisory',
} as const;

export const DNSSEC_KEY_TYPES = {
  KSK: 'KSK',
  ZSK: 'ZSK',
} as const;

// per-object status tokens, one vocabulary per object kind (docs/dnssec-tool-ui.md §0)
export const DNSKEY_STATUSES = {
  ACTIVE_KSK: 'active-ksk',
  ACTIVE_ZSK: 'active-zsk',
  PUBLISHED_NOT_SIGNING: 'published-not-signing',
  REVOKED: 'revoked',
  ORPHANED: 'orphaned',
  SEP_WITHOUT_DS: 'sep-without-ds',
  UNSUPPORTED_ALGORITHM: 'unsupported-algorithm',
  DEPRECATED_ALGORITHM: 'deprecated-algorithm',
  ZONE_FLAG_UNSET: 'zone-flag-unset',
  PROTOCOL_NOT_3: 'protocol-not-3',
} as const;

export const DS_STATUSES = {
  VERIFIED: 'verified',
  DIGEST_MISMATCH: 'digest-mismatch',
  NO_MATCHING_DNSKEY: 'no-matching-dnskey',
  UNSUPPORTED_DIGEST: 'unsupported-digest',
  DEPRECATED_DIGEST: 'deprecated-digest',
  IGNORED_WEAKER_DIGEST: 'ignored-weaker-digest',
  ORPHANED: 'orphaned',
} as const;

export const RRSIG_STATUSES = {
  VERIFIED: 'verified',
  EXPIRED: 'expired',
  NOT_YET_VALID: 'not-yet-valid',
  EXPIRING_SOON: 'expiring-soon',
  SIGNATURE_INVALID: 'signature-invalid',
  BAD_LENGTH: 'bad-length',
  NO_MATCHING_KEY: 'no-matching-key',
  SIGNER_MISMATCH: 'signer-mismatch',
  UNSUPPORTED_ALGORITHM: 'unsupported-algorithm',
  REVOKED_KEY: 'revoked-key',
  LABELS_EXCEED_OWNER: 'labels-exceed-owner',
} as const;

export const RRSET_STATUSES = {
  SIGNED_VERIFIED: 'signed-verified',
  SIGNED_UNVERIFIED: 'signed-unverified',
  UNSIGNED: 'unsigned',
  MISSING_ALGORITHM_COVERAGE: 'missing-algorithm-coverage',
} as const;

export const PROOF_STATUSES = {
  VERIFIED: 'verified',
  MISSING: 'missing',
  INCOMPLETE: 'incomplete',
  OPT_OUT: 'opt-out',
  INVALID_HASH: 'invalid-hash',
  UNSUPPORTED_ALGORITHM: 'unsupported-algorithm',
} as const;

export const SERVER_STATUSES = {
  RESPONDED: 'responded',
  TIMEOUT: 'timeout',
  REFUSED: 'refused',
  SERVFAIL: 'servfail',
  NOT_AUTHORITATIVE: 'not-authoritative',
  DIVERGENT: 'divergent',
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

// a signature closer than this to expiry is a candidate for the expiring-soon warning
export const SIGNATURE_EXPIRY_WARNING_DAYS = 7;
export const SIGNATURE_EXPIRY_WARNING_MS = SIGNATURE_EXPIRY_WARNING_DAYS * 24 * 60 * 60 * 1000;

// …but only when it is also in the last quarter of its own validity window. a KSK signs the
// DNSKEY RRset for two months while a ZSK signs A/AAAA for two days; both are normal, and a
// rule that looked only at absolute time left would warn on every Cloudflare-hosted domain
export const SIGNATURE_EXPIRY_WARNING_FRACTION = 0.25;

// tolerance either side of the validity window, absorbing ordinary clock drift between
// the signer and this host — a signature inside the skew is reported as info, not an error
export const CLOCK_SKEW_MS = 5 * 60 * 1000;

// RFC 9276 §3.1: NSEC3 iterations MUST be 0. validators commonly treat higher counts as
// insecure, and higher still as outright SERVFAIL
export const NSEC3_ITERATIONS_INSECURE_THRESHOLD = 100;
export const NSEC3_ITERATIONS_SERVFAIL_THRESHOLD = 500;

// public validating resolvers queried for corroboration (never for validation itself)
export const CROSS_CHECK_RESOLVERS = [
  { name: 'Google', address: '8.8.8.8' },
  { name: 'Cloudflare', address: '1.1.1.1' },
  { name: 'Quad9', address: '9.9.9.9' },
] as const;

// the cross-check gets its own, much shorter deadline than the validation queries. it is
// corroboration the verdict does not depend on, so one unreachable resolver must not turn a
// 150ms scan into a 5s one — a resolver that misses this window is reported as unreachable
export const CROSS_CHECK_TIMEOUT_MS = 2000;

// the record types the tool retrieves from a target zone to check signature coverage.
// this is a sample of the zone, never an enumeration — see the coverage note in
// docs/dnssec-tool.md §3.4
export const COVERAGE_RECORD_TYPES = ['SOA', 'A', 'AAAA', 'MX', 'TXT', 'NS'] as const;

// how many authoritative servers the deep scan consults per zone before it stops
export const DEEP_SERVERS_PER_ZONE = 8;

// how many servers the default scan will try per query. it stops at the first that answers, so a
// live zone costs one round trip; the cap bounds the cost when a zone the attacker controls lists
// many dead NS addresses, which would otherwise be (addresses × 5s) of sequential timeouts per query
export const STANDARD_SERVERS_PER_ZONE = 5;

// a hard wall-clock ceiling on one validation run. a hostile zone can chain many delegations, each
// with dead servers, to drag a single public lookup into minutes of outbound port-53 work; past this
// the engine stops issuing queries and reports what it could not reach as unreachable
export const MAX_RUN_MS = 60_000;
