// the vocabulary of a DNSSEC judgement: the four outcomes RFC 4033 §5 and RFC 4035 §4.3
// define, and a code for why, each mapped to the extended DNS error (RFC 8914) a
// validating resolver would send for it, where one fits

export const SECURITY_STATUSES = {
  // a chain of signatures runs from a trust anchor to the data
  SECURE: 'secure',
  // the data is proven to sit below a delegation with no DS: nothing could sign it
  INSECURE: 'insecure',
  // a chain should be there and is broken
  BOGUS: 'bogus',
  // it could not be told: a response missing, or a check this runtime cannot do
  INDETERMINATE: 'indeterminate',
} as const;

export type SecurityStatus = (typeof SECURITY_STATUSES)[keyof typeof SECURITY_STATUSES];

// RFC 8914 §4, the codes a judgement can carry
export const EXTENDED_DNS_ERRORS = {
  OTHER: 0,
  UNSUPPORTED_DNSKEY_ALGORITHM: 1,
  UNSUPPORTED_DS_DIGEST_TYPE: 2,
  DNSSEC_INDETERMINATE: 5,
  DNSSEC_BOGUS: 6,
  SIGNATURE_EXPIRED: 7,
  SIGNATURE_NOT_YET_VALID: 8,
  DNSKEY_MISSING: 9,
  RRSIGS_MISSING: 10,
  NO_ZONE_KEY_BIT_SET: 11,
  NSEC_MISSING: 12,
  NO_REACHABLE_AUTHORITY: 22,
  UNSUPPORTED_NSEC3_ITERATIONS: 27,
} as const;

const E = EXTENDED_DNS_ERRORS;

// why a link came out as it did. Each code names one rule; the extended DNS error beside
// it is what RFC 8914 has for that rule, or none where RFC 8914 has nothing that fits
export const REASON_CODES = {
  // secure: every check on the link passed
  VERIFIED: 'verified',

  // insecure
  // the parent proves the zone has no DS (RFC 4035 §5.2)
  NO_DS: 'no-ds',
  // the parent's NSEC3 covering the name sets opt-out (RFC 5155 §6)
  OPT_OUT: 'opt-out',
  // the DS set names only algorithms nothing here verifies (RFC 6840 §5.2)
  UNSUPPORTED_ALGORITHM: 'unsupported-algorithm',
  // the DS set uses only digest types nothing here computes (RFC 4035 §5.2)
  UNSUPPORTED_DIGEST: 'unsupported-digest',
  // the NSEC3 iterations are past what a validator will hash (RFC 9276 §3.2)
  NSEC3_ITERATIONS: 'nsec3-iterations',
  // a zone above is insecure, so nothing below it can be secure
  PARENT_INSECURE: 'parent-insecure',

  // bogus
  // no published root key matches a trust anchor
  NO_TRUST_ANCHOR: 'no-trust-anchor',
  // the parent has a DS, the zone serves no DNSKEY
  DNSKEY_MISSING: 'dnskey-missing',
  // no key the DS set commits to is in the zone's key set
  NO_MATCHING_DNSKEY: 'no-matching-dnskey',
  // a DS names a key, and its digest does not match it
  DS_DIGEST_MISMATCH: 'ds-digest-mismatch',
  // the parent's DS response, or its proof of no DS, is not validly signed
  DS_UNAUTHENTICATED: 'ds-unauthenticated',
  // the parent is secure and neither a DS nor a proof of its absence came back
  NO_DS_PROOF: 'no-ds-proof',
  // the key set is not signed by a key an entry point vouches for
  KEYSET_NOT_SIGNED: 'keyset-not-signed',
  // an RRset that must be signed came with no signature from its zone
  RRSIGS_MISSING: 'rrsigs-missing',
  SIGNATURE_EXPIRED: 'signature-expired',
  SIGNATURE_NOT_YET_VALID: 'signature-not-yet-valid',
  SIGNATURE_INVALID: 'signature-invalid',
  // a signature names a key the zone does not publish
  SIGNING_KEY_MISSING: 'signing-key-missing',
  // a signature was made by a key without the Zone flag (RFC 4034 §2.1.1)
  NO_ZONE_KEY_BIT: 'no-zone-key-bit',
  // a signature was made by a key with the revoke bit (RFC 5011 §2.1)
  REVOKED_KEY: 'revoked-key',
  // a signature names another zone as its signer, or claims more labels than its owner
  SIGNATURE_MISMATCH: 'signature-mismatch',
  // an RRset is not signed by every algorithm in the key set (RFC 4035 §2.2), when that
  // is asked for
  MISSING_ALGORITHM: 'missing-algorithm',
  // a negative answer, or a wildcard answer, came with no proof
  DENIAL_MISSING: 'denial-missing',
  // a proof came, and does not prove what it has to
  DENIAL_INVALID: 'denial-invalid',
  // a CNAME a DNAME should have synthesized does not match it (RFC 6672 §3.4)
  ALIAS_MISMATCH: 'alias-mismatch',
  // a zone above is bogus
  PARENT_BOGUS: 'parent-bogus',
  // the answer needed more signature checks than one judgement may make (KeyTrap,
  // CVE-2023-50387)
  VALIDATION_LIMIT: 'validation-limit',

  // indeterminate
  // a response the judgement needed is missing
  RESPONSE_MISSING: 'response-missing',
  // every signature that mattered uses an algorithm this runtime cannot verify
  UNVERIFIABLE: 'unverifiable',
  // a zone above could not be judged
  PARENT_INDETERMINATE: 'parent-indeterminate',
} as const;

export type ReasonCode = (typeof REASON_CODES)[keyof typeof REASON_CODES];

const R = REASON_CODES;

// the extended DNS error for each code, where RFC 8914 has one
export const REASON_EDE: Partial<Record<ReasonCode, number>> = {
  [R.UNSUPPORTED_ALGORITHM]: E.UNSUPPORTED_DNSKEY_ALGORITHM,
  [R.UNSUPPORTED_DIGEST]: E.UNSUPPORTED_DS_DIGEST_TYPE,
  [R.NSEC3_ITERATIONS]: E.UNSUPPORTED_NSEC3_ITERATIONS,
  [R.NO_TRUST_ANCHOR]: E.DNSSEC_BOGUS,
  [R.DNSKEY_MISSING]: E.DNSKEY_MISSING,
  [R.NO_MATCHING_DNSKEY]: E.DNSKEY_MISSING,
  [R.DS_DIGEST_MISMATCH]: E.DNSKEY_MISSING,
  [R.DS_UNAUTHENTICATED]: E.DNSSEC_BOGUS,
  [R.NO_DS_PROOF]: E.NSEC_MISSING,
  [R.KEYSET_NOT_SIGNED]: E.DNSSEC_BOGUS,
  [R.RRSIGS_MISSING]: E.RRSIGS_MISSING,
  [R.SIGNATURE_EXPIRED]: E.SIGNATURE_EXPIRED,
  [R.SIGNATURE_NOT_YET_VALID]: E.SIGNATURE_NOT_YET_VALID,
  [R.SIGNATURE_INVALID]: E.DNSSEC_BOGUS,
  [R.SIGNING_KEY_MISSING]: E.DNSKEY_MISSING,
  [R.NO_ZONE_KEY_BIT]: E.NO_ZONE_KEY_BIT_SET,
  [R.REVOKED_KEY]: E.DNSSEC_BOGUS,
  [R.SIGNATURE_MISMATCH]: E.DNSSEC_BOGUS,
  [R.MISSING_ALGORITHM]: E.DNSSEC_BOGUS,
  [R.DENIAL_MISSING]: E.NSEC_MISSING,
  [R.DENIAL_INVALID]: E.DNSSEC_BOGUS,
  [R.ALIAS_MISMATCH]: E.DNSSEC_BOGUS,
  [R.PARENT_BOGUS]: E.DNSSEC_BOGUS,
  [R.VALIDATION_LIMIT]: E.DNSSEC_BOGUS,
  [R.RESPONSE_MISSING]: E.NO_REACHABLE_AUTHORITY,
  [R.UNVERIFIABLE]: E.DNSSEC_INDETERMINATE,
  [R.PARENT_INDETERMINATE]: E.DNSSEC_INDETERMINATE,
};

// why a link, or a whole judgement, came out as it did: a code and the values it is
// about, never English
export interface SecurityReason {
  code: ReasonCode;
  // the zone the link belongs to
  zone: string;
  // the RRset, signature or record the reason is about, where it is about one
  name?: string;
  type?: string;
  keyTag?: number;
  algorithm?: number;
  digestType?: number;
  // the extended DNS error (RFC 8914) for the code, where there is one
  ede?: number;
}

export function securityReason(
  code: ReasonCode,
  zone: string,
  about: Omit<SecurityReason, 'code' | 'zone' | 'ede'> = {}
): SecurityReason {
  const ede = REASON_EDE[code];
  return { code, zone, ...about, ...(ede !== undefined && { ede }) };
}
