import { FINDING_SEVERITIES } from './constants';

// the finding catalog. every finding the engine can emit has an entry here: a stable slug,
// a default severity, a short title, the RFC that defines the rule, and the fix. the engine
// supplies the per-instance sentence and the subject (zone / object / key tag); everything
// static about a finding lives here so the UI has copy for a slug without asking the backend
export interface FindingDefinition {
  severity: (typeof FINDING_SEVERITIES)[keyof typeof FINDING_SEVERITIES];
  title: string;
  rfc?: string;
  fix?: string;
}

const { ERROR, WARNING, INFO } = FINDING_SEVERITIES;

export const FINDING_CATALOG = {
  // ---- signature ----------------------------------------------------------
  'signature-expired': {
    severity: ERROR,
    title: 'Signature expired',
    rfc: 'RFC 4035 §5.3.1',
    fix: 'Re-sign the zone with an active signing key and confirm your signing automation is running.',
  },
  'signature-not-yet-valid': {
    severity: ERROR,
    title: 'Signature not yet valid',
    rfc: 'RFC 4035 §5.3.1',
    fix: "Check the signer's clock — the signature's inception time is in the future.",
  },
  'signature-invalid': {
    severity: ERROR,
    title: 'Signature verification failed',
    rfc: 'RFC 4035 §5.3.3',
    fix: 'Re-sign the RRset. The published signature does not match the data it covers.',
  },
  'signature-bad-length': {
    severity: ERROR,
    title: 'Signature has the wrong length for its algorithm',
    rfc: 'RFC 6605 §4',
    fix: 'Re-sign the zone. The signature is malformed for the algorithm it claims.',
  },
  'signature-expiring-soon': {
    severity: WARNING,
    title: 'Signature expires soon',
    rfc: 'RFC 6781 §4.4',
    fix: 'No action needed if automated signing is healthy — confirm the re-signing job runs before this window closes.',
  },
  'signature-within-clock-skew': {
    severity: INFO,
    title: 'Signature is within clock-skew tolerance',
    rfc: 'RFC 4035 §5.3.1',
  },
  'signer-not-zone': {
    severity: ERROR,
    title: 'Signer name does not match the zone',
    rfc: 'RFC 4035 §5.3.1',
    fix: 'Re-sign the RRset with a key belonging to this zone.',
  },
  'rrsig-labels-exceed-owner': {
    severity: ERROR,
    title: 'Signature label count exceeds the owner name',
    rfc: 'RFC 4035 §5.3.1',
    fix: 'Re-sign the RRset — the RRSIG labels field is inconsistent with the name it covers.',
  },
  'original-ttl-exceeded': {
    severity: WARNING,
    title: "RRset TTL exceeds the signature's original TTL",
    rfc: 'RFC 4035 §5.3.1',
    fix: "Align the RRset's TTL with the value in force when it was signed.",
  },
  'ttl-beyond-expiration': {
    severity: WARNING,
    title: 'RRset TTL outlives its signature',
    rfc: 'RFC 4035 §5.3.3',
    fix: 'Shorten the TTL or lengthen the signature validity so cached records never outlive their signature.',
  },
  'no-matching-dnskey': {
    severity: ERROR,
    title: 'Signature references a key this zone does not publish',
    rfc: 'RFC 4035 §5.3.1',
    fix: 'Publish the missing DNSKEY or remove the stale signatures.',
  },
  'revoked-key-signing': {
    severity: ERROR,
    title: 'A revoked key was used for signing',
    rfc: 'RFC 5011 §2.1',
    fix: 'Re-sign the zone with an active key. A revoked key must not produce new signatures.',
  },
  'algorithm-not-supported': {
    severity: WARNING,
    title: 'Signature algorithm cannot be verified',
    rfc: 'RFC 8624',
    fix: 'Migrate to a widely supported algorithm such as ECDSAP256SHA256 (13).',
  },
  'algorithm-deprecated': {
    severity: WARNING,
    title: 'Deprecated signing algorithm',
    rfc: 'RFC 8624 §3.1',
    fix: 'Roll the zone to ECDSAP256SHA256 (13) or Ed25519 (15).',
  },

  // ---- DNSKEY -------------------------------------------------------------
  'dnskey-missing': {
    severity: ERROR,
    title: 'No DNSKEY records published',
    rfc: 'RFC 4035 §2.1',
    fix: "Publish the zone's DNSKEY RRset, or remove the DS record from the parent if the zone is meant to be unsigned.",
  },
  'zone-flag-unset': {
    severity: ERROR,
    title: 'DNSKEY has the Zone flag unset',
    rfc: 'RFC 4034 §2.1.1',
    fix: 'A key without the Zone flag cannot sign zone data — republish it with flags 256 or 257.',
  },
  'protocol-not-3': {
    severity: ERROR,
    title: 'DNSKEY protocol is not 3',
    rfc: 'RFC 4034 §2.1.2',
    fix: 'Republish the key with protocol 3. Any other value makes the key unusable.',
  },
  'no-sep-for-algorithm': {
    severity: ERROR,
    title: 'No secure entry point for an algorithm in the key set',
    rfc: 'RFC 4035 §2.2',
    fix: 'Publish a DS in the parent for at least one key of every algorithm the zone signs with.',
  },
  'key-published-not-signing': {
    severity: INFO,
    title: 'Key published but not signing',
    rfc: 'RFC 6781 §4.1',
  },
  'ksk-rollover-in-progress': {
    severity: INFO,
    title: 'KSK rollover in progress',
    rfc: 'RFC 6781 §4.1.2',
  },
  'zsk-rollover-in-progress': {
    severity: INFO,
    title: 'ZSK rollover in progress',
    rfc: 'RFC 6781 §4.1.1',
  },
  'key-revoked': {
    severity: INFO,
    title: 'Revoked key published',
    rfc: 'RFC 5011 §2.1',
  },
  'weak-key-size': {
    severity: WARNING,
    title: 'Key size below the recommended minimum',
    rfc: 'RFC 8624 §3.1',
    fix: 'Roll to a 2048-bit RSA key, or move to an elliptic-curve algorithm.',
  },
  'single-key-zone': {
    severity: INFO,
    title: 'Zone signs with a single key',
    rfc: 'RFC 6781 §3.1',
  },

  // ---- DS / delegation ----------------------------------------------------
  'ds-digest-invalid': {
    severity: ERROR,
    title: 'DS digest does not match the published DNSKEY',
    rfc: 'RFC 4034 §5.1.4',
    fix: "Regenerate the DS from the zone's current KSK and update it through your registrar.",
  },
  'ds-no-matching-dnskey': {
    severity: ERROR,
    title: 'DS references a key this zone does not publish',
    rfc: 'RFC 4035 §5.2',
    fix: 'Remove the stale DS through your registrar, or publish the key it commits to.',
  },
  'ds-present-child-unsigned': {
    severity: ERROR,
    title: 'Parent publishes a DS but the zone serves no DNSKEY',
    rfc: 'RFC 4035 §5.2',
    fix: 'Either sign the zone or remove the DS record from the parent through your registrar.',
  },
  'ds-digest-unsupported': {
    severity: WARNING,
    title: 'DS digest type cannot be verified',
    rfc: 'RFC 4509 §3',
    fix: 'Publish a SHA-256 (digest type 2) DS alongside it.',
  },
  'ds-digest-deprecated': {
    severity: WARNING,
    title: 'Deprecated DS digest type',
    rfc: 'RFC 8624 §3.3',
    fix: 'Replace the SHA-1 DS with SHA-256 (digest type 2).',
  },
  'ds-digest-ignored': {
    severity: INFO,
    title: 'Weaker DS digest ignored',
    rfc: 'RFC 4509 §3',
  },
  'ds-algorithm-not-in-child': {
    severity: ERROR,
    title: "DS names an algorithm absent from the zone's key set",
    rfc: 'RFC 4035 §2.2',
    fix: 'Remove the DS, or publish a key using that algorithm.',
  },
  'referral-for-ds-query': {
    severity: ERROR,
    title: 'DS query answered with a referral',
    rfc: 'RFC 4035 §3.1.4.1',
    fix: 'The parent servers are answering DS queries below the cut. Contact the registry.',
  },
  'no-ds-proof-missing': {
    severity: ERROR,
    title: 'No DS record and no proof of its absence',
    rfc: 'RFC 4035 §5.2',
    fix: 'The parent must return an NSEC or NSEC3 proof for a non-existent DS. Contact the registry.',
  },
  'ds-response-unauthenticated': {
    severity: ERROR,
    title: "The parent's DS response is not validly signed",
    rfc: 'RFC 4035 §5',
    fix: "Re-sign the parent zone's DS RRset. A DS whose signature does not validate cannot anchor the child.",
  },

  // ---- denial of existence ------------------------------------------------
  'nsec-missing-for-nxdomain': {
    severity: ERROR,
    title: 'NXDOMAIN returned with no proof',
    rfc: 'RFC 4035 §3.1.3.2',
    fix: 'The zone must return NSEC or NSEC3 records proving the name does not exist.',
  },
  'nsec-missing-for-nodata': {
    severity: ERROR,
    title: 'Empty answer returned with no proof',
    rfc: 'RFC 4035 §3.1.3.1',
    fix: 'The zone must return NSEC or NSEC3 records proving the type does not exist.',
  },
  'sname-not-covered': {
    severity: ERROR,
    title: 'No NSEC/NSEC3 record covers the queried name',
    rfc: 'RFC 5155 §8.4',
    fix: 'The denial proof is incomplete — check the signer for a range gap.',
  },
  'no-closest-encloser': {
    severity: ERROR,
    title: 'Closest encloser not proven',
    rfc: 'RFC 5155 §8.3',
    fix: 'The NSEC3 chain is missing the closest-encloser record.',
  },
  'wildcard-not-covered': {
    severity: ERROR,
    title: 'Wildcard absence not proven',
    rfc: 'RFC 5155 §8.5',
    fix: 'The denial proof must also cover the applicable wildcard name.',
  },
  'opt-out-not-authenticated': {
    severity: INFO,
    title: 'Opt-out set — absence is not authenticated',
    rfc: 'RFC 5155 §6',
  },
  'stype-in-bitmap': {
    severity: ERROR,
    title: 'Denial record lists the type it claims does not exist',
    rfc: 'RFC 4035 §5.4',
    fix: 'The proof contradicts itself — re-sign the zone.',
  },
  'nsec3-iterations-nonzero': {
    severity: WARNING,
    title: 'NSEC3 iterations greater than zero',
    rfc: 'RFC 9276 §3.1',
    fix: 'Set NSEC3 iterations to 0 and re-sign.',
  },
  'nsec3-salt-nonempty': {
    severity: WARNING,
    title: 'NSEC3 salt in use',
    rfc: 'RFC 9276 §3.1',
    fix: 'Remove the NSEC3 salt and re-sign — a salt adds no security against zone enumeration.',
  },
  'nsec3-unsupported-algorithm': {
    severity: WARNING,
    title: 'NSEC3 hash algorithm not supported',
    rfc: 'RFC 5155 §11',
  },
  'nsec3-invalid-hash': {
    severity: ERROR,
    title: 'NSEC3 owner name is not a valid hash',
    rfc: 'RFC 5155 §5',
    fix: 'The NSEC3 chain is malformed — re-sign the zone.',
  },

  // ---- response / transport ----------------------------------------------
  'server-timeout': {
    severity: WARNING,
    title: 'Nameserver did not respond',
    fix: 'Check that the server is reachable over TCP and UDP port 53.',
  },
  'server-refused': {
    severity: WARNING,
    title: 'Nameserver refused the query',
    fix: 'The server is not answering for this zone — check its configuration.',
  },
  'server-servfail': {
    severity: ERROR,
    title: 'Nameserver returned SERVFAIL',
    fix: 'The server failed to answer for a zone it should be authoritative for.',
  },
  'not-authoritative': {
    severity: WARNING,
    title: 'Answer was not authoritative',
    rfc: 'RFC 1035 §4.1.1',
    fix: 'The server answered without the AA flag for a zone it is delegated.',
  },
  'server-divergent': {
    severity: ERROR,
    title: 'Nameservers returned different data',
    fix: 'Bring the divergent server back in sync — resolvers will get different answers depending on which they reach.',
  },
  'truncated-no-tcp': {
    severity: WARNING,
    title: 'Response truncated and TCP retry failed',
    rfc: 'RFC 7766 §5',
    fix: 'Allow DNS over TCP on port 53 — DNSSEC responses routinely exceed the UDP limit.',
  },
  'do-bit-cleared': {
    severity: ERROR,
    title: 'Server stripped the DNSSEC OK bit',
    rfc: 'RFC 4035 §3.2.1',
    fix: 'The server is not returning DNSSEC records — check for a middlebox or a non-DNSSEC-aware server.',
  },

  // ---- coverage / hygiene -------------------------------------------------
  'rrset-unsigned': {
    severity: ERROR,
    title: 'Authoritative RRset has no signature',
    rfc: 'RFC 4035 §2.2',
    fix: 'Re-sign the zone. In a secure zone every authoritative RRset must carry an RRSIG.',
  },
  'missing-algorithm-coverage': {
    severity: ERROR,
    title: 'RRset is not signed by every algorithm in the key set',
    rfc: 'RFC 4035 §2.2',
    fix: 'Sign every RRset with each algorithm present in the DNSKEY RRset.',
  },
  'cds-inconsistent-with-ds': {
    severity: WARNING,
    title: 'CDS record does not match the published DS',
    rfc: 'RFC 7344 §4',
    fix: 'The zone is signalling a DS change — confirm it is intentional and let the registry pick it up.',
  },
  'cdnskey-inconsistent-with-ds': {
    severity: WARNING,
    title: 'CDNSKEY record does not match the published DS',
    rfc: 'RFC 7344 §4',
    fix: 'The zone is signalling a key change — confirm it is intentional.',
  },

  // ---- trust anchor -------------------------------------------------------
  'trust-anchor-mismatch': {
    severity: ERROR,
    title: 'Root DNSKEY does not match any IANA trust anchor',
    rfc: 'RFC 4035 §5',
    fix: 'This is a systemic failure — the root key set could not be anchored. Retry, and suspect interception if it persists.',
  },
  'trust-anchor-revoked': {
    severity: INFO,
    title: 'A trust anchor key is published as revoked',
    rfc: 'RFC 5011 §2.1',
  },
  'root-ksk-rollover': {
    severity: INFO,
    title: 'Root KSK rollover in progress',
    rfc: 'RFC 5011',
    fix: 'If you run a validating resolver with a manually configured trust anchor, add KSK-2024 (key tag 38696) before 2026-10-11.',
  },

  // ---- validation could not proceed --------------------------------------
  'zone-unreachable': {
    severity: ERROR,
    title: 'No authoritative server answered for this zone',
    fix: 'Check that the delegated nameservers are reachable and answering.',
  },
  'validation-error': {
    severity: ERROR,
    title: 'Validation could not be completed',
  },
} as const satisfies Record<string, FindingDefinition>;

export type FindingSlug = keyof typeof FINDING_CATALOG;

// look up a slug's static definition
export function getFindingDefinition(slug: FindingSlug): FindingDefinition {
  return FINDING_CATALOG[slug];
}
