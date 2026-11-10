import {
  ALGORITHM_STANDINGS,
  DNSKEY_STATUSES,
  DNSSEC_KEY_TYPES,
  DNSSEC_RECOMMENDATION_PRIORITIES,
  DNSSEC_STATUSES,
  DS_STATUSES,
  FINDING_SEVERITIES,
  PROOF_PURPOSES,
  PROOF_STATUSES,
  PROOF_TYPES,
  RRSET_STATUSES,
  RRSIG_STATUSES,
  SERVER_STATUSES,
  VERIFICATION_RESULTS,
} from './constants';
import type { FindingSlug } from './findings';

// what a DNSSEC analysis is made of: the status vocabulary, the finding catalog, and the
// shape of every object in a report. No code here runs anything, so this entry is safe
// to import anywhere, a browser included
export * from './constants';
export * from './findings';

// the transports the analysis asks its questions over
export type DnssecTransport = 'udp' | 'tcp';

export type DnssecStatus = (typeof DNSSEC_STATUSES)[keyof typeof DNSSEC_STATUSES];
export type VerificationResult = (typeof VERIFICATION_RESULTS)[keyof typeof VERIFICATION_RESULTS];
export type FindingSeverity = (typeof FINDING_SEVERITIES)[keyof typeof FINDING_SEVERITIES];
export type DnssecRecommendationPriority =
  (typeof DNSSEC_RECOMMENDATION_PRIORITIES)[keyof typeof DNSSEC_RECOMMENDATION_PRIORITIES];
export type DnssecKeyType = (typeof DNSSEC_KEY_TYPES)[keyof typeof DNSSEC_KEY_TYPES];
export type DnskeyStatus = (typeof DNSKEY_STATUSES)[keyof typeof DNSKEY_STATUSES];
export type DsStatus = (typeof DS_STATUSES)[keyof typeof DS_STATUSES];
export type RrsigStatus = (typeof RRSIG_STATUSES)[keyof typeof RRSIG_STATUSES];
export type RrsetStatus = (typeof RRSET_STATUSES)[keyof typeof RRSET_STATUSES];
export type ProofStatus = (typeof PROOF_STATUSES)[keyof typeof PROOF_STATUSES];
export type ServerStatus = (typeof SERVER_STATUSES)[keyof typeof SERVER_STATUSES];
export type ProofType = (typeof PROOF_TYPES)[keyof typeof PROOF_TYPES];
export type ProofPurpose = (typeof PROOF_PURPOSES)[keyof typeof PROOF_PURPOSES];
export type AlgorithmStanding = (typeof ALGORITHM_STANDINGS)[keyof typeof ALGORITHM_STANDINGS];

// ---------------------------------------------------------------------------
// findings and recommendations
// ---------------------------------------------------------------------------

// the object a finding is about, so every finding is traceable to a row in the UI tables
export interface FindingSubject {
  zone?: string;
  name?: string;
  recordType?: string;
  keyTag?: number;
  algorithm?: number;
  digestType?: number;
  server?: string;
}

export interface DnssecFinding {
  slug: FindingSlug;
  severity: FindingSeverity;
  title: string;
  // the per-instance sentence: what happened here, in plain language
  message: string;
  subject: FindingSubject;
  // additional subjects when one finding affects several objects — the UI renders these as
  // a chip row instead of repeating the card (ten expired RRsets are one finding, not ten)
  alsoAffects?: FindingSubject[];
  rfc?: string;
  fix?: string;
  // index into the result's query log, pointing at the transaction that produced the evidence
  evidenceQueries?: number[];
}

export interface DnssecRecommendation {
  priority: DnssecRecommendationPriority;
  action: string;
  details?: string;
  subjects?: FindingSubject[];
}

// ---------------------------------------------------------------------------
// records
// ---------------------------------------------------------------------------

// where a record came from, so parent-signed and child-signed data never mix
export interface RecordProvenance {
  zone: string;
  server: string;
  serverHost?: string;
  transport: DnssecTransport;
  section: 'answer' | 'authority' | 'additional';
  // index into the result's query log
  queryIndex?: number;
}

export interface DnssecDnskey {
  name: string;
  ttl: number;
  keyTag: number;
  flags: number;
  protocol: number;
  algorithm: number;
  algorithmName: string;
  keyType: DnssecKeyType;
  sep: boolean;
  revoked: boolean;
  zoneFlag: boolean;
  // bit length of the modulus (RSA) or the curve (EC); undefined when the key is unparseable
  keySize?: number;
  publicKey: string;
  status: DnskeyStatus;
  // how this key was itself authenticated: by a DS in the parent, or by another key in the set
  validatedBy?: string;
  // record types this key produced a verified signature over, in this zone
  signs: string[];
  provenance?: RecordProvenance;
}

// the inputs and outcome of one DS digest computation, shown verbatim in the UI
export interface DigestCheck {
  result: VerificationResult;
  digestType: number;
  digestTypeName: string;
  published: string;
  computed?: string;
  // the expression that produced `computed`, so the user can reproduce it
  input?: string;
  matchedKeyTag?: number;
  reason?: string;
}

export interface DnssecDs {
  name: string;
  ttl: number;
  keyTag: number;
  algorithm: number;
  algorithmName: string;
  digestType: number;
  digestTypeName: string;
  digest: string;
  status: DsStatus;
  check: DigestCheck;
  // true for the DS the delegation's verdict rests on (RFC 4509 §3 strongest-supported-wins)
  selected: boolean;
  provenance?: RecordProvenance;
}

// what was fed to a signature check and what came back, in a form the user can reproduce
export interface SignatureCheck {
  result: VerificationResult;
  // number of RRs in the canonical RRset that was signed
  rrsetSize?: number;
  // byte length of `RRSIG RDATA || canonical RRset`
  signedDataLength?: number;
  signatureLength?: number;
  expectedSignatureLength?: number;
  publicKeyDescription?: string;
  reason?: string;
}

export interface DnssecRrsig {
  name: string;
  ttl: number;
  typeCovered: string;
  algorithm: number;
  algorithmName: string;
  labels: number;
  originalTtl: number;
  // ISO 8601, not Date — a tool result round-trips through a Postgres JSON column
  // (JSON.stringify/parse, no reviver), so a Date field is live-typed on a cold call
  // and a string on every warm one. Constructing the string here instead means every
  // caller sees the same type regardless of cache state.
  inception: string;
  expiration: string;
  // milliseconds until expiry at scan time; negative once expired
  remainingMs: number;
  keyTag: number;
  signerName: string;
  signature: string;
  status: RrsigStatus;
  check: SignatureCheck;
  // true when the signature was made by the parent zone over a delegation record
  fromParent: boolean;
  // true when the RRSIG has fewer labels than its owner name, i.e. the answer was synthesised from
  // a wildcard (RFC 4035 §5.3.4) — such an answer needs a matching proof that the queried name does
  // not otherwise exist
  wildcard?: boolean;
  provenance?: RecordProvenance;
}

// one RRset the tool retrieved, with the signatures covering it
export interface DnssecRrset {
  name: string;
  type: string;
  ttl: number;
  // presentation-format record text, one entry per RR
  records: string[];
  rrsigKeyTags: number[];
  status: RrsetStatus;
  // authoritative data below a secure zone must be signed; delegation NS and glue must not
  authoritative: boolean;
}

// ---------------------------------------------------------------------------
// denial of existence
// ---------------------------------------------------------------------------

export interface Nsec3Params {
  hashAlgorithm: number;
  hashAlgorithmName: string;
  iterations: number;
  salt: string;
  optOut: boolean;
  // RFC 9276 §3.1 assessment of the parameters above
  conforms: boolean;
  notes: string[];
}

export interface DenialProof {
  type: ProofType;
  purpose: ProofPurpose;
  status: ProofStatus;
  result: VerificationResult;
  // the name the proof was asked about
  qname: string;
  // presentation-format text of the NSEC/NSEC3 records that make up the proof
  records: string[];
  // the reasoning, step by step, so "proven unsigned" is checkable rather than asserted
  steps: ProofStep[];
  optOut: boolean;
  nsec3Params?: Nsec3Params;
  reason?: string;
}

export interface ProofStep {
  label: string;
  detail: string;
  result: VerificationResult;
}

// ---------------------------------------------------------------------------
// zones
// ---------------------------------------------------------------------------

export interface DnssecNameserver {
  name: string;
  addresses: string[];
  // the address actually consulted, when one answered
  consulted?: string;
  status: ServerStatus;
  responseMs?: number;
  note?: string;
}

// the parent side of a zone cut: the DS RRset (or the proof that there isn't one)
export interface DnssecDelegation {
  parent: string;
  child: string;
  dsRecords: DnssecDs[];
  // the strongest supported digest type present, which the verdict rests on
  selectedDigestType?: number;
  proofOfNoDs?: DenialProof;
  status: DnssecStatus;
  // the child key tag the delegation successfully authenticates, when it does
  authenticatedKeyTag?: number;
  // whether the secure parent's DS response (the DS RRset, or the NSEC/NSEC3 proof of its absence)
  // carried a valid signature. undefined when the parent is not secure, so there is nothing to
  // authenticate against; false means the response cannot be trusted to anchor or exclude the child
  parentResponseVerified?: boolean;
  reason?: string;
}

export interface DnssecZone {
  zone: string;
  status: DnssecStatus;
  parent?: string;
  // whether a real zone cut was observed here (a label with no cut contributes no zone)
  isZoneCut: boolean;
  nameservers: DnssecNameserver[];
  delegation?: DnssecDelegation;
  dnskeys: DnssecDnskey[];
  rrsets: DnssecRrset[];
  rrsigs: DnssecRrsig[];
  denialOfExistence: DenialProof[];
  nsec3Params?: Nsec3Params;
  // every signing algorithm present in the apex DNSKEY RRset
  algorithms: number[];
  findings: DnssecFinding[];
  elapsed: number;
  reason?: string;
}

// ---------------------------------------------------------------------------
// trust anchor
// ---------------------------------------------------------------------------

export interface TrustAnchor {
  id: string;
  keyTag: number;
  algorithm: number;
  digestType: number;
  digest: string;
  validFrom?: string;
  validUntil?: string;
}

export interface TrustAnchorState {
  source: string;
  anchors: TrustAnchor[];
  // every anchor whose digest matched a published root DNSKEY. during a rollover both are
  // published and both match, which is normal — only one of them is signing
  matchedKeyTags: number[];
  // the anchor that validated the root DNSKEY RRset's signature
  validatedBy?: string;
  validatedKeyTag?: number;
  // key tags published in the root DNSKEY RRset carrying the RFC 5011 revoke bit
  revokedKeyTags: number[];
  result: VerificationResult;
  reason?: string;
}

// ---------------------------------------------------------------------------
// evidence and debug
// ---------------------------------------------------------------------------

export interface DnssecQueryLogEntry {
  index: number;
  timestamp: string;
  zone: string;
  qname: string;
  qtype: string;
  server: string;
  serverHost?: string;
  transport: DnssecTransport;
  // flags sent, e.g. ['DO', 'CD']
  flagsSent: string[];
  // flags observed in the response, e.g. ['AA', 'AD', 'TC']
  flagsReceived: string[];
  ednsBufferSize: number;
  rcode: string;
  extendedError?: string;
  bytes?: number;
  elapsed: number;
  // set when the answer came from a UDP truncation retried over TCP
  retriedOverTcp?: boolean;
  error?: string;
}

export interface ResolverCrossCheck {
  resolver: string;
  address: string;
  rcode: string;
  adBit: boolean;
  extendedError?: string;
  elapsed?: number;
  error?: string;
}

// one cell of the nameserver × RRset consistency matrix
export interface ServerMatrixCell {
  server: string;
  zone: string;
  rrset: string;
  status: VerificationResult;
  note?: string;
}
