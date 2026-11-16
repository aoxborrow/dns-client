import {
  ALGORITHM_STANDINGS,
  PROOF_PURPOSES,
  PROOF_STATUSES,
  PROOF_TYPES,
  VERIFICATION_RESULTS,
} from './constants';

// the shapes the DNSSEC primitives return: the outcome of a check, a denial-of-existence
// proof with its reasoning, and a trust anchor

export type VerificationResult = (typeof VERIFICATION_RESULTS)[keyof typeof VERIFICATION_RESULTS];
export type ProofStatus = (typeof PROOF_STATUSES)[keyof typeof PROOF_STATUSES];
export type ProofType = (typeof PROOF_TYPES)[keyof typeof PROOF_TYPES];
export type ProofPurpose = (typeof PROOF_PURPOSES)[keyof typeof PROOF_PURPOSES];
export type AlgorithmStanding = (typeof ALGORITHM_STANDINGS)[keyof typeof ALGORITHM_STANDINGS];

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
// trust anchor
// ---------------------------------------------------------------------------

export interface TrustAnchor {
  id: string;
  // the zone the anchor is for. Default: the root
  zone?: string;
  keyTag: number;
  algorithm: number;
  digestType: number;
  digest: string;
  validFrom?: Date;
  validUntil?: Date;
}
