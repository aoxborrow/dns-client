// DNSSEC primitives: signature verification, DS digests and key tags, NSEC and NSEC3
// denial proofs, the root trust anchors, and the canonical form signatures are computed
// over. The record data these work on is decoded by `/records` (decodeRrsig, decodeDnskey,
// decodeDs, decodeNsec, decodeNsec3, decodeNsec3Param) and names by `/wire`

export {
  ROOT_TRUST_ANCHORS,
  ROOT_TRUST_ANCHOR_SOURCE,
  ROOT_TRUST_ANCHORS_DATA_VERSION,
  ROOT_TRUST_ANCHORS_REFRESHED,
} from './anchors';
export {
  algorithmName,
  isAlgorithmSupported,
  isAlgorithmVerifiable,
  keySizeBits,
  verifySignature,
} from './crypto';
export type { VerifyOutcome } from './crypto';
export {
  assessNsec3Params,
  verifyNoDsProof,
  verifyNodataProof,
  verifyNxdomainProof,
  verifyWildcardProof,
} from './nsec';
export {
  buildSignedData,
  canonicalRdata,
  computeDsDigest,
  computeKeyTag,
  groupRrsets,
  nsec3Hash,
  wildcardOwner,
} from './canonical';
export type { Rrset } from './canonical';
export {
  isDigestDeprecated,
  readKeys,
  CHECK_LIMITS,
  DS_CODES,
  KEY_SET_CODES,
  RRSET_CODES,
  SIGNATURE_CODES,
} from './checks';
export type {
  AnchorCheck,
  CheckLimits,
  DnssecKey,
  DsCheck,
  DsCode,
  DsSetCheck,
  KeySetCheck,
  KeySetCode,
  RrsetCheck,
  RrsetCode,
  SignatureCheck,
  SignatureCode,
} from './checks';
export { judgeChain } from './judge';
export type {
  ChainInput,
  ChainLink,
  ChainName,
  DenialEvidence,
  DnssecResponse,
  JudgedLink,
  JudgeMode,
  JudgeOptions,
  Judgement,
  KeysEvidence,
  LinkEvidence,
  LinkKind,
  RrsetEvidence,
  ZoneFact,
  ZoneState,
} from './judge';
export { REASON_CODES, SECURITY_STATUSES } from './reasons';
export type { ReasonCode, SecurityReason, SecurityStatus } from './reasons';
export type { Security } from './validate';
export {
  ALGORITHM_REGISTRY_REFRESHED,
  ALGORITHM_STANDINGS,
  DNSKEY_FLAGS,
  DNSKEY_PROTOCOL,
  DNSSEC_ALGORITHMS,
  DS_DIGEST_TYPES,
  NSEC3_FLAGS,
  NSEC3_HASH_ALGORITHMS,
  NSEC3_ITERATIONS_INSECURE_THRESHOLD,
  NSEC3_ITERATIONS_SERVFAIL_THRESHOLD,
  PROOF_PURPOSES,
  PROOF_STATUSES,
  PROOF_TYPES,
  VERIFICATION_RESULTS,
} from './constants';
export type * from './types';
