// DNSSEC primitives: signature verification, DS digests and key tags, NSEC and NSEC3
// denial proofs, the root trust anchors, and the canonical form signatures are computed
// over. The record data these work on is decoded by `/records` (decodeRrsig, decodeDnskey,
// decodeDs, decodeNsec, decodeNsec3, decodeNsec3Param) and names by `/wire`

export {
  ROOT_TRUST_ANCHORS,
  ROOT_TRUST_ANCHOR_SOURCE,
  ROOT_TRUST_ANCHORS_DATA_VERSION,
  ROOT_TRUST_ANCHORS_REFRESHED,
  isAnchorCurrent,
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
  compareCanonicalNames,
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
  toWireMessage,
  wildcardOwner,
} from './canonical';
export type { Rrset, WireMessage, WireRecord } from './canonical';
export {
  checkAnchors,
  checkBudget,
  checkDsSet,
  checkKeySet,
  checkRrset,
  checkSignature,
  coveringSignatures,
  isAuthoritative,
  isDigestDeprecated,
  keyAlgorithms,
  readKeys,
  readRrsig,
  CHECK_LIMITS,
  DS_CODES,
  KEY_SET_CODES,
  RRSET_CODES,
  SIGNATURE_CODES,
} from './checks';
export type {
  AnchorCheck,
  CheckBudget,
  CheckLimits,
  DnssecKey,
  DsCheck,
  DsCode,
  DsSetCheck,
  KeySetCheck,
  KeySetCode,
  RrsetCheck,
  RrsetCheckOptions,
  RrsetCode,
  SignatureCheck,
  SignatureCode,
  ZoneKeys,
} from './checks';
export { judgeChain, judgeKeys } from './judge';
export type {
  ChainInput,
  ChainLink,
  ChainName,
  DnssecResponse,
  JudgeMode,
  JudgeOptions,
  Judgement,
  LinkKind,
  ZoneFact,
  KeysEntry,
  ZoneKeysJudgement,
} from './judge';
export { EDE_CODES, REASON_CODES, REASON_EDE, SECURITY_STATUSES, securityReason } from './reasons';
export type { ReasonCode, SecurityReason, SecurityStatus } from './reasons';
export { denialTypesAt, nextCloserOptOut } from './nsec';
export { presentRecord } from './present';
export { sha1, sha256, sha384 } from './hash';
export * from './constants';
export type * from './types';
