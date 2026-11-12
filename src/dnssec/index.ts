// DNSSEC primitives: signature verification, DS digests and key tags, NSEC and NSEC3
// denial proofs, the root trust anchors, and the canonical form signatures are computed
// over

export {
  ROOT_TRUST_ANCHORS,
  ROOT_TRUST_ANCHOR_SOURCE,
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
  decodeDnskey,
  decodeDs,
  decodeNsec,
  decodeNsec3,
  decodeNsec3Param,
  decodeRrsig,
  decodeTypeBitmap,
  groupRrsets,
  nsec3Hash,
  presentRecord,
  toWireMessage,
  wildcardOwner,
} from './wire';
export type { Rrset, WireMessage, WireRecord } from './wire';
export { sha1, sha256, sha384 } from './hash';
export * from './constants';
export type * from './types';
