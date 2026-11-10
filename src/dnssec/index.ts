import { DnssecEngine } from './engine';
import type { EngineOptions, EngineOutput } from './engine';

// DNSSEC: the analysis of a name's chain of trust, and the primitives it is built from

export type AnalyzeOptions = EngineOptions;
export type DnssecReport = EngineOutput;

// analyze the chain of trust for a name, from the root trust anchor down: every zone on
// the way, its keys, its delegation, the signatures over what it answers, and what was
// found wrong. The report is a description, not a verdict to act on blindly: each object
// in it carries its own status and the reason for it
export function analyze(name: string, options: AnalyzeOptions = {}): Promise<DnssecReport> {
  return new DnssecEngine(options).run(name);
}

export { DnssecEngine } from './engine';
export type { EngineOptions, EngineOutput } from './engine';
export {
  ROOT_TRUST_ANCHORS,
  ROOT_TRUST_ANCHOR_SOURCE,
  ROOT_TRUST_ANCHORS_REFRESHED,
  KSK_2024_SIGNING_DATE,
  KSK_2017_REVOCATION_DATE,
  isAnchorCurrent,
} from './anchors';
export { algorithmName, isAlgorithmVerifiable, keySizeBits, verifySignature } from './crypto';
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
} from './wire';
export type { Rrset, WireMessage, WireRecord } from './wire';
export { sha1, sha256, sha384 } from './hash';
export * from './types';
