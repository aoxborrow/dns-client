import { ParseError } from '../errors';
import { RECORD_TYPES, typeName } from '../protocol/types';
import { decodeDnskey, decodeDs, decodeRrsig } from '../records/decode';
import type { DsFields, RrsigFields } from '../records/decode';
import { bytesEqual, toHex } from '../wire/bytes';
import { canonicalName, countLabels, isSubdomain } from '../wire/names';
import { isAnchorCurrent } from './anchors';
import { buildSignedData, computeDsDigest, computeKeyTag } from './canonical';
import type { Rrset, WireRecord } from './canonical';
import {
  DNSKEY_FLAGS,
  DNSKEY_PROTOCOL,
  DS_DIGEST_TYPES,
  VERIFICATION_RESULTS,
  ALGORITHM_STANDINGS,
} from './constants';
import { isAlgorithmSupported, verifySignature } from './crypto';
import type { TrustAnchor, VerificationResult } from './types';

// the checks a DNSSEC judgement is made of, one object at a time: a key against a trust
// anchor, a DS against a key, a signature against an RRset, an RRset against its zone's
// keys, a key set against the keys its parent vouches for. Each returns what it found as
// data with a code, never English, so a validating resolver and a report of every fault
// read the same results. `judge.ts` puts them together into a verdict for a chain

const { VERIFIED, FAILED, UNCHECKED } = VERIFICATION_RESULTS;
const { DNSKEY, NS, A, AAAA } = RECORD_TYPES;

// record data that does not decode is left out: it proves nothing
function decoded<T>(decode: (rdata: Uint8Array) => T, rdata: Uint8Array): T | undefined {
  try {
    return decode(rdata);
  } catch (error) {
    if (error instanceof ParseError) return undefined;
    throw error;
  }
}

// an RRSIG's fields, or undefined for one that does not decode
export function readRrsig(record: WireRecord): RrsigFields | undefined {
  return decoded(decodeRrsig, record.rdata);
}

// ---------------------------------------------------------------------------
// the work one judgement may do
// ---------------------------------------------------------------------------

// how much signature checking one judgement may do. A zone that publishes many keys with
// the same tag, or signs an RRset many times over, can make a validator run thousands of
// signature checks for one answer (KeyTrap, CVE-2023-50387); validators since cap that
// work and fail the answer past the cap. Without a budget nothing is capped, as for a
// report that wants every check made
export interface CheckBudget {
  // signature verifications left for the whole judgement
  remaining: number;
  // the most keys tried for one signature, where several share its tag and algorithm
  keysPerSignature: number;
  // the most signatures checked for one RRset
  signaturesPerRrset: number;
}

export interface CheckLimits {
  // signature verifications for the whole judgement
  verifications: number;
  keysPerSignature: number;
  signaturesPerRrset: number;
}

export const CHECK_LIMITS: Readonly<CheckLimits> = {
  verifications: 128,
  keysPerSignature: 4,
  signaturesPerRrset: 8,
};

// a fresh budget, at the default limits unless told otherwise
export function checkBudget(limits: Partial<CheckLimits> = {}): CheckBudget {
  return {
    remaining: limits.verifications ?? CHECK_LIMITS.verifications,
    keysPerSignature: limits.keysPerSignature ?? CHECK_LIMITS.keysPerSignature,
    signaturesPerRrset: limits.signaturesPerRrset ?? CHECK_LIMITS.signaturesPerRrset,
  };
}

// take one verification from the budget: false when none is left
function spend(budget: CheckBudget | undefined): boolean {
  if (!budget) return true;
  if (budget.remaining <= 0) return false;
  budget.remaining--;
  return true;
}

// ---------------------------------------------------------------------------
// keys
// ---------------------------------------------------------------------------

export interface DnssecKey {
  record: WireRecord;
  keyTag: number;
  flags: number;
  protocol: number;
  algorithm: number;
  publicKey: Uint8Array;
  // the Secure Entry Point flag: the key a parent's DS normally points at
  sep: boolean;
  // the RFC 5011 revoke bit
  revoked: boolean;
  // the Zone flag: a key without it may not sign the zone's data
  zoneFlag: boolean;
}

// the DNSKEY records among `records`, read. One that does not decode is left out
export function readKeys(records: readonly WireRecord[]): DnssecKey[] {
  const keys: DnssecKey[] = [];
  for (const record of records) {
    if (record.type !== DNSKEY) continue;
    const key = decoded(decodeDnskey, record.rdata);
    if (!key) continue;
    keys.push({
      record,
      keyTag: computeKeyTag(record.rdata),
      flags: key.flags,
      protocol: key.protocol,
      algorithm: key.algorithm,
      publicKey: key.publicKey,
      sep: Boolean(key.flags & DNSKEY_FLAGS.SEP),
      revoked: Boolean(key.flags & DNSKEY_FLAGS.REVOKE),
      zoneFlag: Boolean(key.flags & DNSKEY_FLAGS.ZONE),
    });
  }
  return keys;
}

// whether a key may sign its zone's data at all (RFC 4034 §2.1, RFC 5011 §2.1)
function maySign(key: DnssecKey): boolean {
  return key.zoneFlag && !key.revoked && key.protocol === DNSKEY_PROTOCOL;
}

// the algorithms a zone's key set holds, in order
export function keyAlgorithms(keys: readonly DnssecKey[]): number[] {
  return [...new Set(keys.map(key => key.algorithm))].sort((a, b) => a - b);
}

// ---------------------------------------------------------------------------
// trust anchors
// ---------------------------------------------------------------------------

export interface AnchorCheck {
  // verified when a published key hashes to a current trust anchor
  result: VerificationResult;
  // the published keys that do, in the order they were published
  keys: DnssecKey[];
  // the anchors they match, each once, in the order first matched
  anchors: TrustAnchor[];
  // the key tags of published keys with the revoke bit set
  revokedKeyTags: number[];
  // anchors whose key is published with the revoke bit and signs the key set itself, so
  // it is revoked (RFC 5011 §2.1) and anchors nothing, whatever its validity window says
  revokedAnchors: TrustAnchor[];
}

// a key's record data with the revoke bit cleared: the form its anchor was taken from
function unrevoked(key: DnssecKey): Uint8Array {
  const rdata = Uint8Array.from(key.record.rdata);
  rdata[1] &= ~DNSKEY_FLAGS.REVOKE & 0xff;
  return rdata;
}

function digestMatches(owner: string, rdata: Uint8Array, anchor: TrustAnchor): boolean {
  const digest = computeDsDigest(owner, rdata, anchor.digestType);
  return Boolean(digest) && toHex(digest!) === anchor.digest.toLowerCase();
}

// which published keys a set of trust anchors vouches for. A key is anchored by its own
// material hashing to a current anchor, never by sharing a key tag with one: tags collide,
// and a colliding key added to the set could otherwise vouch for it. `rrset` and
// `rrsigs`, when given, are the key set and its signatures, used to tell a revoked anchor:
// one whose key appears with the revoke bit set and has signed the set with it
export async function checkAnchors(
  zone: string,
  keys: readonly DnssecKey[],
  anchors: readonly TrustAnchor[],
  now: Date,
  signed?: { rrset: Rrset; rrsigs: readonly WireRecord[] },
  budget?: CheckBudget
): Promise<AnchorCheck> {
  const current = anchors.filter(
    anchor =>
      canonicalName(anchor.zone ?? '.') === canonicalName(zone) && isAnchorCurrent(anchor, now)
  );
  const check: AnchorCheck = {
    result: FAILED,
    keys: [],
    anchors: [],
    revokedKeyTags: [],
    revokedAnchors: [],
  };

  for (const key of keys) {
    if (key.revoked) {
      check.revokedKeyTags.push(key.keyTag);
      if (signed) {
        const anchor = current.find(candidate => digestMatches(zone, unrevoked(key), candidate));
        if (anchor && (await selfSigned(key, signed.rrset, signed.rrsigs, now, budget))) {
          check.revokedAnchors.push(anchor);
        }
      }
    }
  }

  for (const key of keys) {
    for (const anchor of current) {
      if (check.revokedAnchors.includes(anchor)) continue;
      if (!digestMatches(zone, key.record.rdata, anchor)) continue;
      check.result = VERIFIED;
      if (!check.keys.includes(key)) check.keys.push(key);
      if (!check.anchors.some(seen => seen.keyTag === anchor.keyTag)) check.anchors.push(anchor);
    }
  }
  return check;
}

// whether a revoked key has signed the key set with itself, as RFC 5011 §2.1 requires
// before a revocation counts
async function selfSigned(
  key: DnssecKey,
  rrset: Rrset,
  rrsigs: readonly WireRecord[],
  now: Date,
  budget?: CheckBudget
): Promise<boolean> {
  for (const record of rrsigs) {
    const sig = readRrsig(record);
    if (!sig || sig.typeCovered !== DNSKEY) continue;
    if (sig.keyTag !== key.keyTag || sig.algorithm !== key.algorithm) continue;
    if (!withinValidity(sig, now)) continue;
    const signedData = buildSignedData(sig, rrset);
    if (!signedData) continue;
    if (!spend(budget)) return false;
    const outcome = await verifySignature(
      key.algorithm,
      key.publicKey,
      signedData.data,
      sig.signature
    );
    if (outcome.verified === true) return true;
  }
  return false;
}

// RRSIG times are 32-bit seconds that wrap, compared with RFC 1982 serial arithmetic
// (RFC 4034 §3.1.5): whether `a` comes after `b`
function serialAfter(a: number, b: number): boolean {
  const distance = (((a - b) % 2 ** 32) + 2 ** 32) % 2 ** 32;
  return distance > 0 && distance < 2 ** 31;
}

const expired = (sig: RrsigFields, now: Date) =>
  serialAfter(Math.floor(now.getTime() / 1000), sig.expiration);
const notYetValid = (sig: RrsigFields, now: Date) =>
  serialAfter(sig.inception, Math.floor(now.getTime() / 1000));

function withinValidity(sig: RrsigFields, now: Date): boolean {
  return !expired(sig, now) && !notYetValid(sig, now);
}

// ---------------------------------------------------------------------------
// DS records
// ---------------------------------------------------------------------------

export const DS_CODES = {
  VERIFIED: 'verified',
  // a digest type nothing here computes
  UNSUPPORTED_DIGEST: 'unsupported-digest',
  // a stronger supported digest type is published beside it, so it is ignored (RFC 4509 §3)
  IGNORED_WEAKER_DIGEST: 'ignored-weaker-digest',
  // the zone publishes no key with its key tag
  NO_MATCHING_KEY: 'no-matching-key',
  // the keys with its tag use another algorithm
  ALGORITHM_MISMATCH: 'algorithm-mismatch',
  // no key with its tag and algorithm hashes to its digest
  DIGEST_MISMATCH: 'digest-mismatch',
} as const;

export type DsCode = (typeof DS_CODES)[keyof typeof DS_CODES];

export interface DsCheck {
  record: WireRecord;
  ds: DsFields;
  code: DsCode;
  result: VerificationResult;
  // whether the digest selection kept it (RFC 4509 §3)
  selected: boolean;
  // the published keys with its key tag
  candidates: DnssecKey[];
  // the digest computed over the last candidate tried, in hex
  computed?: string;
  // the key it authenticates
  key?: DnssecKey;
}

export interface DsSetCheck {
  checks: DsCheck[];
  // the strongest supported digest type published, which decides
  selectedDigestType?: number;
  // the keys the DS set authenticates, in the order the DS records came
  keys: DnssecKey[];
  // the algorithms of the DS records the selection kept
  algorithms: number[];
}

type DigestInfo = (typeof DS_DIGEST_TYPES)[keyof typeof DS_DIGEST_TYPES];
const digestInfo = (type: number): DigestInfo | undefined =>
  DS_DIGEST_TYPES[type as keyof typeof DS_DIGEST_TYPES];

// whether a digest type is deprecated (SHA-1)
export function isDigestDeprecated(type: number): boolean {
  return digestInfo(type)?.standing === ALGORITHM_STANDINGS.DEPRECATED;
}

// RFC 4034 §5.1.4 digest verification, with the RFC 4509 §3 selection rule on top: the
// strongest supported digest type present decides, and a weaker type cannot rescue it.
// Every candidate key sharing a DS's tag is tried, so a colliding key can neither mask the
// real one nor stand in for it
export function checkDsSet(
  child: string,
  dsRecords: readonly WireRecord[],
  keys: readonly DnssecKey[]
): DsSetCheck {
  const read = dsRecords
    .map(record => ({ record, ds: decoded(decodeDs, record.rdata) }))
    .filter((entry): entry is { record: WireRecord; ds: DsFields } => Boolean(entry.ds));

  const supported = read.filter(({ ds }) => digestInfo(ds.digestType)?.verify);
  const selectedDigestType = supported.length
    ? supported.reduce((best, entry) =>
        digestInfo(entry.ds.digestType)!.strength > digestInfo(best.ds.digestType)!.strength
          ? entry
          : best
      ).ds.digestType
    : undefined;

  const set: DsSetCheck = { checks: [], selectedDigestType, keys: [], algorithms: [] };

  for (const { record, ds } of read) {
    const candidates = keys.filter(key => key.keyTag === ds.keyTag);
    const check: DsCheck = {
      record,
      ds,
      code: DS_CODES.NO_MATCHING_KEY,
      result: UNCHECKED,
      selected: false,
      candidates,
    };
    set.checks.push(check);

    if (!digestInfo(ds.digestType)?.verify) {
      check.code = DS_CODES.UNSUPPORTED_DIGEST;
      continue;
    }
    if (selectedDigestType !== undefined && ds.digestType !== selectedDigestType) {
      check.code = DS_CODES.IGNORED_WEAKER_DIGEST;
      continue;
    }

    check.selected = true;
    set.algorithms.push(ds.algorithm);
    check.result = FAILED;

    if (candidates.length === 0) {
      check.code = DS_CODES.NO_MATCHING_KEY;
      continue;
    }
    const sameAlgorithm = candidates.filter(key => key.algorithm === ds.algorithm);
    if (sameAlgorithm.length === 0) {
      check.code = DS_CODES.ALGORITHM_MISMATCH;
      continue;
    }

    const published = toHex(ds.digest);
    for (const key of sameAlgorithm) {
      const computed = computeDsDigest(child, key.record.rdata, ds.digestType);
      check.computed = computed ? toHex(computed) : undefined;
      if (computed && check.computed === published) {
        check.key = key;
        break;
      }
    }
    if (check.key) {
      check.code = DS_CODES.VERIFIED;
      check.result = VERIFIED;
      set.keys.push(check.key);
    } else {
      check.code = DS_CODES.DIGEST_MISMATCH;
    }
  }
  return set;
}

// ---------------------------------------------------------------------------
// signatures
// ---------------------------------------------------------------------------

export const SIGNATURE_CODES = {
  VERIFIED: 'verified',
  // the signer name is not the zone the RRset is judged in
  SIGNER_MISMATCH: 'signer-mismatch',
  // the labels field claims more labels than the owner name has
  LABELS_EXCEED_OWNER: 'labels-exceed-owner',
  // the zone publishes no key with the signature's tag and algorithm
  NO_MATCHING_KEY: 'no-matching-key',
  ZONE_FLAG_UNSET: 'zone-flag-unset',
  PROTOCOL_NOT_3: 'protocol-not-3',
  REVOKED_KEY: 'revoked-key',
  EXPIRED: 'expired',
  NOT_YET_VALID: 'not-yet-valid',
  // the RRset could not be put in canonical form
  NOT_CANONICAL: 'not-canonical',
  // the signature is the wrong length for its algorithm
  BAD_LENGTH: 'bad-length',
  // checked, and it does not match the data
  INVALID: 'invalid',
  // made with an algorithm this runtime cannot verify
  UNSUPPORTED_ALGORITHM: 'unsupported-algorithm',
  // made by another zone's key, and left for that zone to judge
  FOREIGN: 'foreign',
  // not checked: the judgement had used up the signature checks it may make
  LIMIT_EXCEEDED: 'limit-exceeded',
} as const;

export type SignatureCode = (typeof SIGNATURE_CODES)[keyof typeof SIGNATURE_CODES];

export interface SignatureCheck {
  record: WireRecord;
  rrsig: RrsigFields;
  code: SignatureCode;
  result: VerificationResult;
  // the key it was checked against
  key?: DnssecKey;
  // fewer labels than its owner: the answer was synthesized from a wildcard
  wildcard?: boolean;
  // the RRset's TTL is above the original TTL the signature records
  ttlExceedsOriginal?: boolean;
  signedDataLength?: number;
  signatureLength?: number;
  expectedSignatureLength?: number;
  publicKeyDescription?: string;
  // what the crypto said, as it said it
  detail?: string;
}

// check one RRSIG over an RRset in `zone` with the zone's keys, every RFC 4035 §5.3.1
// precondition before any crypto runs. Where keys share the signature's tag and
// algorithm, each that may sign is tried
export async function checkSignature(
  record: WireRecord,
  rrset: Rrset,
  zone: string,
  keys: readonly DnssecKey[],
  now: Date,
  budget?: CheckBudget
): Promise<SignatureCheck> {
  const rrsig = readRrsig(record);
  if (!rrsig) {
    return {
      record,
      rrsig: undefined as unknown as RrsigFields,
      code: SIGNATURE_CODES.INVALID,
      result: FAILED,
    };
  }
  const check: SignatureCheck = { record, rrsig, code: SIGNATURE_CODES.VERIFIED, result: FAILED };
  const fail = (code: SignatureCode) => ({ ...check, code, result: FAILED });

  if (canonicalName(rrsig.signerName) !== canonicalName(zone)) {
    return fail(SIGNATURE_CODES.SIGNER_MISMATCH);
  }
  if (rrsig.labels > countLabels(record.name)) return fail(SIGNATURE_CODES.LABELS_EXCEED_OWNER);

  const candidates = keys.filter(
    key => key.keyTag === rrsig.keyTag && key.algorithm === rrsig.algorithm
  );
  if (candidates.length === 0) return fail(SIGNATURE_CODES.NO_MATCHING_KEY);
  const usable = candidates.filter(maySign);
  // with no key that may sign, the first candidate says why
  if (usable.length === 0) {
    const [key] = candidates;
    check.key = key;
    if (!key.zoneFlag) return fail(SIGNATURE_CODES.ZONE_FLAG_UNSET);
    if (key.protocol !== DNSKEY_PROTOCOL) return fail(SIGNATURE_CODES.PROTOCOL_NOT_3);
    return fail(SIGNATURE_CODES.REVOKED_KEY);
  }
  check.key = usable[0];

  // temporal validity, before the crypto, so an expired signature reads as expired
  if (expired(rrsig, now)) return fail(SIGNATURE_CODES.EXPIRED);
  if (notYetValid(rrsig, now)) return fail(SIGNATURE_CODES.NOT_YET_VALID);

  if (rrset.ttl > rrsig.originalTtl) check.ttlExceedsOriginal = true;

  const signedData = buildSignedData(rrsig, rrset);
  if (!signedData) return fail(SIGNATURE_CODES.NOT_CANONICAL);
  check.wildcard = signedData.wildcard;
  check.signedDataLength = signedData.data.length;
  check.signatureLength = rrsig.signature.length;

  let first: SignatureCheck | undefined;
  const tries = budget ? usable.slice(0, budget.keysPerSignature) : usable;
  for (const key of tries) {
    if (!spend(budget)) return first ?? fail(SIGNATURE_CODES.LIMIT_EXCEEDED);
    const outcome = await verifySignature(
      key.algorithm,
      key.publicKey,
      signedData.data,
      rrsig.signature
    );
    const tried: SignatureCheck = {
      ...check,
      key,
      result: outcome.verified === undefined ? UNCHECKED : outcome.verified ? VERIFIED : FAILED,
      expectedSignatureLength: outcome.expectedSignatureLength,
      publicKeyDescription: outcome.publicKeyDescription,
      detail: outcome.reason,
    };
    if (tried.result === VERIFIED) {
      tried.code = SIGNATURE_CODES.VERIFIED;
    } else if (tried.result === UNCHECKED) {
      tried.code = SIGNATURE_CODES.UNSUPPORTED_ALGORITHM;
    } else if (
      outcome.expectedSignatureLength &&
      rrsig.signature.length !== outcome.expectedSignatureLength
    ) {
      tried.code = SIGNATURE_CODES.BAD_LENGTH;
    } else {
      tried.code = SIGNATURE_CODES.INVALID;
    }
    if (tried.result === VERIFIED) return tried;
    first ??= tried;
  }
  return first!;
}

// ---------------------------------------------------------------------------
// RRsets
// ---------------------------------------------------------------------------

export const RRSET_CODES = {
  // a signature from the zone verified it
  VERIFIED: 'verified',
  // signed by the zone, and no signature verified
  UNVERIFIED: 'unverified',
  // no signature from the zone covers it
  UNSIGNED: 'unsigned',
  // verified, but not by every algorithm in the key set (RFC 4035 §2.2)
  MISSING_ALGORITHM: 'missing-algorithm',
} as const;

export type RrsetCode = (typeof RRSET_CODES)[keyof typeof RRSET_CODES];

export interface RrsetCheck {
  rrset: Rrset;
  // false for the NS RRset of a delegation and for glue, which the parent does not sign
  // (RFC 4035 §2.2)
  authoritative: boolean;
  code: RrsetCode;
  // the signatures covering it, in the order they came. One made by another zone is
  // recorded as `foreign` and not checked
  signatures: SignatureCheck[];
  // the algorithms of the key set no verified signature used, when every algorithm is
  // required
  missingAlgorithms: number[];
}

export interface ZoneKeys {
  zone: string;
  keys: readonly DnssecKey[];
}

export interface RrsetCheckOptions {
  now: Date;
  // the child zone, when the RRset came with a referral to it: its NS RRset is then the
  // delegation's, which the parent does not sign
  delegationOf?: string;
  // require a signature from every algorithm in the key set (RFC 4035 §2.2). Validators
  // accept any one (RFC 6840 §5.11), so off by default
  requireEveryAlgorithm?: boolean;
  // stop at the first signature that verifies
  stopAtFirst?: boolean;
  // the signature checks the judgement may still make
  budget?: CheckBudget;
}

// the RRSIGs among `rrsigs` that cover `rrset`
export function coveringSignatures(rrset: Rrset, rrsigs: readonly WireRecord[]): WireRecord[] {
  const owner = canonicalName(rrset.name);
  return rrsigs.filter(record => {
    const sig = readRrsig(record);
    return sig?.typeCovered === rrset.type && canonicalName(record.name) === owner;
  });
}

// whether an RRset is the zone's own data, as opposed to a delegation's NS RRset or glue
export function isAuthoritative(rrset: Rrset, zone: string, delegationOf?: string): boolean {
  const delegationNs =
    rrset.type === NS &&
    delegationOf !== undefined &&
    canonicalName(rrset.name) === canonicalName(delegationOf);
  const glue = (rrset.type === A || rrset.type === AAAA) && !isSubdomain(rrset.name, zone);
  return !delegationNs && !glue;
}

// judge an RRset in its zone. Only a signature from the zone can authenticate the zone's
// data (RFC 4035 §5.3.1): an RRset whose only signatures name another signer is unsigned,
// or a server could strip the real RRSIG and attach an off-zone one
export async function checkRrset(
  zone: ZoneKeys,
  rrset: Rrset,
  rrsigs: readonly WireRecord[],
  options: RrsetCheckOptions
): Promise<RrsetCheck> {
  const authoritative = isAuthoritative(rrset, zone.zone, options.delegationOf);
  const check: RrsetCheck = {
    rrset,
    authoritative,
    code: RRSET_CODES.UNSIGNED,
    signatures: [],
    missingAlgorithms: [],
  };
  const covering = coveringSignatures(rrset, rrsigs);
  if (covering.length === 0) return check;

  let inZone = false;
  let checked = 0;
  const verifiedAlgorithms = new Set<number>();
  const stop = options.stopAtFirst && !options.requireEveryAlgorithm;
  for (const record of covering) {
    const rrsig = readRrsig(record)!;
    if (canonicalName(rrsig.signerName) !== canonicalName(zone.zone)) {
      check.signatures.push({ record, rrsig, code: SIGNATURE_CODES.FOREIGN, result: UNCHECKED });
      continue;
    }
    inZone = true;
    if (stop && verifiedAlgorithms.size > 0) continue;
    if (options.budget && checked >= options.budget.signaturesPerRrset) {
      check.signatures.push({
        record,
        rrsig,
        code: SIGNATURE_CODES.LIMIT_EXCEEDED,
        result: UNCHECKED,
      });
      continue;
    }
    checked++;
    const signature = await checkSignature(
      record,
      rrset,
      zone.zone,
      zone.keys,
      options.now,
      options.budget
    );
    check.signatures.push(signature);
    if (signature.result === VERIFIED) verifiedAlgorithms.add(rrsig.algorithm);
  }

  if (authoritative && !inZone) return check;
  check.code = verifiedAlgorithms.size > 0 ? RRSET_CODES.VERIFIED : RRSET_CODES.UNVERIFIED;

  const algorithms = keyAlgorithms(zone.keys);
  if (
    options.requireEveryAlgorithm &&
    authoritative &&
    algorithms.length > 1 &&
    verifiedAlgorithms.size > 0
  ) {
    check.missingAlgorithms = algorithms.filter(algorithm => !verifiedAlgorithms.has(algorithm));
    if (check.missingAlgorithms.length) check.code = RRSET_CODES.MISSING_ALGORITHM;
  }
  return check;
}

// ---------------------------------------------------------------------------
// key sets
// ---------------------------------------------------------------------------

export const KEY_SET_CODES = {
  // signed by a key an entry point vouches for
  VERIFIED: 'verified',
  // no DNSKEY response
  NO_RESPONSE: 'no-response',
  // a response with no DNSKEY RRset in it
  NO_RRSET: 'no-rrset',
  // the DNSKEY RRset carries no signature
  UNSIGNED: 'unsigned',
  // nothing links the key set: every algorithm the entry points name is one this runtime
  // cannot verify (RFC 4035 §5.2, RFC 6840 §5.2)
  NO_SUPPORTED_ALGORITHM: 'no-supported-algorithm',
  // no published key is one an entry point vouches for
  NO_ENTRY_KEY: 'no-entry-key',
  // keys are vouched for, and none of them signed the key set validly
  NOT_SIGNED_BY_ENTRY_KEY: 'not-signed-by-entry-key',
} as const;

export type KeySetCode = (typeof KEY_SET_CODES)[keyof typeof KEY_SET_CODES];

export interface KeySetCheck {
  code: KeySetCode;
  // the DNSKEY RRset
  rrset?: Rrset;
  // every signature over it, each checked against the zone's keys
  signatures: SignatureCheck[];
  // the tag of the vouched-for key whose signature verified it
  keyTag?: number;
}

// the DNSKEY RRset must carry a signature from a key an entry point (the trust anchor at
// the top, the parent's DS elsewhere) vouches for. This is the link that makes the chain
// a chain. The signature is bound to the vouched-for key's material, not its tag
export async function checkKeySet(
  zone: string,
  dnskey: { answers: readonly WireRecord[] } | undefined,
  keys: readonly DnssecKey[],
  entryKeys: readonly DnssecKey[],
  entryAlgorithms: readonly number[],
  now: Date,
  options: { stopAtFirst?: boolean; budget?: CheckBudget } = {}
): Promise<KeySetCheck> {
  if (!dnskey) return { code: KEY_SET_CODES.NO_RESPONSE, signatures: [] };
  const owner = canonicalName(zone);
  const records = dnskey.answers.filter(
    record => record.type === DNSKEY && canonicalName(record.name) === owner
  );
  if (records.length === 0) return { code: KEY_SET_CODES.NO_RRSET, signatures: [] };
  const rrset = groupRrsets1(records);

  const rrsigs = coveringSignatures(
    rrset,
    dnskey.answers.filter(record => record.type === RECORD_TYPES.RRSIG)
  );
  if (rrsigs.length === 0) return { code: KEY_SET_CODES.UNSIGNED, rrset, signatures: [] };

  const check: KeySetCheck = { code: KEY_SET_CODES.NOT_SIGNED_BY_ENTRY_KEY, rrset, signatures: [] };
  // signatures by a vouched-for key that could not be checked: this runtime has no way to
  // verify their algorithm
  let vouchedUnchecked = 0;
  const { budget } = options;
  for (const [index, record] of rrsigs.entries()) {
    if (options.stopAtFirst && check.keyTag !== undefined) break;
    if (budget && index >= budget.signaturesPerRrset) {
      const rrsig = readRrsig(record)!;
      check.signatures.push({
        record,
        rrsig,
        code: SIGNATURE_CODES.LIMIT_EXCEEDED,
        result: UNCHECKED,
      });
      continue;
    }
    const signature = await checkSignature(record, rrset, zone, keys, now, budget);
    check.signatures.push(signature);
    const rrsig = signature.rrsig;
    const byEntryKey = entryKeys.some(
      key => key.keyTag === rrsig.keyTag && key.algorithm === rrsig.algorithm
    );
    if (byEntryKey && signature.result === UNCHECKED) vouchedUnchecked++;
    if (check.keyTag === undefined && (await vouched(signature, rrset, entryKeys, now, budget))) {
      check.keyTag = rrsig.keyTag;
    }
  }

  if (check.keyTag !== undefined) return { ...check, code: KEY_SET_CODES.VERIFIED };

  // which algorithms the entry points name decides what an unverifiable signature means:
  // one supported algorithm among them is enough to make a missing or failed signature by
  // it a break (RFC 6840 §5.2)
  const supported = await Promise.all(entryAlgorithms.map(isAlgorithmSupported));
  const unlinkable = entryAlgorithms.length > 0 && !supported.includes(true);
  if (entryKeys.length === 0) {
    return {
      ...check,
      code: unlinkable ? KEY_SET_CODES.NO_SUPPORTED_ALGORITHM : KEY_SET_CODES.NO_ENTRY_KEY,
    };
  }
  if (vouchedUnchecked > 0 && !supported.includes(true)) {
    return { ...check, code: KEY_SET_CODES.NO_SUPPORTED_ALGORITHM };
  }
  return check;
}

// one RRset from records already known to share an owner and type
function groupRrsets1(records: readonly WireRecord[]): Rrset {
  const [first] = records;
  return {
    name: first.name,
    type: first.type,
    typeName: typeName(first.type),
    class: first.class,
    ttl: Math.min(...records.map(record => record.ttl)),
    records: [...records],
  };
}

// whether a checked signature over the key set was made by a key an entry point vouches
// for. The check above ran against the first usable key with the tag; under a tag
// collision the vouched key is tried directly
async function vouched(
  signature: SignatureCheck,
  rrset: Rrset,
  entryKeys: readonly DnssecKey[],
  now: Date,
  budget?: CheckBudget
): Promise<boolean> {
  const { rrsig } = signature;
  const candidates = entryKeys.filter(
    key => key.keyTag === rrsig.keyTag && key.algorithm === rrsig.algorithm && maySign(key)
  );
  if (candidates.length === 0) return false;
  if (signature.result === VERIFIED && signature.key) {
    if (candidates.some(key => bytesEqual(key.record.rdata, signature.key!.record.rdata))) {
      return true;
    }
  }
  if (!withinValidity(rrsig, now)) return false;
  const signedData = buildSignedData(rrsig, rrset);
  if (!signedData) return false;
  for (const key of candidates) {
    if (signature.key && bytesEqual(key.record.rdata, signature.key.record.rdata)) continue;
    if (!spend(budget)) return false;
    const outcome = await verifySignature(
      key.algorithm,
      key.publicKey,
      signedData.data,
      rrsig.signature
    );
    if (outcome.verified === true) return true;
  }
  return false;
}
