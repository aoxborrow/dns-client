import { RECORD_TYPES, typeName } from '../protocol/types';
import { RCODES } from '../protocol/header';
import {
  canonicalName,
  countLabels,
  isSubdomain,
  labelsToName,
  parentName,
  readName,
  splitName,
} from '../wire/names';
import { ROOT_TRUST_ANCHORS } from './anchors';
import { groupRrsets, wildcardOwner } from './canonical';
import type { ResourceRecord } from '../wire/message';
import type { Rrset } from './canonical';
import {
  checkAnchors,
  checkBudget,
  checkDsSet,
  coveringSignatures,
  checkKeySet,
  checkRrset,
  KEY_SET_CODES,
  readKeys,
  readRrsig,
  RRSET_CODES,
  SIGNATURE_CODES,
} from './checks';
import type {
  AnchorCheck,
  CheckBudget,
  CheckLimits,
  DnssecKey,
  DsSetCheck,
  KeySetCheck,
  RrsetCheck,
  SignatureCheck,
} from './checks';
import {
  NSEC3_ITERATIONS_INSECURE_THRESHOLD,
  PROOF_PURPOSES,
  PROOF_STATUSES,
  VERIFICATION_RESULTS,
} from './constants';
import { decodeNsec3 } from '../records/decode';
import {
  denialTypesAt,
  iterationsExceededProof,
  nextCloserOptOut,
  verifyNodataProof,
  verifyNoDsProof,
  verifyNxdomainProof,
  verifyWildcardProof,
} from './nsec';
import { REASON_CODES, SECURITY_STATUSES, securityReason } from './reasons';
import type { ReasonCode, SecurityReason, SecurityStatus } from './reasons';
import type { DenialProof, TrustAnchor } from './types';

const { SECURE, INSECURE, BOGUS, INDETERMINATE } = SECURITY_STATUSES;
const R = REASON_CODES;
const { VERIFIED } = VERIFICATION_RESULTS;
const { DS, RRSIG, NSEC, NSEC3, CNAME, DNAME, NS, SOA } = RECORD_TYPES;

/** one response, as the judgement reads it */
export interface DnssecResponse {
  /**
   * the question that was sent: never the response's own question section, which is
   * unsigned and could name something else
   */
  name: string;
  type: number;
  rcode: number;
  answers: ResourceRecord[];
  authorities: ResourceRecord[];
  /**
   * the server was asked to recurse, so it follows every alias to its end: a response that
   * stops at an alias without the target's records owes a proof that the target has none.
   * A zone's own server hands over an alias that leads out of its zone and nothing more
   */
  recursive?: boolean;
  /** the response came with TC set: it is not the whole answer */
  truncated?: boolean;
}

/** a name between the trust anchor and the data, with what was fetched for it */
export interface ChainName {
  name: string;
  /** the answer to `<name> DS`, which the zone above gives */
  ds?: DnssecResponse;
  /** the answer to `<name> DNSKEY`, needed where `ds` shows the name is a zone of its own */
  dnskey?: DnssecResponse;
}

/**
 * what is known about a name from an earlier judgement, so it need not be fetched or
 * judged again: whether it is a zone of its own and, if so, what came of its key set
 */
export interface ZoneFact {
  name: string;
  /** false: the name is inside the zone above it */
  cut: boolean;
  status: SecurityStatus;
  reason: SecurityReason;
  /** the zone's validated keys, for a secure zone */
  keys: DnssecKey[];
  /** how long the fact holds, in seconds: the shortest TTL, or signature lifetime, it rests on */
  ttl: number;
}

/**
 * what `judgeChain` judges: the responses fetched for each name from the trust anchor down, and the
 * responses holding the data
 */
export interface ChainInput {
  /**
   * the DNSKEY response of the zone the trust anchors are for: the root unless the
   * anchors say otherwise
   */
  anchored?: DnssecResponse;
  /** the names below it, each with its DS response and, for a zone cut, its DNSKEY response */
  names?: ChainName[];
  /** the responses whose data is judged */
  responses?: DnssecResponse[];
  /** what earlier judgements established, which is used as it is */
  known?: ZoneFact[];
}

/** `'first'` stops at the first link that settles the outcome; `'all'` judges every link */
export type JudgeMode = 'first' | 'all';

/** the options of `judgeChain` */
export interface JudgeOptions {
  /** default: IANA's root trust anchors */
  trustAnchors?: readonly TrustAnchor[];
  /** the time signatures and anchors are judged at. Default: now */
  now?: Date;
  /**
   * 'first' (default) stops at the first link that settles the outcome; 'all' judges
   * every link
   */
  mode?: JudgeMode;
  /**
   * require each RRset to be signed by every algorithm in its zone's key set (RFC 4035
   * §2.2). Validators accept any one (RFC 6840 §5.11), so off by default
   */
  requireEveryAlgorithm?: boolean;
  /**
   * how much signature checking may be done before the judgement gives up on what is left
   * as bogus. In mode 'first' one budget covers the whole judgement; in mode 'all' each zone
   * (its key set, and the RRsets and proofs it signs) has its own, so one zone cannot use up
   * another's. Default: 128 verifications, 4 keys tried per signature, 8 signatures per RRset
   */
  limits?: Partial<CheckLimits>;
}

/** what a link is about: a zone's key set, an RRset, or a denial proof */
export type LinkKind = 'keys' | 'rrset' | 'denial';

/**
 * one link in the chain: a zone's key set (vouched for by the trust anchor or by its
 * parent's DS), an RRset of the data, or a proof that something does not exist
 */
export interface ChainLink {
  kind: LinkKind;
  zone: string;
  /** the RRset or name the link is about, for data and proofs */
  name?: string;
  type?: string;
  status: SecurityStatus;
  reason: SecurityReason;
}

/**
 * what a link's status rests on: the checks made for it, as they came out. A link that only
 * takes a zone's outcome, below a zone that is not secure or from a known fact, has none
 */
export type LinkEvidence = KeysEvidence | RrsetEvidence | DenialEvidence;

/** a zone's key set, and how its parent vouched for it or proved it has none */
export interface KeysEvidence {
  kind: 'keys';
  /** the published keys, read */
  keys: DnssecKey[];
  /** what the trust anchors made of them, for the anchored zone */
  anchors?: AnchorCheck;
  /** the parent's signatures over the DS RRset */
  ds?: RrsetCheck;
  /** what the DS records made of the keys */
  dsSet?: DsSetCheck;
  /** the key set's signatures */
  keySet?: KeySetCheck;
  /** the parent's proof that the name has no DS */
  noDs?: DenialEvidence;
}

/** an RRset of the data, and its signatures */
export interface RrsetEvidence {
  kind: 'rrset';
  check: RrsetCheck;
}

/** a proof that something does not exist */
export interface DenialEvidence {
  kind: 'denial';
  /** each NSEC or NSEC3 RRset the proof is made of, checked in the zone */
  records: RrsetCheck[];
  /**
   * the proof worked out from them, step by step: one that fails for want of records when
   * none came, and one left unworked past the NSEC3 iterations validators hash. Absent when
   * the records could not be trusted
   */
  proof?: DenialProof;
  /**
   * what a response's proof is for: that the name does not exist, that it has no data of
   * the type asked, or that a wildcard answering it may. Absent on a proof of no DS
   */
  purpose?: 'wildcard' | 'nxdomain' | 'nodata';
}

/** a link of the judgement, with the evidence its status rests on */
export interface JudgedLink extends ChainLink {
  /** the checks behind the link's status */
  evidence?: LinkEvidence;
}

/** what `judgeChain` came to: the outcome, its reason, and every link judged */
export interface Judgement {
  status: SecurityStatus;
  reason: SecurityReason;
  /** every link judged, zones from the top down, then the data, each with what it rests on */
  links: JudgedLink[];
  /** the first link that is bogus or indeterminate, when the outcome is either */
  failure?: JudgedLink;
  /**
   * what this judgement established about each name, to keep for next time. Only secure
   * and insecure outcomes are given: a broken or unanswered zone is asked about again
   */
  facts: ZoneFact[];
}

/** what a judgement established about a zone */
export interface ZoneState {
  zone: string;
  status: SecurityStatus;
  reason: SecurityReason;
  keys: DnssecKey[];
}

// ---------------------------------------------------------------------------

/**
 * the judging core: given the records fetched for each zone on the way down from a trust anchor,
 * and the responses whose data is to be trusted, say whether each link holds and why. It fetches
 * nothing and keeps no state, so the same records and time always give the same judgement. `mode:
 * 'first'` stops as soon as the outcome is settled, the way a validating resolver does; `mode:
 * 'all'` judges every link and every signature, for a report of everything that is wrong
 */
export async function judgeChain(
  input: ChainInput,
  options: JudgeOptions = {}
): Promise<Judgement> {
  const now = options.now ?? new Date();
  const anchors = options.trustAnchors ?? ROOT_TRUST_ANCHORS;
  const mode = options.mode ?? 'first';
  const stopAtFirst = mode === 'first';
  // judging everything, each zone gets its own budget, so one zone's signatures cannot
  // starve the report on the rest. Stopping at the first failure, as a validator does, one
  // budget bounds the whole judgement however many zones an answer crosses
  const budgets = new Map<string, CheckBudget>();
  const budget = (zone: string): CheckBudget => {
    const key = stopAtFirst ? '' : canonicalName(zone);
    let found = budgets.get(key);
    if (!found) {
      found = checkBudget(options.limits);
      budgets.set(key, found);
    }
    return found;
  };
  const rrsetOptions: RrsetOptions = {
    now,
    stopAtFirst,
    requireEveryAlgorithm: options.requireEveryAlgorithm ?? false,
    budget,
  };

  const links: JudgedLink[] = [];
  const facts: ZoneFact[] = [];
  const zones = new Map<string, ZoneState>();
  const insideZone = new Set<string>();
  const done = () => stopAtFirst && links.some(link => link.status === BOGUS);

  for (const fact of input.known ?? []) {
    const name = canonicalName(fact.name);
    if (fact.cut) zones.set(name, { ...fact, zone: name });
    else insideZone.add(name);
  }

  // the deepest zone holding `name`: the name itself when it is a zone, unless `strict`
  const enclosing = (name: string, strict = false): ZoneState | undefined => {
    let current = canonicalName(name);
    if (strict) {
      if (current === '.') return undefined;
      current = parentName(current);
    }
    for (;;) {
      const zone = zones.get(current);
      if (zone) return zone;
      if (current === '.') return undefined;
      current = parentName(current);
    }
  };

  // the zone the trust anchors are for
  const anchorZone = canonicalName(anchors[0]?.zone ?? '.');
  if (!zones.has(anchorZone)) {
    const state = await judgeKeys(
      anchorZone,
      input.anchored,
      { anchors },
      now,
      stopAtFirst,
      budget(anchorZone)
    );
    zones.set(anchorZone, state.zone);
    links.push(keysLink(state.zone, keysEvidence(state)));
    if (state.fact) facts.push(state.fact);
  }

  // the names below it, parents first
  const names = [...(input.names ?? [])].sort(
    (a, b) => countLabels(canonicalName(a.name)) - countLabels(canonicalName(b.name))
  );
  for (const entry of names) {
    if (done()) break;
    const name = canonicalName(entry.name);
    if (zones.has(name) || insideZone.has(name)) continue;
    const parent = enclosing(name, true);
    // nothing outside the anchored tree, and nothing below a zone that is not secure, can
    // change: the names there take that zone's outcome
    if (!parent || parent.status !== SECURE) continue;

    const judged = await judgeName(parent, name, entry, now, rrsetOptions);
    if (judged.cut) {
      zones.set(name, judged.cut);
      links.push(keysLink(judged.cut, judged.evidence));
    } else if (judged.inside) {
      insideZone.add(name);
    }
    if (judged.fact) facts.push(judged.fact);
  }

  // the data
  const dataLinks: JudgedLink[] = [];
  // a response that ends at an alias another response was asked about is continued there
  const asked = new Set((input.responses ?? []).map(response => canonicalName(response.name)));
  for (const response of input.responses ?? []) {
    if (done()) break;
    const judged = await judgeResponse(response, enclosing, rrsetOptions, stopAtFirst, asked);
    links.push(...judged);
    dataLinks.push(...judged);
  }

  // with no data, the outcome is the deepest zone's
  const deciding = dataLinks.length ? dataLinks : links.slice(-1);
  const status = worst(deciding.map(link => link.status));
  const decisive = deciding.find(link => link.status === status) ?? deciding[0];
  const failure =
    status === BOGUS || status === INDETERMINATE
      ? links.find(link => link.status === status)
      : undefined;
  return {
    status,
    reason: decisive?.reason ?? securityReason(R.RESPONSE_MISSING, anchorZone),
    links,
    ...(failure && { failure }),
    facts,
  };
}

// bogus outweighs indeterminate, which outweighs insecure, which outweighs secure
const WEIGHT: Record<SecurityStatus, number> = {
  [SECURE]: 0,
  [INSECURE]: 1,
  [INDETERMINATE]: 2,
  [BOGUS]: 3,
};

function worst(statuses: SecurityStatus[]): SecurityStatus {
  if (statuses.length === 0) return INDETERMINATE;
  return statuses.reduce((a, b) => (WEIGHT[b] > WEIGHT[a] ? b : a));
}

function keysLink(zone: ZoneState, evidence?: KeysEvidence): JudgedLink {
  return {
    kind: 'keys',
    zone: zone.zone,
    status: zone.status,
    reason: zone.reason,
    ...(evidence && { evidence }),
  };
}

function keysEvidence(judged: ZoneKeysJudgement, ds?: RrsetCheck): KeysEvidence {
  return {
    kind: 'keys',
    keys: judged.keys,
    ...(judged.anchors && { anchors: judged.anchors }),
    ...(ds && { ds }),
    ...(judged.dsSet && { dsSet: judged.dsSet }),
    ...(judged.keySet && { keySet: judged.keySet }),
  };
}

// ---------------------------------------------------------------------------
// a zone's key set
// ---------------------------------------------------------------------------

// what `judgeKeys` made of a zone's key set
export interface ZoneKeysJudgement {
  zone: ZoneState;
  // the published keys, read
  keys: DnssecKey[];
  // what the trust anchors made of them, for the anchored zone
  anchors?: AnchorCheck;
  // what the parent's DS records made of them, for any other
  dsSet?: DsSetCheck;
  // the key set's signatures, checked
  keySet?: KeySetCheck;
  fact?: ZoneFact;
}

// where a zone's key set gets its trust: the trust anchors, for the anchored zone, or the
// parent's DS records. `authenticated: false` says the parent's DS response was not
// validly signed, so the DS records anchor nothing
export type KeysEntry =
  | { anchors: readonly TrustAnchor[] }
  | { ds: readonly ResourceRecord[]; dsTtl?: number; authenticated?: boolean };

// judge a zone's key set against its entry points. Every check is made and handed back,
// even past a failure, unless `stopAtFirst`
export async function judgeKeys(
  zone: string,
  dnskey: DnssecResponse | undefined,
  entry: KeysEntry,
  now: Date,
  stopAtFirst = false,
  budget?: CheckBudget
): Promise<ZoneKeysJudgement> {
  const state = (status: SecurityStatus, code: ReasonCode, about = {}): ZoneState => ({
    zone,
    status,
    reason: securityReason(code, zone, about),
    keys: [],
  });

  if (!dnskey) {
    return { zone: state(INDETERMINATE, R.RESPONSE_MISSING, { type: 'DNSKEY' }), keys: [] };
  }
  const owner = canonicalName(zone);
  const keys = readKeys(dnskey.answers.filter(record => canonicalName(record.name) === owner));
  if (keys.length === 0) {
    return { zone: state(BOGUS, R.DNSKEY_MISSING, { type: 'DNSKEY' }), keys };
  }

  // the entry points, and a verdict already reached from them alone
  let entryKeys: DnssecKey[] = [];
  let entryAlgorithms: number[] = [];
  let anchors: AnchorCheck | undefined;
  let dsSet: DsSetCheck | undefined;
  let decided: ZoneState | undefined;
  if ('anchors' in entry) {
    const rrset = groupRrsets(keys.map(key => key.record))[0];
    const rrsigs = dnskey.answers.filter(record => record.type === RRSIG);
    anchors = await checkAnchors(zone, keys, entry.anchors, now, { rrset, rrsigs }, budget);
    entryKeys = anchors.keys;
    entryAlgorithms = entryKeys.map(key => key.algorithm);
    if (entryKeys.length === 0) decided = state(BOGUS, R.NO_TRUST_ANCHOR);
  } else if (entry.authenticated === false) {
    decided = state(BOGUS, R.DS_UNAUTHENTICATED, { name: zone, type: 'DS' });
  } else {
    dsSet = checkDsSet(zone, entry.ds, keys);
    entryKeys = dsSet.keys;
    entryAlgorithms = dsSet.algorithms;
    // a DS set with no digest type this runtime can compute links nothing: the zone is
    // treated as unsigned (RFC 4035 §5.2)
    if (dsSet.selectedDigestType === undefined) {
      decided = state(INSECURE, R.UNSUPPORTED_DIGEST, {
        digestType: dsSet.checks[0]?.ds.digestType,
      });
    }
  }
  if (decided && stopAtFirst) return { zone: decided, keys, anchors, dsSet };

  const keySet = await checkKeySet(zone, dnskey, keys, entryKeys, entryAlgorithms, now, {
    stopAtFirst,
    budget,
  });
  const judged = { keys, anchors, dsSet, keySet };
  if (decided) return { zone: decided, ...judged };

  switch (keySet.code) {
    case KEY_SET_CODES.VERIFIED: {
      const verifying = keySet.signatures.find(
        signature => signature.result === VERIFIED && signature.rrsig.keyTag === keySet.keyTag
      );
      const lifetimes = [keySet.rrset!.ttl];
      if ('ds' in entry && entry.dsTtl !== undefined) lifetimes.push(entry.dsTtl);
      // no longer than the signature's original TTL, nor past its expiry (RFC 4035 §5.3.3)
      if (verifying) lifetimes.push(signatureLifetime(verifying, now));
      const secure: ZoneState = {
        zone,
        status: SECURE,
        reason: securityReason(R.VERIFIED, zone, { keyTag: keySet.keyTag }),
        keys,
      };
      return {
        zone: secure,
        ...judged,
        fact: { name: zone, cut: true, ...secure, ttl: Math.max(0, Math.min(...lifetimes)) },
      };
    }
    case KEY_SET_CODES.NO_RESPONSE:
      return { zone: state(INDETERMINATE, R.RESPONSE_MISSING, { type: 'DNSKEY' }), ...judged };
    case KEY_SET_CODES.NO_RRSET:
      return { zone: state(BOGUS, R.DNSKEY_MISSING, { type: 'DNSKEY' }), ...judged };
    case KEY_SET_CODES.UNSIGNED:
      return { zone: state(BOGUS, R.RRSIGS_MISSING, { name: zone, type: 'DNSKEY' }), ...judged };
    case KEY_SET_CODES.NO_SUPPORTED_ALGORITHM: {
      // no algorithm the entry points name can be verified here: no path to check, which a
      // validator treats as no DS at all (RFC 4035 §5.2, RFC 6840 §5.2)
      return {
        zone: state(INSECURE, R.UNSUPPORTED_ALGORITHM, { algorithm: entryAlgorithms[0] }),
        ...judged,
      };
    }
    case KEY_SET_CODES.NO_ENTRY_KEY: {
      const failed = dsSet?.checks.find(check => check.selected);
      const code = failed?.code === 'digest-mismatch' ? R.DS_DIGEST_MISMATCH : R.NO_MATCHING_DNSKEY;
      return { zone: state(BOGUS, code, { keyTag: failed?.ds.keyTag }), ...judged };
    }
    default: {
      // signatures left unchecked for want of budget may have held a good one: the limit is
      // why the key set failed
      const byEntry =
        keySet.signatures.find(signature => signature.code === SIGNATURE_CODES.LIMIT_EXCEEDED) ??
        keySet.signatures.find(signature =>
          entryKeys.some(
            key =>
              key.keyTag === signature.rrsig.keyTag && key.algorithm === signature.rrsig.algorithm
          )
        );
      const code = byEntry ? signatureReason(byEntry) : R.KEYSET_NOT_SIGNED;
      return {
        zone: state(BOGUS, code, {
          name: zone,
          type: 'DNSKEY',
          ...(byEntry && { keyTag: byEntry.rrsig.keyTag }),
        }),
        ...judged,
      };
    }
  }
}

// the reason a checked signature failed
function signatureReason(signature: SignatureCheck): ReasonCode {
  switch (signature.code) {
    case SIGNATURE_CODES.EXPIRED:
      return R.SIGNATURE_EXPIRED;
    case SIGNATURE_CODES.NOT_YET_VALID:
      return R.SIGNATURE_NOT_YET_VALID;
    case SIGNATURE_CODES.NO_MATCHING_KEY:
      return R.SIGNING_KEY_MISSING;
    case SIGNATURE_CODES.ZONE_FLAG_UNSET:
      return R.NO_ZONE_KEY_BIT;
    case SIGNATURE_CODES.REVOKED_KEY:
      return R.REVOKED_KEY;
    case SIGNATURE_CODES.SIGNER_MISMATCH:
    case SIGNATURE_CODES.LABELS_EXCEED_OWNER:
      return R.SIGNATURE_MISMATCH;
    case SIGNATURE_CODES.UNSUPPORTED_ALGORITHM:
      return R.UNVERIFIABLE;
    case SIGNATURE_CODES.LIMIT_EXCEEDED:
      return R.VALIDATION_LIMIT;
    default:
      return R.SIGNATURE_INVALID;
  }
}

// the status and reason an RRset that should be signed comes out with
function rrsetVerdict(
  check: RrsetCheck,
  zone: string
): { status: SecurityStatus; reason: SecurityReason } {
  const about = { name: check.rrset.name, type: check.rrset.typeName };
  switch (check.code) {
    case RRSET_CODES.VERIFIED:
      return { status: SECURE, reason: securityReason(R.VERIFIED, zone, about) };
    case RRSET_CODES.UNSIGNED:
      return { status: BOGUS, reason: securityReason(R.RRSIGS_MISSING, zone, about) };
    case RRSET_CODES.MISSING_ALGORITHM:
      return {
        status: BOGUS,
        reason: securityReason(R.MISSING_ALGORITHM, zone, {
          ...about,
          algorithm: check.missingAlgorithms[0],
        }),
      };
    default: {
      const own = check.signatures.filter(signature => signature.code !== SIGNATURE_CODES.FOREIGN);
      // every signature in an algorithm nothing here verifies: it cannot be told
      const unverifiable = (signature: SignatureCheck) =>
        signature.code === SIGNATURE_CODES.UNSUPPORTED_ALGORITHM;
      if (own.length > 0 && own.every(unverifiable)) {
        return {
          status: INDETERMINATE,
          reason: securityReason(R.UNVERIFIABLE, zone, {
            ...about,
            algorithm: own[0].rrsig.algorithm,
          }),
        };
      }
      // signatures left unchecked for want of budget may have held a good one: the limit is
      // why the RRset failed
      const failed =
        own.find(signature => signature.code === SIGNATURE_CODES.LIMIT_EXCEEDED) ??
        own.find(signature => !unverifiable(signature)) ??
        own[0];
      return {
        status: BOGUS,
        reason: securityReason(failed ? signatureReason(failed) : R.SIGNATURE_INVALID, zone, {
          ...about,
          ...(failed && { keyTag: failed.rrsig.keyTag }),
        }),
      };
    }
  }
}

// ---------------------------------------------------------------------------
// a name below a secure zone: a zone cut, or a name inside the zone
// ---------------------------------------------------------------------------

interface NameJudgement {
  // the name is a zone of its own, and this is what came of it
  cut?: ZoneState;
  evidence?: KeysEvidence;
  // the name is inside its parent's zone
  inside?: boolean;
  fact?: ZoneFact;
}

type RrsetOptions = {
  now: Date;
  stopAtFirst: boolean;
  requireEveryAlgorithm: boolean;
  // the budget of the zone whose signatures are checked
  budget: (zone: string) => CheckBudget;
};

// an RRset checked in its zone, on that zone's budget
function checkIn(
  zone: ZoneState,
  rrset: Rrset,
  rrsigs: readonly ResourceRecord[],
  options: RrsetOptions
): Promise<RrsetCheck> {
  return checkRrset(zone, rrset, rrsigs, { ...options, budget: options.budget(zone.zone) });
}

interface DenialRecords {
  // each NSEC or NSEC3 RRset of the zone, checked in it
  checks: RrsetCheck[];
  // their records, which are all a proof is worked out from
  records: ResourceRecord[];
}

// the NSEC and NSEC3 RRsets of a response's authority section that belong to `zone`, each
// checked in it. Undefined when there are none.
//
// a response can carry another zone's proof beside this one's (a wildcard answer in one
// zone whose alias ends at a name missing from another), so an RRset whose signatures all
// name another signer is left to that zone, not counted against this one. Leaving records
// out only takes evidence away, so it cannot make a proof pass. Of the NSEC3 records, only
// those with the parameters of the first count: a zone uses one set (RFC 5155 §7.1), and
// hashing a name again for every set a response makes up is work for nothing
// (CVE-2023-50868)
async function checkDenialRecords(
  zone: ZoneState,
  authorities: ResourceRecord[],
  rrsigs: ResourceRecord[],
  options: RrsetOptions
): Promise<DenialRecords | undefined> {
  const apex = canonicalName(zone.zone);
  let params: string | undefined;
  const ours = authorities.filter(record => {
    if (record.type === NSEC) return isSubdomain(record.name, apex);
    if (record.type !== NSEC3) return false;
    if (parentName(canonicalName(record.name)) !== apex) return false;
    const key = nsec3Params(record);
    if (key === undefined) return false;
    params ??= key;
    return key === params;
  });
  const rrsets = groupRrsets(ours).filter(rrset => {
    const signers = coveringSignatures(rrset, rrsigs).map(record => readRrsig(record)?.signerName);
    return (
      signers.length === 0 ||
      signers.some(signer => signer !== undefined && canonicalName(signer) === apex)
    );
  });
  if (rrsets.length === 0) return undefined;
  const checks: RrsetCheck[] = [];
  for (const rrset of rrsets) checks.push(await checkIn(zone, rrset, rrsigs, options));
  return { checks, records: rrsets.flatMap(rrset => rrset.records) };
}

// an NSEC3 record's hash parameters, as one string to compare
function nsec3Params(record: ResourceRecord): string | undefined {
  try {
    const { hashAlgorithm, iterations, salt } = decodeNsec3(record.rdata);
    return `${hashAlgorithm}/${iterations}/${salt.join(',')}`;
  } catch {
    return undefined;
  }
}

// the most NSEC3 iterations among records
function nsec3Iterations(records: ResourceRecord[]): number {
  let most = 0;
  for (const record of records) {
    if (record.type !== NSEC3) continue;
    try {
      most = Math.max(most, decodeNsec3(record.rdata).iterations);
    } catch {
      // a record that does not decode proves nothing
    }
  }
  return most;
}

// an NSEC or NSEC3 record is never synthesized from a wildcard: one whose signature says
// it was is not the zone's (RFC 4035 §5.3.4)
function expandedFromWildcard(check: RrsetCheck): boolean {
  return check.signatures.some(signature => signature.result === VERIFIED && signature.wildcard);
}

// how long a verified RRset may be trusted, in seconds: its TTL, capped at the original
// TTL and the expiry of the signature that verified it (RFC 4035 §5.3.3)
function rrsetLifetime(check: RrsetCheck, now: Date): number {
  const verifying = check.signatures.find(signature => signature.result === VERIFIED);
  return Math.min(check.rrset.ttl, verifying ? signatureLifetime(verifying, now) : Infinity);
}

function signatureLifetime(signature: SignatureCheck, now: Date): number {
  // seconds until the expiration, read with serial arithmetic (RFC 4034 §3.1.5)
  const expires =
    (((signature.rrsig.expiration - Math.floor(now.getTime() / 1000)) % 2 ** 32) + 2 ** 32) %
    2 ** 32;
  return expires >= 2 ** 31 ? 0 : Math.min(signature.rrsig.originalTtl, expires);
}

const signaturesIn = (response: DnssecResponse) =>
  [...response.answers, ...response.authorities].filter(record => record.type === RRSIG);

async function judgeName(
  parent: ZoneState,
  name: string,
  entry: ChainName,
  now: Date,
  options: RrsetOptions
): Promise<NameJudgement> {
  const cut = (
    status: SecurityStatus,
    code: ReasonCode,
    about = {},
    evidence?: Omit<KeysEvidence, 'kind' | 'keys'>
  ): NameJudgement => {
    const zone: ZoneState = {
      zone: name,
      status,
      reason: securityReason(code, name, about),
      keys: [],
    };
    return { cut: zone, ...(evidence && { evidence: { kind: 'keys', keys: [], ...evidence } }) };
  };
  const response = entry.ds;
  if (!response) return cut(INDETERMINATE, R.RESPONSE_MISSING, { type: 'DS' });
  if (response.rcode !== RCODES.NOERROR && response.rcode !== RCODES.NXDOMAIN) {
    return cut(INDETERMINATE, R.RESPONSE_MISSING, { type: 'DS' });
  }
  const rrsigs = signaturesIn(response);
  const owner = canonicalName(name);
  const answerSets = groupRrsets(response.answers);
  const dsRrset = answerSets.find(
    rrset => rrset.type === DS && canonicalName(rrset.name) === owner
  );

  if (dsRrset) {
    // the DS RRset has to be signed by the parent before it can vouch for anything
    const signed = await checkIn(parent, dsRrset, rrsigs, options);
    if (signed.code !== RRSET_CODES.VERIFIED) {
      const verdict = rrsetVerdict(signed, parent.zone);
      const code =
        verdict.reason.code === R.RRSIGS_MISSING ? R.DS_UNAUTHENTICATED : verdict.reason.code;
      const about = { name, type: 'DS' };
      if (options.stopAtFirst) return cut(verdict.status, code, about, { ds: signed });
      // judging everything, the child's keys and their signatures are still read for the
      // evidence, though DS records the parent does not vouch for link nothing
      const unvouched = await judgeKeys(
        name,
        entry.dnskey,
        { ds: dsRrset.records, authenticated: false },
        now,
        false,
        options.budget(name)
      );
      return {
        cut: {
          zone: name,
          status: verdict.status,
          reason: securityReason(code, name, about),
          keys: [],
        },
        evidence: keysEvidence(unvouched, signed),
      };
    }
    const dsTtl = rrsetLifetime(signed, now);
    const judged = await judgeKeys(
      name,
      entry.dnskey,
      { ds: dsRrset.records, dsTtl },
      now,
      options.stopAtFirst,
      options.budget(name)
    );
    const fact =
      judged.fact ??
      (judged.zone.status === INSECURE ? factOf(judged.zone, true, dsTtl) : undefined);
    return { cut: judged.zone, evidence: keysEvidence(judged, signed), ...(fact && { fact }) };
  }

  // a name below a DNAME is rewritten, never looked up, so it cannot be a zone cut
  // (RFC 6672 §2.3)
  const dname = answerSets.find(
    rrset =>
      rrset.type === DNAME &&
      canonicalName(rrset.name) !== owner &&
      isSubdomain(owner, rrset.name) &&
      isSubdomain(rrset.name, parent.zone)
  );
  if (dname) {
    const signed = await checkIn(parent, dname, rrsigs, options);
    if (signed.code === RRSET_CODES.VERIFIED) {
      return { inside: true, fact: factOf(parent, false, rrsetLifetime(signed, now), name) };
    }
    const verdict = rrsetVerdict(signed, parent.zone);
    return cut(verdict.status, verdict.reason.code, { name: dname.name, type: 'DNAME' });
  }

  // a CNAME at the name: an alias cannot be a zone cut
  const alias = answerSets.find(
    rrset => rrset.type === CNAME && canonicalName(rrset.name) === owner
  );
  if (alias) {
    const signed = await checkIn(parent, alias, rrsigs, options);
    if (signed.code === RRSET_CODES.VERIFIED) {
      return { inside: true, fact: factOf(parent, false, rrsetLifetime(signed, now), name) };
    }
    const verdict = rrsetVerdict(signed, parent.zone);
    return cut(verdict.status, verdict.reason.code, { name, type: 'CNAME' });
  }

  // no DS: the parent has to prove it, with NSEC or NSEC3 records it signed
  const denial = await checkDenialRecords(parent, response.authorities, rrsigs, options);
  if (!denial) {
    return cut(
      BOGUS,
      R.NO_DS_PROOF,
      { name, type: 'DS' },
      { noDs: { kind: 'denial', records: [], proof: verifyNoDsProof(name, []) } }
    );
  }
  const noDs = (proof?: DenialProof): DenialEvidence => ({
    kind: 'denial',
    records: denial.checks,
    ...(proof && { proof }),
  });
  const unsigned = denial.checks.find(check => check.code !== RRSET_CODES.VERIFIED);
  if (unsigned) {
    const verdict = rrsetVerdict(unsigned, parent.zone);
    return cut(
      BOGUS,
      verdict.reason.code === R.RRSIGS_MISSING ? R.DS_UNAUTHENTICATED : verdict.reason.code,
      {
        name: unsigned.rrset.name,
        type: unsigned.rrset.typeName,
      },
      { noDs: noDs() }
    );
  }
  const expanded = denial.checks.find(expandedFromWildcard);
  if (expanded) {
    return cut(
      BOGUS,
      R.DENIAL_INVALID,
      {
        name: expanded.rrset.name,
        type: expanded.rrset.typeName,
      },
      { noDs: noDs() }
    );
  }
  const ttl = Math.min(...denial.checks.map(check => rrsetLifetime(check, now)));

  // past the iterations validators hash, nothing is hashed at all (RFC 9276 §3.2)
  if (nsec3Iterations(denial.records) > NSEC3_ITERATIONS_INSECURE_THRESHOLD) {
    return insecureCut(
      name,
      R.NSEC3_ITERATIONS,
      ttl,
      noDs(iterationsExceededProof(name, PROOF_PURPOSES.NO_DS, denial.records))
    );
  }
  const proof = verifyNoDsProof(name, denial.records);
  if (proof.status === PROOF_STATUSES.OPT_OUT) {
    return insecureCut(name, R.OPT_OUT, ttl, noDs(proof));
  }
  if (proof.result !== VERIFIED) {
    return cut(BOGUS, R.NO_DS_PROOF, { name, type: 'DS' }, { noDs: noDs(proof) });
  }

  const at = denialTypesAt(name, denial.records);
  if (at.types?.includes(NS) && !at.types.includes(SOA)) {
    // a delegation with no DS: the zone below is unsigned
    return insecureCut(name, R.NO_DS, ttl, noDs(proof));
  }
  // the name has no NS, or does not exist: it is inside the parent's zone
  return { inside: true, fact: factOf(parent, false, ttl, name) };
}

function insecureCut(
  name: string,
  code: ReasonCode,
  ttl: number,
  noDs: DenialEvidence
): NameJudgement {
  const zone: ZoneState = {
    zone: name,
    status: INSECURE,
    reason: securityReason(code, name),
    keys: [],
  };
  return { cut: zone, evidence: { kind: 'keys', keys: [], noDs }, fact: factOf(zone, true, ttl) };
}

function factOf(zone: ZoneState, cut: boolean, ttl: number, name = zone.zone): ZoneFact {
  return cut
    ? { name, cut, status: zone.status, reason: zone.reason, keys: zone.keys, ttl }
    : { name, cut, status: zone.status, reason: zone.reason, keys: [], ttl };
}

// ---------------------------------------------------------------------------
// the data
// ---------------------------------------------------------------------------

// where an alias takes a name: a CNAME at it, or a DNAME above it (RFC 6672 §2.2)
function aliasStep(name: string, rrsets: Rrset[]): string | undefined {
  const current = canonicalName(name);
  for (const rrset of rrsets) {
    if (rrset.type === CNAME && canonicalName(rrset.name) === current)
      return targetOf(rrset.records[0]);
  }
  for (const rrset of rrsets) {
    if (rrset.type !== DNAME) continue;
    const owner = canonicalName(rrset.name);
    if (owner === current || !isSubdomain(current, owner)) continue;
    return substitute(current, owner, targetOf(rrset.records[0]));
  }
  return undefined;
}

function targetOf(record: ResourceRecord): string {
  return canonicalName(labelsToName(readName(record.rdata, 0).labels));
}

// the name a DNAME at `owner` pointing at `target` makes of `name` below it
function substitute(name: string, owner: string, target: string): string {
  const labels = splitName(canonicalName(name));
  const prefix = labels.slice(0, labels.length - splitName(owner).length);
  return canonicalName([...prefix, ...splitName(target)].join('.'));
}

// a CNAME a server synthesized from a DNAME carries no signature of its own; it is
// trusted when a verified DNAME above it makes exactly it (RFC 6672 §5.3.1, RFC 4035
// §3.2.3)
function synthesized(cname: Rrset, verifiedDnames: Rrset[]): boolean {
  const owner = canonicalName(cname.name);
  const target = targetOf(cname.records[0]);
  return verifiedDnames.some(dname => {
    const dnameOwner = canonicalName(dname.name);
    return (
      owner !== dnameOwner &&
      isSubdomain(owner, dnameOwner) &&
      substitute(owner, dnameOwner, targetOf(dname.records[0])) === target
    );
  });
}

async function judgeResponse(
  response: DnssecResponse,
  enclosing: (name: string, strict?: boolean) => ZoneState | undefined,
  options: RrsetOptions,
  stopAtFirst: boolean,
  asked: Set<string>
): Promise<JudgedLink[]> {
  const links: JudgedLink[] = [];
  const rrsigs = signaturesIn(response);
  const rrsets = groupRrsets(response.answers);
  const inherit = (
    zone: ZoneState | undefined,
    kind: LinkKind,
    name: string,
    type: string
  ): ChainLink =>
    zone
      ? { kind, zone: zone.zone, name, type, status: zone.status, reason: zone.reason }
      : {
          kind,
          zone: '.',
          name,
          type,
          status: INDETERMINATE,
          reason: securityReason(R.RESPONSE_MISSING, '.', { name, type }),
        };

  // a truncated response is not the whole answer: what is missing from it cannot be
  // judged, in a zone that signs. Below a zone that does not, it is what that zone is
  if (response.truncated) {
    const name = canonicalName(response.name);
    const type = typeName(response.type);
    const zone = enclosing(name, response.type === DS);
    if (zone && zone.status !== SECURE) return [inherit(zone, 'rrset', name, type)];
    return [
      {
        kind: 'rrset',
        zone: zone?.zone ?? '.',
        name,
        type,
        status: INDETERMINATE,
        reason: securityReason(R.RESPONSE_MISSING, zone?.zone ?? '.', { name, type }),
      },
    ];
  }

  // DNAMEs first, so the CNAMEs they synthesize can be judged against them
  const ordered = [
    ...rrsets.filter(rrset => rrset.type === DNAME),
    ...rrsets.filter(rrset => rrset.type !== DNAME),
  ];
  const verifiedDnames: Rrset[] = [];
  for (const rrset of ordered) {
    if (stopAtFirst && links.some(link => link.status === BOGUS)) return links;
    // a DS RRset is the parent's data
    const zone = enclosing(rrset.name, rrset.type === DS);
    if (!zone || zone.status !== SECURE) {
      links.push(inherit(zone, 'rrset', rrset.name, rrset.typeName));
      continue;
    }
    const check = await checkIn(zone, rrset, rrsigs, options);
    if (
      check.code === RRSET_CODES.UNSIGNED &&
      rrset.type === CNAME &&
      synthesized(rrset, verifiedDnames)
    ) {
      links.push({
        kind: 'rrset',
        zone: zone.zone,
        name: rrset.name,
        type: rrset.typeName,
        status: SECURE,
        reason: securityReason(R.VERIFIED, zone.zone, { name: rrset.name, type: rrset.typeName }),
        evidence: { kind: 'rrset', check },
      });
      continue;
    }
    const verdict = rrsetVerdict(check, zone.zone);
    links.push({
      kind: 'rrset',
      zone: zone.zone,
      name: rrset.name,
      type: rrset.typeName,
      ...verdict,
      evidence: { kind: 'rrset', check },
    });
    if (verdict.status !== SECURE) continue;
    if (rrset.type === DNAME) verifiedDnames.push(rrset);

    // an answer synthesized from a wildcard is only good with a proof that the name it
    // answers has no records of its own (RFC 4035 §5.3.4)
    const wildcard = check.signatures.find(
      signature => signature.result === VERIFIED && signature.wildcard
    );
    if (wildcard) {
      const owner = wildcardOwner(rrset.name, wildcard.rrsig.labels);
      links.push(
        await judgeDenial(zone, response, rrsigs, options, rrset.name, 'wildcard', records => ({
          proof: verifyWildcardProof(rrset.name, records, owner),
          // the wildcard's parent is the closest encloser
          optOut: nextCloserOptOut(rrset.name, records, parentName(canonicalName(owner))),
        }))
      );
    }
  }

  // the end of the alias chain, the name the last alias was found at, and whether the end
  // holds what was asked for
  let target = canonicalName(response.name);
  let lastAlias = target;
  for (let step = 0; step <= rrsets.length; step++) {
    const next = aliasStep(target, rrsets);
    if (next === undefined) break;
    lastAlias = target;
    target = next;
  }
  const answered = rrsets.some(
    rrset =>
      canonicalName(rrset.name) === target &&
      (rrset.type === response.type || response.type === RECORD_TYPES.ANY)
  );
  // the rcode is not signed: an answer stands for itself only under NOERROR. An NXDOMAIN
  // keeps the alias RRsets on the way, and the name at the end still takes a denial proof
  if (
    response.rcode === RCODES.NOERROR &&
    (answered || (response.type === CNAME && rrsets.some(rrset => rrset.type === CNAME)))
  )
    return links;
  const aliased = target !== canonicalName(response.name);
  if (aliased && response.rcode === RCODES.NOERROR && !asked.has(target)) {
    // this response stops at the alias. A server answering for its own zone hands over an
    // alias that leads elsewhere and nothing about the name it leads to; one that leads
    // inside its zone it follows. A recursive resolver follows every alias. Otherwise only a
    // response that speaks for the target's zone (its SOA beside the empty answer) says the
    // target has nothing. Where the target has to be accounted for, it takes a proof
    const targetZone = enclosing(target)?.zone;
    const speaksForTarget = response.authorities.some(
      record =>
        record.type === SOA && targetZone !== undefined && canonicalName(record.name) === targetZone
    );
    const insideZone = targetZone !== undefined && enclosing(lastAlias)?.zone === targetZone;
    if (!response.recursive && !insideZone && !speaksForTarget) return links;
  } else if (aliased && response.rcode === RCODES.NOERROR) {
    // the alias is answered by another response
    return links;
  }
  if (response.rcode !== RCODES.NOERROR && response.rcode !== RCODES.NXDOMAIN) {
    links.push({
      kind: 'denial',
      zone: enclosing(target)?.zone ?? '.',
      name: target,
      type: typeName(response.type),
      status: INDETERMINATE,
      reason: securityReason(R.RESPONSE_MISSING, enclosing(target)?.zone ?? '.', { name: target }),
    });
    return links;
  }

  // a name with nothing of the type, or no name at all: the zone has to prove it. Whether
  // a name has a DS is its parent's to say
  const ds = response.type === DS;
  const zone = enclosing(target, ds);
  if (!zone || zone.status !== SECURE) {
    links.push(inherit(zone, 'denial', target, typeName(response.type)));
    return links;
  }
  const nxdomain = response.rcode === RCODES.NXDOMAIN;
  links.push(
    await judgeDenial(
      zone,
      response,
      rrsigs,
      options,
      target,
      nxdomain ? 'nxdomain' : 'nodata',
      records => {
        if (nxdomain) {
          return {
            proof: verifyNxdomainProof(target, records),
            optOut: nextCloserOptOut(target, records),
          };
        }
        // a DS proof allows an opt-out range over the name (RFC 5155 §8.6)
        const proof = ds
          ? verifyNoDsProof(target, records)
          : verifyNodataProof(target, response.type, records);
        // a name with an NSEC or NSEC3 of its own is in no opt-out range; one without was
        // proven through a wildcard, whose next closer name may be
        const exact = denialTypesAt(target, records).types !== undefined;
        return { proof, optOut: !exact && nextCloserOptOut(target, records) };
      }
    )
  );
  return links;
}

async function judgeDenial(
  zone: ZoneState,
  response: DnssecResponse,
  rrsigs: ResourceRecord[],
  options: RrsetOptions,
  name: string,
  purpose: 'wildcard' | 'nxdomain' | 'nodata',
  // the proof, and whether the NSEC3 covering the next closer name sets opt-out
  prove: (records: ResourceRecord[]) => { proof: DenialProof; optOut: boolean }
): Promise<JudgedLink> {
  const type = purpose === 'nodata' ? typeName(response.type) : undefined;
  const link = (
    status: SecurityStatus,
    code: ReasonCode,
    evidence: DenialEvidence,
    about: Record<string, unknown> = {}
  ): JudgedLink => ({
    kind: 'denial',
    zone: zone.zone,
    name,
    ...(type && { type }),
    status,
    reason: securityReason(code, zone.zone, { name, ...(type && { type }), ...about }),
    evidence: { ...evidence, purpose },
  });

  const denial = await checkDenialRecords(zone, response.authorities, rrsigs, options);
  if (!denial) {
    return link(BOGUS, R.DENIAL_MISSING, { kind: 'denial', records: [], proof: prove([]).proof });
  }
  const records: DenialEvidence = { kind: 'denial', records: denial.checks };
  const unsigned = denial.checks.find(check => check.code !== RRSET_CODES.VERIFIED);
  if (unsigned) {
    const verdict = rrsetVerdict(unsigned, zone.zone);
    return link(verdict.status, verdict.reason.code, records, {
      name: unsigned.rrset.name,
      type: unsigned.rrset.typeName,
    });
  }
  const expanded = denial.checks.find(expandedFromWildcard);
  if (expanded) {
    return link(BOGUS, R.DENIAL_INVALID, records, {
      name: expanded.rrset.name,
      type: expanded.rrset.typeName,
    });
  }

  // past the iterations validators hash, nothing is hashed at all (RFC 9276 §3.2)
  if (nsec3Iterations(denial.records) > NSEC3_ITERATIONS_INSECURE_THRESHOLD) {
    return link(INSECURE, R.NSEC3_ITERATIONS, {
      ...records,
      proof: iterationsExceededProof(name, purpose, denial.records),
    });
  }
  const { proof, optOut } = prove(denial.records);
  const proven: DenialEvidence = { ...records, proof };
  if (proof.result === VERIFIED) {
    // the NSEC3 covering the next closer name sets opt-out: an unsigned delegation may
    // sit in its range, so the proof does not authenticate the answer (RFC 5155 §9.2)
    if (optOut) return link(INSECURE, R.OPT_OUT, proven);
    return link(SECURE, R.VERIFIED, proven);
  }
  if (proof.status === PROOF_STATUSES.OPT_OUT) return link(INSECURE, R.OPT_OUT, proven);
  return link(BOGUS, proof.records.length ? R.DENIAL_INVALID : R.DENIAL_MISSING, proven);
}
