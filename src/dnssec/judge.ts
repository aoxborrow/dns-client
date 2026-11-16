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
import type { Rrset, WireRecord } from './canonical';
import {
  checkAnchors,
  checkDsSet,
  checkKeySet,
  checkRrset,
  KEY_SET_CODES,
  readKeys,
  RRSET_CODES,
  SIGNATURE_CODES,
} from './checks';
import type {
  AnchorCheck,
  DnssecKey,
  DsSetCheck,
  KeySetCheck,
  RrsetCheck,
  SignatureCheck,
} from './checks';
import {
  NSEC3_ITERATIONS_INSECURE_THRESHOLD,
  PROOF_STATUSES,
  VERIFICATION_RESULTS,
} from './constants';
import {
  denialTypesAt,
  verifyNodataProof,
  verifyNoDsProof,
  verifyNxdomainProof,
  verifyWildcardProof,
} from './nsec';
import { REASON_CODES, SECURITY_STATUSES, securityReason } from './reasons';
import type { ReasonCode, SecurityReason, SecurityStatus } from './reasons';
import type { DenialProof, TrustAnchor } from './types';

// the judging core: given the records fetched for each zone on the way down from a trust
// anchor, and the responses whose data is to be trusted, say whether each link holds and
// why. It fetches nothing and keeps no state, so the same records and time always give
// the same judgement. `mode: 'first'` stops as soon as the outcome is settled, the way a
// validating resolver does; `mode: 'all'` judges every link and every signature, for a
// report of everything that is wrong

const { SECURE, INSECURE, BOGUS, INDETERMINATE } = SECURITY_STATUSES;
const R = REASON_CODES;
const { VERIFIED } = VERIFICATION_RESULTS;
const { DS, RRSIG, NSEC, NSEC3, CNAME, DNAME, NS, SOA } = RECORD_TYPES;

// one response, as the judgement reads it
export interface DnssecResponse {
  // the question that was sent: never the response's own question section, which is
  // unsigned and could name something else
  name: string;
  type: number;
  rcode: number;
  answers: WireRecord[];
  authorities: WireRecord[];
}

// a name between the trust anchor and the data, with what was fetched for it
export interface ChainName {
  name: string;
  // the answer to `<name> DS`, which the zone above gives
  ds?: DnssecResponse;
  // the answer to `<name> DNSKEY`, needed where `ds` shows the name is a zone of its own
  dnskey?: DnssecResponse;
}

// what is known about a name from an earlier judgement, so it need not be fetched or
// judged again: whether it is a zone of its own and, if so, what came of its key set
export interface ZoneFact {
  name: string;
  // false: the name is inside the zone above it
  cut: boolean;
  status: SecurityStatus;
  reason: SecurityReason;
  // the zone's validated keys, for a secure zone
  keys: DnssecKey[];
  // how long the fact holds, in seconds: the shortest TTL, or signature lifetime, it rests on
  ttl: number;
}

export interface ChainInput {
  // the DNSKEY response of the zone the trust anchors are for: the root unless the
  // anchors say otherwise
  anchored?: DnssecResponse;
  // the names below it, each with its DS response and, for a zone cut, its DNSKEY response
  names?: ChainName[];
  // the responses whose data is judged
  responses?: DnssecResponse[];
  // what earlier judgements established, which is used as it is
  known?: ZoneFact[];
}

export type JudgeMode = 'first' | 'all';

export interface JudgeOptions {
  // default: IANA's root trust anchors
  trustAnchors?: readonly TrustAnchor[];
  // the time signatures and anchors are judged at. Default: now
  now?: Date;
  // 'first' (default) stops at the first link that settles the outcome; 'all' judges
  // every link
  mode?: JudgeMode;
  // require each RRset to be signed by every algorithm in its zone's key set (RFC 4035
  // §2.2). Validators accept any one (RFC 6840 §5.11), so off by default
  requireEveryAlgorithm?: boolean;
}

export type LinkKind = 'keys' | 'rrset' | 'denial';

// one link in the chain: a zone's key set (vouched for by the trust anchor or by its
// parent's DS), an RRset of the data, or a proof that something does not exist
export interface ChainLink {
  kind: LinkKind;
  zone: string;
  // the RRset or name the link is about, for data and proofs
  name?: string;
  type?: string;
  status: SecurityStatus;
  reason: SecurityReason;
}

export interface Judgement {
  status: SecurityStatus;
  reason: SecurityReason;
  // every link judged, zones from the top down, then the data
  links: ChainLink[];
  // the first link that is bogus or indeterminate, when the outcome is either
  failure?: ChainLink;
  // what this judgement established about each name, to keep for next time. Only secure
  // and insecure outcomes are given: a broken or unanswered zone is asked about again
  facts: ZoneFact[];
}

interface ZoneState {
  zone: string;
  status: SecurityStatus;
  reason: SecurityReason;
  keys: DnssecKey[];
}

// ---------------------------------------------------------------------------

export async function judgeChain(
  input: ChainInput,
  options: JudgeOptions = {}
): Promise<Judgement> {
  const now = options.now ?? new Date();
  const anchors = options.trustAnchors ?? ROOT_TRUST_ANCHORS;
  const mode = options.mode ?? 'first';
  const stopAtFirst = mode === 'first';
  const rrsetOptions = {
    now,
    stopAtFirst,
    requireEveryAlgorithm: options.requireEveryAlgorithm ?? false,
  };

  const links: ChainLink[] = [];
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
    const state = await judgeKeys(anchorZone, input.anchored, { anchors }, now, stopAtFirst);
    zones.set(anchorZone, state.zone);
    links.push(keysLink(state.zone));
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
      links.push(keysLink(judged.cut));
    } else if (judged.inside) {
      insideZone.add(name);
    }
    if (judged.fact) facts.push(judged.fact);
  }

  // the data
  const dataLinks: ChainLink[] = [];
  for (const response of input.responses ?? []) {
    if (done()) break;
    const judged = await judgeResponse(response, enclosing, rrsetOptions, stopAtFirst);
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

function keysLink(zone: ZoneState): ChainLink {
  return { kind: 'keys', zone: zone.zone, status: zone.status, reason: zone.reason };
}

// ---------------------------------------------------------------------------
// a zone's key set
// ---------------------------------------------------------------------------

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
  | { ds: readonly WireRecord[]; dsTtl?: number; authenticated?: boolean };

// judge a zone's key set against its entry points. Every check is made and handed back,
// even past a failure, unless `stopAtFirst`
export async function judgeKeys(
  zone: string,
  dnskey: DnssecResponse | undefined,
  entry: KeysEntry,
  now: Date,
  stopAtFirst = false
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
    anchors = await checkAnchors(zone, keys, entry.anchors, now, { rrset, rrsigs });
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
      if (verifying) {
        lifetimes.push(Math.floor((verifying.rrsig.expiration * 1000 - now.getTime()) / 1000));
      }
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
    case KEY_SET_CODES.NO_SUPPORTED_ALGORITHM:
      // no algorithm the entry points name can be verified here: no path to check, which
      // a validator treats as no DS at all (RFC 4035 §5.2, RFC 6840 §5.2)
      return {
        zone: state(INSECURE, R.UNSUPPORTED_ALGORITHM, { algorithm: entryAlgorithms[0] }),
        ...judged,
      };
    case KEY_SET_CODES.NO_ENTRY_KEY: {
      const failed = dsSet?.checks.find(check => check.selected);
      const code = failed?.code === 'digest-mismatch' ? R.DS_DIGEST_MISMATCH : R.NO_MATCHING_DNSKEY;
      return { zone: state(BOGUS, code, { keyTag: failed?.ds.keyTag }), ...judged };
    }
    default: {
      const byEntry = keySet.signatures.find(signature =>
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
      if (
        own.length > 0 &&
        own.every(signature => signature.code === SIGNATURE_CODES.UNSUPPORTED_ALGORITHM)
      ) {
        return {
          status: INDETERMINATE,
          reason: securityReason(R.UNVERIFIABLE, zone, {
            ...about,
            algorithm: own[0].rrsig.algorithm,
          }),
        };
      }
      const failed =
        own.find(signature => signature.code !== SIGNATURE_CODES.UNSUPPORTED_ALGORITHM) ?? own[0];
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
  // the name is inside its parent's zone
  inside?: boolean;
  fact?: ZoneFact;
}

type RrsetOptions = { now: Date; stopAtFirst: boolean; requireEveryAlgorithm: boolean };

// the NSEC and NSEC3 RRsets of a response's authority section, each checked in `zone`.
// Undefined when there are none
async function checkDenialRecords(
  zone: ZoneState,
  authorities: WireRecord[],
  rrsigs: WireRecord[],
  options: RrsetOptions
): Promise<RrsetCheck[] | undefined> {
  const rrsets = groupRrsets(
    authorities.filter(record => record.type === NSEC || record.type === NSEC3)
  );
  if (rrsets.length === 0) return undefined;
  const checks: RrsetCheck[] = [];
  for (const rrset of rrsets) checks.push(await checkRrset(zone, rrset, rrsigs, options));
  return checks;
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
  const cut = (status: SecurityStatus, code: ReasonCode, about = {}): NameJudgement => {
    const zone: ZoneState = {
      zone: name,
      status,
      reason: securityReason(code, name, about),
      keys: [],
    };
    return { cut: zone };
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
    const signed = await checkRrset(parent, dsRrset, rrsigs, options);
    if (signed.code !== RRSET_CODES.VERIFIED) {
      const verdict = rrsetVerdict(signed, parent.zone);
      const code =
        verdict.reason.code === R.RRSIGS_MISSING ? R.DS_UNAUTHENTICATED : verdict.reason.code;
      return cut(verdict.status, code, { name, type: 'DS' });
    }
    const judged = await judgeKeys(
      name,
      entry.dnskey,
      { ds: dsRrset.records, dsTtl: dsRrset.ttl },
      now,
      options.stopAtFirst
    );
    const fact =
      judged.fact ??
      (judged.zone.status === INSECURE ? factOf(judged.zone, true, dsRrset.ttl) : undefined);
    return { cut: judged.zone, ...(fact && { fact }) };
  }

  // a CNAME at the name: an alias cannot be a zone cut
  const alias = answerSets.find(
    rrset => rrset.type === CNAME && canonicalName(rrset.name) === owner
  );
  if (alias) {
    const signed = await checkRrset(parent, alias, rrsigs, options);
    if (signed.code === RRSET_CODES.VERIFIED) {
      return { inside: true, fact: factOf(parent, false, alias.ttl, name) };
    }
    const verdict = rrsetVerdict(signed, parent.zone);
    return cut(verdict.status, verdict.reason.code, { name, type: 'CNAME' });
  }

  // no DS: the parent has to prove it, with NSEC or NSEC3 records it signed
  const denial = await checkDenialRecords(parent, response.authorities, rrsigs, options);
  if (!denial) return cut(BOGUS, R.NO_DS_PROOF, { name, type: 'DS' });
  const unsigned = denial.find(check => check.code !== RRSET_CODES.VERIFIED);
  if (unsigned) {
    const verdict = rrsetVerdict(unsigned, parent.zone);
    return cut(
      BOGUS,
      verdict.reason.code === R.RRSIGS_MISSING ? R.DS_UNAUTHENTICATED : verdict.reason.code,
      {
        name: unsigned.rrset.name,
        type: unsigned.rrset.typeName,
      }
    );
  }
  const ttl = Math.min(...denial.map(check => check.rrset.ttl));

  const proof = verifyNoDsProof(name, response.authorities);
  if (tooManyIterations(proof)) return insecureCut(name, R.NSEC3_ITERATIONS, ttl);
  if (proof.status === PROOF_STATUSES.OPT_OUT) return insecureCut(name, R.OPT_OUT, ttl);
  if (proof.result !== VERIFIED) return cut(BOGUS, R.NO_DS_PROOF, { name, type: 'DS' });

  const at = denialTypesAt(name, response.authorities);
  if (at.types?.includes(NS) && !at.types.includes(SOA)) {
    // a delegation with no DS: the zone below is unsigned
    return insecureCut(name, R.NO_DS, ttl);
  }
  // the name has no NS, or does not exist: it is inside the parent's zone
  return { inside: true, fact: factOf(parent, false, ttl, name) };
}

function insecureCut(name: string, code: ReasonCode, ttl: number): NameJudgement {
  const zone: ZoneState = {
    zone: name,
    status: INSECURE,
    reason: securityReason(code, name),
    keys: [],
  };
  return { cut: zone, fact: factOf(zone, true, ttl) };
}

function factOf(zone: ZoneState, cut: boolean, ttl: number, name = zone.zone): ZoneFact {
  return cut
    ? { name, cut, status: zone.status, reason: zone.reason, keys: zone.keys, ttl }
    : { name, cut, status: zone.status, reason: zone.reason, keys: [], ttl };
}

function tooManyIterations(proof: DenialProof): boolean {
  return (proof.nsec3Params?.iterations ?? 0) > NSEC3_ITERATIONS_INSECURE_THRESHOLD;
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

function targetOf(record: WireRecord): string {
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
  stopAtFirst: boolean
): Promise<ChainLink[]> {
  const links: ChainLink[] = [];
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
    const check = await checkRrset(zone, rrset, rrsigs, options);
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
    });
    if (verdict.status !== SECURE) continue;
    if (rrset.type === DNAME) verifiedDnames.push(rrset);

    // an answer synthesized from a wildcard is only good with a proof that the name it
    // answers has no records of its own (RFC 4035 §5.3.4)
    const wildcard = check.signatures.find(
      signature => signature.result === VERIFIED && signature.wildcard
    );
    if (wildcard) {
      links.push(
        await judgeDenial(zone, response, rrsigs, options, rrset.name, 'wildcard', () =>
          verifyWildcardProof(
            rrset.name,
            response.authorities,
            wildcardOwner(rrset.name, wildcard.rrsig.labels)
          )
        )
      );
    }
  }

  // the end of the alias chain, and whether it holds what was asked for
  let target = canonicalName(response.name);
  for (let step = 0; step <= rrsets.length; step++) {
    const next = aliasStep(target, rrsets);
    if (next === undefined) break;
    target = next;
  }
  const answered = rrsets.some(
    rrset =>
      canonicalName(rrset.name) === target &&
      (rrset.type === response.type || response.type === RECORD_TYPES.ANY)
  );
  if (answered || (response.type === CNAME && rrsets.some(rrset => rrset.type === CNAME)))
    return links;
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

  // a name with nothing of the type, or no name at all: the zone has to prove it
  const zone = enclosing(target);
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
      () =>
        nxdomain
          ? verifyNxdomainProof(target, response.authorities)
          : verifyNodataProof(target, response.type, response.authorities)
    )
  );
  return links;
}

async function judgeDenial(
  zone: ZoneState,
  response: DnssecResponse,
  rrsigs: WireRecord[],
  options: RrsetOptions,
  name: string,
  purpose: 'wildcard' | 'nxdomain' | 'nodata',
  prove: () => DenialProof
): Promise<ChainLink> {
  const type = purpose === 'nodata' ? typeName(response.type) : undefined;
  const link = (
    status: SecurityStatus,
    code: ReasonCode,
    about: Record<string, unknown> = {}
  ): ChainLink => ({
    kind: 'denial',
    zone: zone.zone,
    name,
    ...(type && { type }),
    status,
    reason: securityReason(code, zone.zone, { name, ...(type && { type }), ...about }),
  });

  const denial = await checkDenialRecords(zone, response.authorities, rrsigs, options);
  if (!denial) return link(BOGUS, R.DENIAL_MISSING);
  const unsigned = denial.find(check => check.code !== RRSET_CODES.VERIFIED);
  if (unsigned) {
    const verdict = rrsetVerdict(unsigned, zone.zone);
    return link(verdict.status, verdict.reason.code, {
      name: unsigned.rrset.name,
      type: unsigned.rrset.typeName,
    });
  }

  const proof = prove();
  if (tooManyIterations(proof)) return link(INSECURE, R.NSEC3_ITERATIONS);
  if (proof.result === VERIFIED) {
    // an opt-out range over the name: it may sit below an unsigned delegation
    if (purpose === 'nxdomain' && proof.optOut) return link(INSECURE, R.OPT_OUT);
    return link(SECURE, R.VERIFIED);
  }
  if (proof.status === PROOF_STATUSES.OPT_OUT) return link(INSECURE, R.OPT_OUT);
  return link(BOGUS, proof.records.length ? R.DENIAL_INVALID : R.DENIAL_MISSING);
}
