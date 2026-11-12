import { toHex } from '../wire/bytes';
import { compareNames, splitName } from '../wire/names';
import {
  WireRecord,
  decodeNsec,
  decodeNsec3,
  nsec3Hash,
  toNsec3Label,
  canonicalName,
  countLabels,
  parentName,
  presentRecord,
  isInZone,
  TYPE_NSEC,
  TYPE_NSEC3,
  TYPE_DS,
  TYPE_SOA,
  TYPE_NS,
  TYPE_CNAME,
  recordTypeName,
} from './wire';
import { DenialProof, ProofStep, Nsec3Params, ProofPurpose } from './types';
import {
  PROOF_STATUSES,
  PROOF_TYPES,
  PROOF_PURPOSES,
  VERIFICATION_RESULTS,
  NSEC3_FLAGS,
  NSEC3_HASH_ALGORITHMS,
  NSEC3_ITERATIONS_INSECURE_THRESHOLD,
  NSEC3_ITERATIONS_SERVFAIL_THRESHOLD,
} from './constants';

// NSEC and NSEC3 proof validation (RFC 4035 §5.4, RFC 5155 §8, RFC 7129).
//
// this is what turns `insecure` from a guess into a proof. inferring "unsigned" from the
// absence of records is spoofable by anyone who can strip records in transit; a verified
// denial proof is not.

const { VERIFIED, FAILED, UNCHECKED } = VERIFICATION_RESULTS;

// ---------------------------------------------------------------------------
// canonical name ordering (RFC 4034 §6.1)
// ---------------------------------------------------------------------------

// names sort by label, right to left, each label compared as lowercase unsigned octets. The
// labels are read from the presentation form the way the wire decoder writes it, so an
// escaped dot stays inside its label and `\255` compares as the octet 0xff. Throws for a
// name that cannot be written in wire form
export function compareCanonicalNames(a: string, b: string): number {
  return compareNames(a, b);
}

// does the half-open NSEC interval (owner, next] cover `name`? the last NSEC in a zone wraps
// around to the apex, so `next <= owner` means the range runs past the end of the zone. A
// name that cannot be written in wire form is never covered
function nsecCovers(owner: string, next: string, name: string): boolean {
  try {
    const afterOwner = compareCanonicalNames(name, owner) > 0;
    const beforeNext = compareCanonicalNames(name, next) < 0;
    return compareCanonicalNames(next, owner) <= 0
      ? afterOwner || beforeNext
      : afterOwner && beforeNext;
  } catch {
    return false;
  }
}

// the same wrap-aware range test over base32hex NSEC3 labels, which are plain ASCII and so
// compare lexicographically
function nsec3Covers(ownerHash: string, nextHash: string, hash: string): boolean {
  const afterOwner = hash > ownerHash;
  const beforeNext = hash < nextHash;
  return nextHash <= ownerHash ? afterOwner || beforeNext : afterOwner && beforeNext;
}

// ---------------------------------------------------------------------------
// parameters
// ---------------------------------------------------------------------------

// RFC 9276 §3.1 assessment of a zone's NSEC3 parameters
export function assessNsec3Params(
  hashAlgorithm: number,
  iterations: number,
  salt: Uint8Array,
  optOut: boolean
): Nsec3Params {
  const notes: string[] = [];
  const hash = NSEC3_HASH_ALGORITHMS[hashAlgorithm as keyof typeof NSEC3_HASH_ALGORITHMS];

  if (!hash) {
    notes.push(`Hash algorithm ${hashAlgorithm} is not defined for NSEC3 and cannot be verified.`);
  }
  if (iterations > 0) {
    let note = `RFC 9276 requires 0 iterations; this zone uses ${iterations}.`;
    if (iterations > NSEC3_ITERATIONS_SERVFAIL_THRESHOLD) {
      note += ' Validators commonly return SERVFAIL above 500.';
    } else if (iterations > NSEC3_ITERATIONS_INSECURE_THRESHOLD) {
      note += ' Validators commonly treat counts above 100 as insecure.';
    }
    notes.push(note);
  }
  if (salt.length > 0) {
    notes.push('RFC 9276 recommends no salt; a salt adds no protection against enumeration.');
  }
  if (optOut) {
    notes.push('Opt-out is set, so the absence of unsigned delegations is not authenticated.');
  }

  return {
    hashAlgorithm,
    hashAlgorithmName: hash?.name ?? `Unknown (${hashAlgorithm})`,
    iterations,
    salt: toHex(salt),
    optOut,
    conforms: iterations === 0 && salt.length === 0 && Boolean(hash),
    notes,
  };
}

// ---------------------------------------------------------------------------
// proof construction
// ---------------------------------------------------------------------------

interface NsecEntry {
  record: WireRecord;
  owner: string;
  next: string;
  types: number[];
}

interface Nsec3Entry {
  record: WireRecord;
  // the first label of the owner name, which is the base32hex hash
  ownerHash: string;
  // the zone the NSEC3 belongs to (the owner name minus the hash label)
  zone: string;
  nextHash: string;
  types: number[];
  hashAlgorithm: number;
  iterations: number;
  salt: Uint8Array;
  optOut: boolean;
}

function collectNsec(records: WireRecord[]): NsecEntry[] {
  const out: NsecEntry[] = [];
  for (const rr of records) {
    if (rr.type !== TYPE_NSEC) continue;
    const decoded = decodeNsec(rr.rdata);
    if (!decoded) continue;
    out.push({ record: rr, owner: rr.name, next: decoded.nextDomain, types: decoded.types });
  }
  return out;
}

function collectNsec3(records: WireRecord[]): Nsec3Entry[] {
  const out: Nsec3Entry[] = [];
  for (const rr of records) {
    if (rr.type !== TYPE_NSEC3) continue;
    const decoded = decodeNsec3(rr.rdata);
    if (!decoded) continue;
    const [ownerHash, ...zone] = splitName(rr.name);
    if (zone.length === 0) continue;
    out.push({
      record: rr,
      ownerHash: ownerHash.toLowerCase(),
      zone: zone.join('.'),
      nextHash: toNsec3Label(decoded.nextHashed),
      types: decoded.types,
      hashAlgorithm: decoded.hashAlgorithm,
      iterations: decoded.iterations,
      salt: decoded.salt,
      optOut: Boolean(decoded.flags & NSEC3_FLAGS.OPT_OUT),
    });
  }
  return out;
}

function step(label: string, detail: string, result: ProofStep['result']): ProofStep {
  return { label, detail, result };
}

function emptyProof(
  type: DenialProof['type'],
  purpose: ProofPurpose,
  qname: string,
  reason: string
): DenialProof {
  return {
    type,
    purpose,
    status: PROOF_STATUSES.MISSING,
    result: FAILED,
    qname,
    records: [],
    steps: [step('Proof records', reason, FAILED)],
    optOut: false,
    reason,
  };
}

// find the NSEC3 whose owner hash matches `name`, and the one whose range covers it
function matchNsec3(entries: Nsec3Entry[], name: string): Nsec3Entry | undefined {
  for (const entry of entries) {
    const hash = nsec3Hash(name, entry.salt, entry.iterations, entry.hashAlgorithm);
    if (hash && hash === entry.ownerHash) return entry;
  }
  return undefined;
}

function coverNsec3(
  entries: Nsec3Entry[],
  name: string
): { entry: Nsec3Entry; hash: string } | undefined {
  for (const entry of entries) {
    const hash = nsec3Hash(name, entry.salt, entry.iterations, entry.hashAlgorithm);
    if (hash && nsec3Covers(entry.ownerHash, entry.nextHash, hash)) return { entry, hash };
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// proof of no DS — the one that makes `insecure` provable
// ---------------------------------------------------------------------------

// the parent answered a DS query with NODATA. establish that no DS exists at the delegation
export function verifyNoDsProof(qname: string, records: WireRecord[]): DenialProof {
  const nsec3 = collectNsec3(records);
  if (nsec3.length > 0) return verifyNoDsNsec3(qname, nsec3);

  const nsec = collectNsec(records);
  if (nsec.length > 0) return verifyNoDsNsec(qname, nsec);

  return emptyProof(
    PROOF_TYPES.NSEC,
    PROOF_PURPOSES.NO_DS,
    qname,
    'The parent returned no NSEC or NSEC3 records, so the absence of a DS record is unproven.'
  );
}

function verifyNoDsNsec(qname: string, entries: NsecEntry[]): DenialProof {
  const steps: ProofStep[] = [];
  const name = canonicalName(qname);

  // the delegation point itself has an NSEC whose bitmap carries NS but not DS
  const match = entries.find(e => e.owner === name);
  if (match) {
    const hasDs = match.types.includes(TYPE_DS);
    const hasSoa = match.types.includes(TYPE_SOA);
    const hasNs = match.types.includes(TYPE_NS);

    steps.push(
      step('Matching NSEC', `Owner ${match.owner} matches the delegation name exactly.`, VERIFIED)
    );
    steps.push(
      step(
        'Type bitmap',
        `Types present: ${match.types.map(recordTypeName).join(' ') || '(none)'}.`,
        hasDs ? FAILED : VERIFIED
      )
    );

    if (hasDs) {
      return {
        type: PROOF_TYPES.NSEC,
        purpose: PROOF_PURPOSES.NO_DS,
        status: PROOF_STATUSES.INVALID_HASH,
        result: FAILED,
        qname: name,
        records: entries.map(e => presentRecord(e.record)),
        steps,
        optOut: false,
        reason: 'The NSEC bitmap lists DS, contradicting the empty answer.',
      };
    }

    // an NSEC with SOA and no NS is the zone apex, not a delegation — it proves nothing
    // about a child (RFC 6840 §4.4)
    if (hasSoa && !hasNs) {
      steps.push(
        step(
          'Delegation check',
          'The NSEC is the zone apex, not a delegation point, so it cannot prove a child has no DS.',
          FAILED
        )
      );
      return {
        type: PROOF_TYPES.NSEC,
        purpose: PROOF_PURPOSES.NO_DS,
        status: PROOF_STATUSES.INCOMPLETE,
        result: FAILED,
        qname: name,
        records: entries.map(e => presentRecord(e.record)),
        steps,
        optOut: false,
        reason: 'The NSEC returned belongs to the zone apex rather than the delegation.',
      };
    }

    return {
      type: PROOF_TYPES.NSEC,
      purpose: PROOF_PURPOSES.NO_DS,
      status: PROOF_STATUSES.VERIFIED,
      result: VERIFIED,
      qname: name,
      records: entries.map(e => presentRecord(e.record)),
      steps,
      optOut: false,
    };
  }

  // no NSEC at the name itself: the name must be covered by a range, proving it does not
  // exist at all — and therefore neither does a DS at it
  const covering = entries.find(e => nsecCovers(e.owner, e.next, name));
  if (covering) {
    steps.push(
      step(
        'Covering NSEC',
        `${name} falls between ${covering.owner} and ${covering.next}, so the name does not exist.`,
        VERIFIED
      )
    );
    return {
      type: PROOF_TYPES.NSEC,
      purpose: PROOF_PURPOSES.NO_DS,
      status: PROOF_STATUSES.VERIFIED,
      result: VERIFIED,
      qname: name,
      records: entries.map(e => presentRecord(e.record)),
      steps,
      optOut: false,
    };
  }

  steps.push(step('Covering NSEC', `No NSEC record covers or matches ${name}.`, FAILED));
  return {
    type: PROOF_TYPES.NSEC,
    purpose: PROOF_PURPOSES.NO_DS,
    status: PROOF_STATUSES.INCOMPLETE,
    result: FAILED,
    qname: name,
    records: entries.map(e => presentRecord(e.record)),
    steps,
    optOut: false,
    reason: 'The NSEC records returned neither match nor cover the delegation name.',
  };
}

function verifyNoDsNsec3(qname: string, entries: Nsec3Entry[]): DenialProof {
  const steps: ProofStep[] = [];
  const name = canonicalName(qname);
  const first = entries[0];
  const params = assessNsec3Params(
    first.hashAlgorithm,
    first.iterations,
    first.salt,
    entries.some(e => e.optOut)
  );
  const records = entries.map(e => presentRecord(e.record));

  if (!NSEC3_HASH_ALGORITHMS[first.hashAlgorithm as keyof typeof NSEC3_HASH_ALGORITHMS]) {
    return {
      type: PROOF_TYPES.NSEC3,
      purpose: PROOF_PURPOSES.NO_DS,
      status: PROOF_STATUSES.UNSUPPORTED_ALGORITHM,
      result: UNCHECKED,
      qname: name,
      records,
      steps: [
        step(
          'Hash algorithm',
          `NSEC3 hash algorithm ${first.hashAlgorithm} is not one this tool can compute.`,
          UNCHECKED
        ),
      ],
      optOut: params.optOut,
      nsec3Params: params,
      reason: `Unsupported NSEC3 hash algorithm ${first.hashAlgorithm}.`,
    };
  }

  // direct match: an NSEC3 for the delegation name itself, whose bitmap lacks DS
  const match = matchNsec3(entries, name);
  if (match) {
    const hash = nsec3Hash(name, match.salt, match.iterations, match.hashAlgorithm)!;
    steps.push(
      step(
        'Matching NSEC3',
        `${name} hashes to ${hash}, which is the owner of an NSEC3 record.`,
        VERIFIED
      )
    );
    const hasDs = match.types.includes(TYPE_DS);
    steps.push(
      step(
        'Type bitmap',
        `Types present: ${match.types.map(recordTypeName).join(' ') || '(none)'}.`,
        hasDs ? FAILED : VERIFIED
      )
    );
    if (hasDs) {
      return {
        type: PROOF_TYPES.NSEC3,
        purpose: PROOF_PURPOSES.NO_DS,
        status: PROOF_STATUSES.INVALID_HASH,
        result: FAILED,
        qname: name,
        records,
        steps,
        optOut: params.optOut,
        nsec3Params: params,
        reason: 'The NSEC3 bitmap lists DS, contradicting the empty answer.',
      };
    }
    return {
      type: PROOF_TYPES.NSEC3,
      purpose: PROOF_PURPOSES.NO_DS,
      status: PROOF_STATUSES.VERIFIED,
      result: VERIFIED,
      qname: name,
      records,
      steps,
      optOut: false,
      nsec3Params: params,
    };
  }

  // no direct match — an opt-out proof: find the closest encloser, then show the next closer
  // name is covered by an NSEC3 with opt-out set
  const closest = findClosestEncloser(entries, name);
  if (!closest) {
    steps.push(
      step('Closest encloser', `No NSEC3 record matches any ancestor of ${name}.`, FAILED)
    );
    return {
      type: PROOF_TYPES.NSEC3,
      purpose: PROOF_PURPOSES.NO_DS,
      status: PROOF_STATUSES.INCOMPLETE,
      result: FAILED,
      qname: name,
      records,
      steps,
      optOut: params.optOut,
      nsec3Params: params,
      reason: 'The closest encloser could not be established.',
    };
  }

  steps.push(
    step('Closest encloser', `${closest.name} is proven to exist by a matching NSEC3.`, VERIFIED)
  );

  const nextCloser = nextCloserName(name, closest.name);
  const covered = coverNsec3(entries, nextCloser);
  if (!covered) {
    steps.push(step('Next closer', `No NSEC3 record covers ${nextCloser}.`, FAILED));
    return {
      type: PROOF_TYPES.NSEC3,
      purpose: PROOF_PURPOSES.NO_DS,
      status: PROOF_STATUSES.INCOMPLETE,
      result: FAILED,
      qname: name,
      records,
      steps,
      optOut: params.optOut,
      nsec3Params: params,
      reason: `The next closer name ${nextCloser} is not covered by any NSEC3 record.`,
    };
  }

  steps.push(
    step(
      'Next closer',
      `${nextCloser} hashes to ${covered.hash}, which falls between ${covered.entry.ownerHash} and ${covered.entry.nextHash}.`,
      VERIFIED
    )
  );

  // opt-out means the covering NSEC3 makes no statement about unsigned delegations in its
  // range. the name is still not proven signed, but the absence is not *authenticated*
  if (covered.entry.optOut) {
    steps.push(
      step(
        'Opt-out',
        'The covering NSEC3 has the opt-out flag set, so the absence of a DS record is asserted but not authenticated.',
        UNCHECKED
      )
    );
    return {
      type: PROOF_TYPES.NSEC3,
      purpose: PROOF_PURPOSES.NO_DS,
      status: PROOF_STATUSES.OPT_OUT,
      result: UNCHECKED,
      qname: name,
      records,
      steps,
      optOut: true,
      nsec3Params: params,
      reason: 'Opt-out is in effect for this delegation.',
    };
  }

  steps.push(step('Opt-out', 'Not set — the absence of a DS record is authenticated.', VERIFIED));
  return {
    type: PROOF_TYPES.NSEC3,
    purpose: PROOF_PURPOSES.NO_DS,
    status: PROOF_STATUSES.VERIFIED,
    result: VERIFIED,
    qname: name,
    records,
    steps,
    optOut: false,
    nsec3Params: params,
  };
}

// the deepest ancestor of `name` that has a matching NSEC3 record
function findClosestEncloser(
  entries: Nsec3Entry[],
  name: string
): { name: string; entry: Nsec3Entry } | undefined {
  let candidate = parentName(name);
  const zone = entries[0].zone;
  for (;;) {
    const match = matchNsec3(entries, candidate);
    if (match) return { name: candidate, entry: match };
    if (candidate === '.' || candidate === zone || !isInZone(candidate, zone)) return undefined;
    const next = parentName(candidate);
    if (next === candidate) return undefined;
    candidate = next;
  }
}

// the name one label longer than the closest encloser, on the path to `name`
function nextCloserName(name: string, closestEncloser: string): string {
  const nameLabels = countLabels(name);
  const encloserLabels = countLabels(closestEncloser);
  if (nameLabels <= encloserLabels + 1) return name;
  const parts = splitName(canonicalName(name));
  return parts.slice(parts.length - (encloserLabels + 1)).join('.');
}

// ---------------------------------------------------------------------------
// NODATA and NXDOMAIN
// ---------------------------------------------------------------------------

// the NODATA bitmap check: the type asked for is absent, and so is CNAME
function bitmapStep(qtype: number, present: boolean, aliased: boolean) {
  if (present) {
    return step(
      'Type bitmap',
      `${recordTypeName(qtype)} is listed in the bitmap, contradicting the empty answer.`,
      FAILED
    );
  }
  if (aliased) {
    return step(
      'Type bitmap',
      'CNAME is listed in the bitmap, so the name is an alias and an empty answer is wrong.',
      FAILED
    );
  }
  return step('Type bitmap', `${recordTypeName(qtype)} is absent from the bitmap.`, VERIFIED);
}

// the zone answered with an empty answer section for a type it does not hold
export function verifyNodataProof(
  qname: string,
  qtype: number,
  records: WireRecord[]
): DenialProof {
  const name = canonicalName(qname);
  const nsec3 = collectNsec3(records);

  if (nsec3.length > 0) {
    const params = assessNsec3Params(
      nsec3[0].hashAlgorithm,
      nsec3[0].iterations,
      nsec3[0].salt,
      nsec3.some(e => e.optOut)
    );
    const match = matchNsec3(nsec3, name);
    const present = match?.types.includes(qtype) ?? false;
    // neither the type asked for nor CNAME may be in the bitmap (RFC 5155 §8.5): a CNAME
    // means the name is an alias, so a bare NODATA is wrong
    const aliased = match?.types.includes(TYPE_CNAME) ?? false;
    const ok = Boolean(match) && !present && !aliased;
    return {
      type: PROOF_TYPES.NSEC3,
      purpose: PROOF_PURPOSES.NODATA,
      status: ok ? PROOF_STATUSES.VERIFIED : PROOF_STATUSES.INCOMPLETE,
      result: ok ? VERIFIED : FAILED,
      qname: name,
      records: nsec3.map(e => presentRecord(e.record)),
      steps: [
        step(
          'Matching NSEC3',
          match
            ? `${name} matches an NSEC3 owner.`
            : `No NSEC3 record matches ${name}, so the empty answer is unproven.`,
          match ? VERIFIED : FAILED
        ),
        bitmapStep(qtype, present, aliased),
      ],
      optOut: params.optOut,
      nsec3Params: params,
      reason: ok ? undefined : 'The NODATA response is not fully proven.',
    };
  }

  const nsec = collectNsec(records);
  if (nsec.length === 0) {
    return emptyProof(
      PROOF_TYPES.NSEC,
      PROOF_PURPOSES.NODATA,
      name,
      'The zone returned an empty answer with no NSEC or NSEC3 records.'
    );
  }

  const match = nsec.find(e => e.owner === name);
  const present = match?.types.includes(qtype) ?? false;
  // a CNAME in the bitmap means the name exists as an alias, so a bare NODATA is wrong
  const aliased = match?.types.includes(TYPE_CNAME) ?? false;
  const ok = Boolean(match) && !present && !aliased;

  return {
    type: PROOF_TYPES.NSEC,
    purpose: PROOF_PURPOSES.NODATA,
    status: ok ? PROOF_STATUSES.VERIFIED : PROOF_STATUSES.INCOMPLETE,
    result: ok ? VERIFIED : FAILED,
    qname: name,
    records: nsec.map(e => presentRecord(e.record)),
    steps: [
      step(
        'Matching NSEC',
        match ? `Owner ${match.owner} matches the query name.` : `No NSEC record matches ${name}.`,
        match ? VERIFIED : FAILED
      ),
      bitmapStep(qtype, present, aliased),
    ],
    optOut: false,
    reason: ok ? undefined : 'The NODATA response is not fully proven.',
  };
}

// the zone said the name does not exist at all
export function verifyNxdomainProof(qname: string, records: WireRecord[]): DenialProof {
  const name = canonicalName(qname);
  const nsec3 = collectNsec3(records);

  if (nsec3.length > 0) {
    const params = assessNsec3Params(
      nsec3[0].hashAlgorithm,
      nsec3[0].iterations,
      nsec3[0].salt,
      nsec3.some(e => e.optOut)
    );
    const steps: ProofStep[] = [];
    const closest = findClosestEncloser(nsec3, name);
    steps.push(
      step(
        'Closest encloser',
        closest
          ? `${closest.name} is proven to exist by a matching NSEC3.`
          : `No NSEC3 record matches any ancestor of ${name}.`,
        closest ? VERIFIED : FAILED
      )
    );

    let nextOk = false;
    let wildcardOk = false;
    if (closest) {
      const nextCloser = nextCloserName(name, closest.name);
      const covered = coverNsec3(nsec3, nextCloser);
      nextOk = Boolean(covered);
      steps.push(
        step(
          'Next closer',
          covered
            ? `${nextCloser} is covered by an NSEC3 range, so it does not exist.`
            : `No NSEC3 record covers ${nextCloser}.`,
          covered ? VERIFIED : FAILED
        )
      );

      const wildcard = `*.${closest.name}`;
      const wildcardCovered = coverNsec3(nsec3, wildcard);
      const wildcardMatched = matchNsec3(nsec3, wildcard);
      wildcardOk = Boolean(wildcardCovered) && !wildcardMatched;
      steps.push(
        step(
          'Wildcard',
          wildcardOk
            ? `${wildcard} is covered by an NSEC3 range, so no wildcard could have answered.`
            : `${wildcard} is not proven absent.`,
          wildcardOk ? VERIFIED : FAILED
        )
      );
    }

    const ok = Boolean(closest) && nextOk && wildcardOk;
    return {
      type: PROOF_TYPES.NSEC3,
      purpose: PROOF_PURPOSES.NXDOMAIN,
      status: ok ? PROOF_STATUSES.VERIFIED : PROOF_STATUSES.INCOMPLETE,
      result: ok ? VERIFIED : FAILED,
      qname: name,
      records: nsec3.map(e => presentRecord(e.record)),
      steps,
      optOut: params.optOut,
      nsec3Params: params,
      reason: ok ? undefined : 'The NXDOMAIN response is not fully proven.',
    };
  }

  const nsec = collectNsec(records);
  if (nsec.length === 0) {
    return emptyProof(
      PROOF_TYPES.NSEC,
      PROOF_PURPOSES.NXDOMAIN,
      name,
      'The zone returned NXDOMAIN with no NSEC or NSEC3 records.'
    );
  }

  const covering = nsec.find(e => nsecCovers(e.owner, e.next, name));
  // the wildcard that could have synthesised an answer must be proven absent too: the one at
  // the closest encloser, which may be an empty non-terminal only the next name reveals
  const wildcardSource = covering ? closestEncloserOf(name, covering) : name;
  const wildcard = `*.${wildcardSource}`;
  const wildcardCovered = nsec.find(
    e => e.owner === wildcard || nsecCovers(e.owner, e.next, wildcard)
  );
  const wildcardOk = Boolean(wildcardCovered) && wildcardCovered!.owner !== wildcard;
  const ok = Boolean(covering) && wildcardOk;

  return {
    type: PROOF_TYPES.NSEC,
    purpose: PROOF_PURPOSES.NXDOMAIN,
    status: ok ? PROOF_STATUSES.VERIFIED : PROOF_STATUSES.INCOMPLETE,
    result: ok ? VERIFIED : FAILED,
    qname: name,
    records: nsec.map(e => presentRecord(e.record)),
    steps: [
      step(
        'Covering NSEC',
        covering
          ? `${name} falls between ${covering.owner} and ${covering.next}.`
          : `No NSEC record covers ${name}.`,
        covering ? VERIFIED : FAILED
      ),
      step(
        'Wildcard',
        wildcardOk
          ? `${wildcard} is proven absent, so no wildcard could have answered.`
          : `${wildcard} is not proven absent.`,
        wildcardOk ? VERIFIED : FAILED
      ),
    ],
    optOut: false,
    reason: ok ? undefined : 'The NXDOMAIN response is not fully proven.',
  };
}

// RFC 4035 §5.3.4 and RFC 5155 §8.8: a positive answer synthesised from a wildcard is valid only
// if the queried name has no exact match of its own, and the wildcard that answered is the one at
// the queried name's closest encloser. Otherwise a wildcard RRset could be replayed for a name that
// really holds different records, should not exist, or sits under a nearer wildcard. `wildcard` is
// the owner that was signed, `*.<source of synthesis>`, rebuilt from the RRSIG's labels field; the
// signature binds it, so it is the closest encloser the proof has to agree with
export function verifyWildcardProof(
  qname: string,
  records: WireRecord[],
  wildcard: string
): DenialProof {
  const name = canonicalName(qname);
  const signed = canonicalName(wildcard);
  const source = parentName(signed);
  // the wildcard must sit above the queried name, and be a wildcard at all
  const above = splitName(signed)[0] === '*' && name !== source && isInZone(name, source);
  const nsec3 = collectNsec3(records);

  if (nsec3.length > 0) {
    const params = assessNsec3Params(
      nsec3[0].hashAlgorithm,
      nsec3[0].iterations,
      nsec3[0].salt,
      nsec3.some(e => e.optOut)
    );
    // the RRSIG's labels give the closest encloser, so the server sends no NSEC3 matching it
    // (RFC 5155 §7.2.5); what has to be shown is that the next closer name does not exist
    const steps: ProofStep[] = [
      step(
        'Closest encloser',
        above
          ? `The answer came from ${signed}, so ${source} is the closest encloser.`
          : `The answer came from ${signed}, which cannot answer for ${name}.`,
        above ? VERIFIED : FAILED
      ),
    ];
    let nextOk = false;
    if (above) {
      const nextCloser = nextCloserName(name, source);
      const covered = coverNsec3(nsec3, nextCloser);
      nextOk = Boolean(covered);
      steps.push(
        step(
          'Next closer',
          covered
            ? `${nextCloser} is covered by an NSEC3 range, so the queried name has no exact match.`
            : `No NSEC3 record covers ${nextCloser}.`,
          covered ? VERIFIED : FAILED
        )
      );
    }
    const ok = above && nextOk;
    return {
      type: PROOF_TYPES.NSEC3,
      purpose: PROOF_PURPOSES.WILDCARD,
      status: ok ? PROOF_STATUSES.VERIFIED : PROOF_STATUSES.INCOMPLETE,
      result: ok ? VERIFIED : FAILED,
      qname: name,
      records: nsec3.map(e => presentRecord(e.record)),
      steps,
      optOut: params.optOut,
      nsec3Params: params,
      reason: ok
        ? undefined
        : 'The wildcard-expanded answer is not proven: the queried name is not shown to be absent below the wildcard that answered.',
    };
  }

  const nsec = collectNsec(records);
  if (nsec.length === 0) {
    return emptyProof(
      PROOF_TYPES.NSEC,
      PROOF_PURPOSES.WILDCARD,
      name,
      'The wildcard-expanded answer came with no NSEC or NSEC3 proof that the queried name is absent.'
    );
  }
  const covering = nsec.find(e => nsecCovers(e.owner, e.next, name) && e.owner !== name);
  const encloser = covering ? closestEncloserOf(name, covering) : undefined;
  const fromEncloser =
    encloser !== undefined && above && countLabels(encloser) === countLabels(source);
  const ok = Boolean(covering) && fromEncloser;
  return {
    type: PROOF_TYPES.NSEC,
    purpose: PROOF_PURPOSES.WILDCARD,
    status: ok ? PROOF_STATUSES.VERIFIED : PROOF_STATUSES.INCOMPLETE,
    result: ok ? VERIFIED : FAILED,
    qname: name,
    records: nsec.map(e => presentRecord(e.record)),
    steps: [
      step(
        'Covering NSEC',
        covering
          ? `${name} falls between ${covering.owner} and ${covering.next}, so it has no exact match.`
          : `No NSEC record proves ${name} is absent.`,
        covering ? VERIFIED : FAILED
      ),
      ...(encloser === undefined
        ? []
        : [
            step(
              'Wildcard',
              fromEncloser
                ? `The answer came from ${signed}, the wildcard at the closest encloser ${encloser}.`
                : `The closest encloser of ${name} is ${encloser}, so only *.${encloser === '.' ? '' : encloser} could answer, not ${signed}.`,
              fromEncloser ? VERIFIED : FAILED
            ),
          ]),
    ],
    optOut: false,
    reason: ok
      ? undefined
      : 'The wildcard-expanded answer is not proven: the queried name is not shown to be absent below the wildcard that answered.',
  };
}

// the closest encloser of a name an NSEC covers: the deeper of the suffixes it shares with the
// NSEC's owner and with its next name. Both of those exist, and nothing between them does
function closestEncloserOf(name: string, covering: { owner: string; next: string }): string {
  const byOwner = longestCommonSuffix(name, covering.owner);
  const byNext = longestCommonSuffix(name, covering.next);
  return countLabels(byNext) > countLabels(byOwner) ? byNext : byOwner;
}

// the deepest name that is a suffix of both — the closest encloser in the NSEC case. Labels
// are split on unescaped dots only and compared as octets, however they were escaped
function longestCommonSuffix(a: string, b: string): string {
  const al = splitName(canonicalName(a));
  const bl = splitName(canonicalName(b));
  const shared: string[] = [];
  let i = al.length - 1;
  let j = bl.length - 1;
  while (i >= 0 && j >= 0 && sameLabel(al[i], bl[j])) {
    shared.unshift(al[i]);
    i -= 1;
    j -= 1;
  }
  return shared.length ? shared.join('.') : '.';
}

function sameLabel(a: string, b: string): boolean {
  try {
    return compareNames(a, b) === 0;
  } catch {
    return a === b;
  }
}
