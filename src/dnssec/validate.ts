import { RECORD_TYPES } from '../protocol/types';
import { RCODES } from '../protocol/header';
import type { Message, ResourceRecord } from '../wire/message';
import {
  canonicalName,
  isSubdomain,
  labelsToName,
  parentName,
  readName,
  splitName,
} from '../wire/names';
import { ROOT_TRUST_ANCHORS } from './anchors';
import { readRrsig } from './checks';
import { judgeChain } from './judge';
import type { ChainLink, ChainName, DnssecResponse, ZoneFact } from './judge';
import { denialTypesAt } from './nsec';
import type { SecurityReason, SecurityStatus } from './reasons';
import type { TrustAnchor } from './types';

// validation as the resolvers do it: work out which zones an answer's data lives in, fetch
// each one's DS and DNSKEY records (with DO and CD set, so an upstream validator cannot
// hide what is broken), and hand it all to the judging core. What the core establishes
// about each zone is kept for as long as the TTLs and signatures it rests on allow

// validation asks for signatures with the DO bit, which only a query with EDNS carries.
// Without it none come back, and every signed answer would be judged bogus: so a
// validating resolver refuses `edns: false`, for itself or for one query
export function requireEdns(edns: boolean | undefined): void {
  if (edns === false) {
    throw new TypeError(
      'DNSSEC validation needs EDNS: signatures are asked for with the DO bit, which a ' +
        'query sent with `edns: false` cannot carry'
    );
  }
}

/** what a validated answer carries */
export interface Security {
  status: SecurityStatus;
  reason: SecurityReason;
  /** every link judged: each zone's key set from the trust anchor down, then the data */
  chain: ChainLink[];
  /** the first link that is bogus or indeterminate, when the outcome is either */
  failure?: ChainLink;
}

// ask one question with DNSSEC records and Checking Disabled, and hand back the response
// as it came. Undefined when no response arrived
export type ValidationFetch = (name: string, type: number) => Promise<Message | undefined>;

export interface ValidatorOptions {
  // default: IANA's root trust anchors
  trustAnchors?: readonly TrustAnchor[];
  // the longest a zone's validated key set is kept, in seconds, whatever its TTL says.
  // Default one day
  maxTtl?: number;
  // the most zones kept. Default 1000
  maxZones?: number;
}

const DEFAULT_MAX_TTL = 86_400;
const DEFAULT_MAX_ZONES = 1000;
const { DS, DNSKEY, RRSIG, NSEC, NSEC3, NS, CNAME, DNAME } = RECORD_TYPES;

// a response, as the judging core reads it, for the question that was sent
export function dnssecResponse(message: Message, name: string, type: number): DnssecResponse {
  return {
    name,
    type,
    rcode: message.rcode,
    answers: message.answers,
    authorities: message.authorities,
    ...(message.flags.tc && { truncated: true }),
  };
}

export class Validator {
  private readonly anchors: readonly TrustAnchor[];
  private readonly maxTtl: number;
  private readonly maxZones: number;
  // what is known about each name, by canonical name, until when (milliseconds)
  private readonly facts = new Map<string, { fact: ZoneFact; expires: number }>();

  constructor(options: ValidatorOptions = {}) {
    this.anchors = options.trustAnchors ?? ROOT_TRUST_ANCHORS;
    this.maxTtl = options.maxTtl ?? DEFAULT_MAX_TTL;
    this.maxZones = options.maxZones ?? DEFAULT_MAX_ZONES;
  }

  // forget every zone judged so far
  clear(): void {
    this.facts.clear();
  }

  // judge the data in `responses`, fetching whatever chain it needs. A fetch that fails
  // leaves its link indeterminate, unless `signal` has been aborted: then the failure is
  // the caller's, and validation rejects with it
  async validate(
    responses: DnssecResponse[],
    fetch: ValidationFetch,
    signal?: AbortSignal
  ): Promise<Security> {
    const now = new Date();
    const anchorZone = canonicalName(this.anchors[0]?.zone ?? '.');
    const known: ZoneFact[] = [];
    const knownNames = new Set<string>();
    const remember = (name: string) => {
      const entry = this.facts.get(name);
      if (!entry) return undefined;
      if (entry.expires <= now.getTime()) {
        this.facts.delete(name);
        return undefined;
      }
      if (!knownNames.has(name)) {
        knownNames.add(name);
        known.push(entry.fact);
      }
      return entry.fact;
    };

    const ask = async (name: string, type: number): Promise<DnssecResponse | undefined> => {
      const message = await fetch(name, type).catch((error: unknown) => {
        if (signal?.aborted) throw error;
        return undefined;
      });
      // a truncated response is not the chain's records, only some of them: it is missing
      return message && !message.flags.tc ? dnssecResponse(message, name, type) : undefined;
    };

    // the anchored zone's key set
    const anchored = remember(anchorZone) ? undefined : await ask(anchorZone, DNSKEY);

    // every name the data sits at, and each name between it and the trust anchor
    const names = new Map<string, ChainName>();
    const stopped = new Set<string>();
    for (const target of dataNames(responses)) {
      if (!isSubdomain(target, anchorZone)) continue;
      const labels = splitName(target);
      const depth = splitName(anchorZone).length;
      for (let index = labels.length - depth - 1; index >= 0; index--) {
        const name = canonicalName(labels.slice(index).join('.'));
        if (stopped.has(parentName(name)) || stopped.has(name)) {
          stopped.add(name);
          continue;
        }
        const fact = remember(name);
        if (fact) {
          if (fact.cut && fact.status !== 'secure') stopped.add(name);
          continue;
        }
        if (names.has(name)) continue;
        const ds = await ask(name, DS);
        const entry: ChainName = { name, ...(ds && { ds }) };
        names.set(name, entry);
        if (!ds) {
          stopped.add(name);
          continue;
        }
        if (hasDs(ds, name)) {
          const dnskey = await ask(name, DNSKEY);
          if (dnskey) entry.dnskey = dnskey;
        } else if (endsTheChain(ds, name)) {
          // no DS, and what came back says this is where signing stops: there is nothing
          // below to fetch. The core judges whether that is proven
          stopped.add(name);
        }
      }
    }

    const judgement = await judgeChain(
      { ...(anchored && { anchored }), names: [...names.values()], responses, known },
      { trustAnchors: this.anchors, now, mode: 'first' }
    );

    for (const fact of judgement.facts) {
      const ttl = Math.min(fact.ttl, this.maxTtl);
      if (ttl <= 0) continue;
      this.facts.delete(canonicalName(fact.name));
      this.facts.set(canonicalName(fact.name), { fact, expires: now.getTime() + ttl * 1000 });
    }
    // the least recently learned go first
    while (this.facts.size > this.maxZones) {
      this.facts.delete(this.facts.keys().next().value!);
    }

    return {
      status: judgement.status,
      reason: judgement.reason,
      chain: judgement.links,
      ...(judgement.failure && { failure: judgement.failure }),
    };
  }
}

// the names the data in the responses sits at: each answer RRset's owner, the name asked
// about, and where its aliases lead. A signature's signer is a zone the chain must reach
function dataNames(responses: DnssecResponse[]): string[] {
  const names = new Set<string>();
  for (const response of responses) {
    names.add(canonicalName(response.name));
    for (const record of response.answers) {
      if (record.type === RRSIG) {
        const sig = readRrsig(record);
        if (sig) names.add(canonicalName(sig.signerName));
        continue;
      }
      // a DS RRset is its parent's data
      names.add(canonicalName(record.type === DS ? parentName(record.name) : record.name));
      if (record.type === CNAME || record.type === DNAME) {
        const target = aliasTargetOf(record);
        if (target) names.add(target);
      }
    }
  }
  // parents first, so a zone above is fetched before those below it
  return [...names].sort((a, b) => splitName(a).length - splitName(b).length);
}

function aliasTargetOf(record: ResourceRecord): string | undefined {
  try {
    return canonicalName(labelsToName(readName(record.rdata, 0).labels));
  } catch {
    return undefined;
  }
}

function hasDs(response: DnssecResponse, name: string): boolean {
  const owner = canonicalName(name);
  return response.answers.some(
    record => record.type === DS && canonicalName(record.name) === owner
  );
}

// whether a response without a DS shows signing stops at the name: a delegation without
// DS, an opt-out range over it, or a zone above that is not signed at all
function endsTheChain(response: DnssecResponse, name: string): boolean {
  if (response.rcode !== RCODES.NOERROR && response.rcode !== RCODES.NXDOMAIN) return true;
  const denial = response.authorities.filter(
    record => record.type === NSEC || record.type === NSEC3
  );
  if (denial.length === 0) {
    // an alias is a name inside its zone; anything else unproven ends the chain here
    return !response.answers.some(record => record.type === CNAME);
  }
  const at = denialTypesAt(name, denial);
  return Boolean(at.types?.includes(NS)) || at.optOut;
}
