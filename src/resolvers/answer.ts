import type { Security } from '../dnssec/validate';
import type { ErrorData } from '../errors';
import type { ExchangeOptions, ExchangeResult, SentQuery } from '../exchange';
import { RCODES, rcodeName } from '../protocol/header';
import type { RcodeName } from '../protocol/header';
import { decodeRecords } from '../records/decode';
import { extendedErrors } from '../records/edns';
import type { ExtendedErrorOption } from '../records/edns';
import type { DnsRecord, SoaRecord } from '../records/types';
import type { TransportName } from '../transports/types';
import type { HeaderFlags, Message, ResourceRecord } from '../wire/message';
import { canonicalName, comparableName, encodeName, isSubdomain, splitName } from '../wire/names';

/**
 * what an answer amounts to:
 * - `ok`: `records` holds what was asked for
 * - `nxdomain`: the name does not exist, or the name at the end of its alias chain does not
 * - `nodata`: the name exists, with nothing of the type asked for
 * - `referral`: the server sent the question on to another zone's servers instead of answering
 * - `alias`: the name is an alias, and its target's records are not here because it was not
 *   followed
 * - `failed`: the servers gave up on the question (SERVFAIL, REFUSED and the like), an empty
 *   answer came truncated and asking again over TCP did not help, or every server of a zone
 *   answered without authority or the zone's SOA, NXDOMAIN included (AuthoritativeResolver)
 */
export type AnswerStatus = 'ok' | 'nxdomain' | 'nodata' | 'referral' | 'alias' | 'failed';

/**
 * the answer both resolvers return: what the server said, typed and raw. Plain data, with no
 * methods: it can be copied, stored and sent as it is (`toDig(answer)` gives the `dig` command for
 * it)
 */
export interface Answer<Rec extends DnsRecord = DnsRecord> {
  /** the question, as it was asked, with no trailing dot */
  name: string;
  type: string;
  class: string;

  rcode: number;
  rcodeName: RcodeName | `RCODE${number}`;
  /** the response's header flags */
  flags: HeaderFlags;
  /** what the answer amounts to, read from the rcode and the sections: see {@link AnswerStatus} */
  status: AnswerStatus;
  /**
   * `nxdomain` and `nodata` only: how many seconds the negative answer may be kept. The
   * smaller of the SOA's TTL and its `minimum` field (RFC 2308 §5), and of the TTL of any alias
   * that led to it; 0 when no SOA for the name came with it, or the answer is truncated. From
   * the cache, what is left of it
   */
  negativeTtl?: number;

  /**
   * the records that answer the question: those of the type asked for, at the name asked
   * about or at the end of the alias chain it leads to. Read them when `status` is `ok`: with
   * another status they are usually empty, but an error response may still carry some. From
   * AuthoritativeResolver, only records the answering zone holds authority for: an
   * alias out of the zone ends `records` there, unless `followCnames` resolves its target
   */
  records: Rec[];
  /**
   * every record in each section of the response, typed, as the server sent it and not
   * vetted: a zone's server can put anything here, records about other zones included.
   * `answers` holds the aliases a name went through and, when DNSSEC records were asked
   * for, the signatures
   */
  answers: DnsRecord[];
  authorities: DnsRecord[];
  additionals: DnsRecord[];
  extendedErrors: ExtendedErrorOption[];

  /** the response as decoded from the wire, record data as bytes, and exactly as it arrived */
  message: Message;
  bytes: Uint8Array;
  /**
   * the query the server answered, as it was sent. After an alias was followed its name
   * is the alias's target, not the name first asked about
   */
  query: SentQuery;

  /** who answered, and how */
  server: string;
  /** the server's name, where the resolver knows it */
  serverName?: string;
  port: number;
  /** DoH: the URL the query went to */
  url?: string;
  transport: TransportName;
  /** milliseconds from asking to having the answer, all servers and attempts included */
  elapsed: number;
  /** how many times a query was sent to get it */
  attempts: number;
  /** when the response arrived */
  timestamp: Date;
  /** served from the resolver's cache: the record TTLs are what is left of them */
  cached: boolean;
  /**
   * the answer is a truncated UDP one (`flags.tc`), with whatever records it carried,
   * because asking again over TCP failed: why it did
   */
  tcpFallbackError?: ErrorData;

  /** every server asked on the way from the root. AuthoritativeResolver only */
  trace?: TraceHop[];

  /**
   * what DNSSEC validation made of the answer, when the resolver was asked to validate:
   * secure, insecure, bogus or indeterminate, why, and the chain it judged
   */
  security?: Security;
}

/** one step of a resolution from the root */
export interface TraceHop {
  server: string;
  serverName?: string;
  /** the zone this server was asked as an authority for */
  zone: string;
  /** what it was asked, which changes when an alias is followed */
  name: string;
  type: string;
  transport?: TransportName;
  rcode?: number;
  rcodeName?: RcodeName | `RCODE${number}`;
  /** the zone it referred the question on to, when it did */
  referral?: string;
  bytes?: number;
  elapsed: number;
  timestamp: Date;
  /** why this server gave nothing usable, when it did not */
  error?: ErrorData;
  /**
   * its answer was truncated over UDP and asking again over TCP failed: why. The
   * truncated answer is what the walk went on with, when it could
   */
  tcpFallbackError?: ErrorData;
}

/**
 * the flags and EDNS settings of a query, which both resolvers take for every query and
 * for a single one
 */
export type QuerySettings = Pick<
  ExchangeOptions,
  | 'transport'
  | 'port'
  | 'recursionDesired'
  | 'checkingDisabled'
  | 'authenticData'
  | 'dnssecOk'
  | 'udpPayloadSize'
  | 'ednsOptions'
  | 'edns'
  | 'timeout'
  | 'retries'
  | 'tcpFallback'
>;

const ALIASES = new Set(['CNAME', 'DNAME']);

// the name the answer section ends at: the question's name, followed through whatever
// CNAMEs and DNAMEs the section holds. A CNAME at the name wins, since a server that
// follows RFC 6672 sends the CNAME it synthesized from a DNAME beside it; a DNAME alone
// above the name rewrites the name's suffix (RFC 6672 §2.2)
export function aliasTarget(name: string, answers: readonly DnsRecord[]): string {
  let current = canonicalName(name);
  // a chain cannot be longer than the section, which also stops a loop
  for (let step = 0; step <= answers.length; step++) {
    const next = aliasStep(current, answers);
    if (next === undefined) break;
    current = next;
  }
  return current;
}

// where one alias in the section takes a name, or undefined when none applies
function aliasStep(current: string, answers: readonly DnsRecord[]): string | undefined {
  for (const record of answers) {
    if (record.type === 'CNAME' && canonicalName(record.name) === current) {
      return canonicalName(record.target);
    }
  }
  for (const record of answers) {
    if (record.type !== 'DNAME') continue;
    const owner = canonicalName(record.name);
    // a DNAME redirects the names below its owner, not the owner itself
    if (owner === current || !isSubdomain(current, owner)) continue;
    const labels = splitName(current);
    const prefix = labels.slice(0, labels.length - splitName(owner).length);
    const substituted = canonicalName([...prefix, ...splitName(record.target)].join('.'));
    try {
      // a substitution too long to be a name is YXDOMAIN, not a name to ask about
      encodeName(substituted);
    } catch {
      return undefined;
    }
    return substituted;
  }
  return undefined;
}

// pick out the records that answer the question
export function matchingRecords(
  name: string,
  type: string,
  answers: readonly DnsRecord[]
): DnsRecord[] {
  if (type === 'ANY') return [...answers];
  const owner = ALIASES.has(type) ? canonicalName(name) : aliasTarget(name, answers);
  return answers.filter(record => record.type === type && canonicalName(record.name) === owner);
}

// how long a negative answer may be kept, in seconds: the smaller of the TTL and the minimum
// field of an SOA that speaks for `end` (RFC 2308 §5), and no longer than an alias that led to
// it. Only an SOA at or above the name, and at or below the zone that was asked when one was,
// speaks for it; undefined when none does. `age` is how long the response sat in a cache,
// already taken off the record TTLs
export function negativeLifetime(
  end: string,
  answers: readonly DnsRecord[],
  authorities: readonly DnsRecord[],
  zone?: string,
  age = 0
): number | undefined {
  const soa = authorities.find(
    (record): record is SoaRecord =>
      record.type === 'SOA' &&
      isSubdomain(end, record.name) &&
      (zone === undefined || isSubdomain(record.name, zone))
  );
  if (!soa) return undefined;
  return Math.max(0, Math.min(soa.ttl, soa.minimum - age, ...answers.map(record => record.ttl)));
}

export interface AnswerExtras {
  // seconds to take off every TTL: how long the response sat in a cache
  age?: number;
  cached?: boolean;
  // malformed record data is an error, not an UnknownRecord
  strict?: boolean;
  serverName?: string;
  trace?: TraceHop[];
  timestamp?: Date;
  elapsed?: number;
  attempts?: number;
  // the name first asked about, when an alias was followed to another
  name?: string;
  // records from earlier responses to put before this one's answers: the aliases followed
  before?: DnsRecord[];
  // the zone the answering server was asked as an authority for: `records` holds only
  // what is at or below it, and what came before
  zone?: string;
}

const copyRecord = (record: ResourceRecord): ResourceRecord => ({
  ...record,
  rdata: record.rdata.slice(),
});

// a copy of a message that shares nothing with it, down to the bytes
function copyMessage(message: Message): Message {
  return {
    ...message,
    flags: { ...message.flags },
    questions: message.questions.map(question => ({ ...question })),
    answers: message.answers.map(copyRecord),
    authorities: message.authorities.map(copyRecord),
    additionals: message.additionals.map(copyRecord),
    ...(message.edns && {
      edns: {
        ...message.edns,
        options: message.edns.options.map(option => ({ ...option, data: option.data.slice() })),
      },
    }),
  };
}

// build an answer from a response. Decoding is done here, every time, and the raw
// response is copied, so no two answers share an object and nothing a caller does to one
// reaches another, or the cache
export function buildAnswer(result: ExchangeResult, extras: AnswerExtras = {}): Answer {
  const { message } = result;
  const options = { strict: extras.strict };
  const aged = (records: DnsRecord[]) => {
    if (!extras.age) return records;
    for (const record of records) record.ttl = Math.max(0, record.ttl - (extras.age ?? 0));
    return records;
  };
  const own = aged(decodeRecords(message.answers, options));
  const answers = [...(extras.before ?? []), ...own];
  const { zone } = extras;
  const vouched = zone
    ? [...(extras.before ?? []), ...own.filter(record => isSubdomain(record.name, zone))]
    : answers;
  const name = extras.name ?? result.query.name;
  const { type } = result.query;
  const asked = comparableName(name);
  const records = matchingRecords(asked, type, vouched);
  const authorities = aged(decodeRecords(message.authorities, options));

  // the name the answer ends at, and whether an SOA speaks for it there. An alias chain whose
  // end was not asked about was not followed, and no SOA for its end means its records are
  // simply not here. With one, the end exists with nothing of the type (RFC 2308 §2.2). An
  // empty truncated answer cannot tell that from records lost to the truncation
  const end = type === 'ANY' || ALIASES.has(type) ? asked : aliasTarget(asked, vouched);
  const lifetime = negativeLifetime(end, answers, authorities, zone, extras.age);
  const { tc, aa } = message.flags;
  // from a zone's server, a denial needs authority or the zone's SOA behind it, as the walk
  // requires: without either it is lame, returned only when every server was the same
  const unvouched =
    zone !== undefined &&
    !aa &&
    !authorities.some(record => record.type === 'SOA' && isSubdomain(record.name, zone));
  let status: AnswerStatus;
  if (message.rcode === RCODES.NXDOMAIN) status = unvouched ? 'failed' : 'nxdomain';
  else if (message.rcode !== RCODES.NOERROR) status = 'failed';
  else if (records.length > 0) status = 'ok';
  else if (tc) status = 'failed';
  else if (lifetime !== undefined) status = 'nodata';
  else if (end !== comparableName(result.query.name)) status = 'alias';
  else if (!aa && authorities.some(record => record.type === 'NS')) status = 'referral';
  // nothing at all, from a zone's server that does not claim authority: it is not serving
  // the zone
  else if (zone !== undefined && !aa) status = 'failed';
  else status = 'nodata';

  return {
    name,
    type: result.query.type,
    class: result.query.class,
    rcode: message.rcode,
    rcodeName: rcodeName(message.rcode),
    flags: { ...message.flags },
    status,
    ...((status === 'nxdomain' || status === 'nodata') && {
      negativeTtl: tc ? 0 : (lifetime ?? 0),
    }),
    records,
    answers,
    authorities,
    additionals: aged(decodeRecords(message.additionals, options)),
    extendedErrors: extendedErrors(message.edns),
    message: copyMessage(message),
    bytes: result.bytes.slice(),
    query: {
      name: result.query.name,
      type: result.query.type,
      class: result.query.class,
      flags: { ...result.query.flags },
      edns: result.query.edns && { ...result.query.edns },
    },
    server: result.server,
    ...(extras.serverName && { serverName: extras.serverName }),
    port: result.port,
    ...(result.url && { url: result.url }),
    transport: result.transport,
    elapsed: extras.elapsed ?? result.elapsed,
    attempts: extras.attempts ?? result.attempts,
    timestamp: extras.timestamp ?? new Date(),
    cached: extras.cached ?? false,
    ...(result.tcpFallbackError && { tcpFallbackError: { ...result.tcpFallbackError } }),
    ...(extras.trace && { trace: extras.trace }),
  };
}
