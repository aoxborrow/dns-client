import type { ErrorData } from '../errors';
import type { ExchangeOptions, ExchangeResult, SentQuery } from '../exchange';
import { rcodeName } from '../protocol/header';
import { decodeRecords } from '../records/decode';
import { extendedErrors } from '../records/edns';
import type { ExtendedErrorOption } from '../records/edns';
import type { DnsRecord } from '../records/types';
import type { TransportName } from '../transports/types';
import type { HeaderFlags, Message, ResourceRecord } from '../wire/message';
import { canonicalName, comparableName, encodeName, isSubdomain, splitName } from '../wire/names';

// the answer both resolvers return: what the server said, typed and raw. Plain data, with
// no methods: it can be copied, stored and sent as it is (`toDig(answer)` gives the `dig`
// command for it)

export interface Answer<Rec extends DnsRecord = DnsRecord> {
  // the question, as it was asked, with no trailing dot
  name: string;
  type: string;
  class: string;

  rcode: number;
  rcodeName: string;
  // the response's header flags
  flags: HeaderFlags;

  // the records that answer the question: those of the type asked for, at the name asked
  // about or at the end of the alias chain it leads to. Empty for NXDOMAIN and for a name
  // with no records of that type; `rcodeName` tells the two apart
  records: Rec[];
  // every record in each section of the response, typed. `answers` holds the aliases a
  // name went through and, when DNSSEC records were asked for, the signatures
  answers: DnsRecord[];
  authorities: DnsRecord[];
  additionals: DnsRecord[];
  extendedErrors: ExtendedErrorOption[];

  // the response as decoded from the wire, record data as bytes, and exactly as it arrived
  message: Message;
  bytes: Uint8Array;
  // the query the server answered, as it was sent. After an alias was followed its name
  // is the alias's target, not the name first asked about
  query: SentQuery;

  // who answered, and how
  server: string;
  // the server's name, where the resolver knows it
  serverName?: string;
  port: number;
  // DoH: the URL the query went to
  url?: string;
  transport: TransportName;
  // milliseconds from asking to having the answer, all servers and attempts included
  elapsed: number;
  // how many times a query was sent to get it
  attempts: number;
  // when the response arrived
  timestamp: Date;
  // served from the resolver's cache: the record TTLs are what is left of them
  cached: boolean;

  // every server asked on the way from the root. AuthoritativeResolver only
  trace?: TraceHop[];
}

// one step of a resolution from the root
export interface TraceHop {
  server: string;
  serverName?: string;
  // the zone this server was asked as an authority for
  zone: string;
  // what it was asked, which changes when an alias is followed
  name: string;
  type: string;
  transport?: TransportName;
  rcode?: number;
  rcodeName?: string;
  // the zone it referred the question on to, when it did
  referral?: string;
  bytes?: number;
  elapsed: number;
  timestamp: Date;
  // why this server gave nothing usable, when it did not
  error?: ErrorData;
}

// the flags and EDNS settings of a query, which both resolvers take for every query and
// for a single one
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
  const options = { lenient: !extras.strict };
  const aged = (records: DnsRecord[]) => {
    if (!extras.age) return records;
    for (const record of records) record.ttl = Math.max(0, record.ttl - (extras.age ?? 0));
    return records;
  };
  const answers = [...(extras.before ?? []), ...aged(decodeRecords(message.answers, options))];
  const name = extras.name ?? result.query.name;

  return {
    name,
    type: result.query.type,
    class: result.query.class,
    rcode: message.rcode,
    rcodeName: rcodeName(message.rcode),
    flags: { ...message.flags },
    records: matchingRecords(comparableName(name), result.query.type, answers),
    answers,
    authorities: aged(decodeRecords(message.authorities, options)),
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
    ...(extras.trace && { trace: extras.trace }),
  };
}
