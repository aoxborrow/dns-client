import type { ErrorData } from '../errors';
import type { ExchangeOptions, ExchangeResult } from '../exchange';
import { rcodeName } from '../protocol/header';
import { decodeRecords } from '../records/decode';
import { extendedErrors } from '../records/edns';
import type { ExtendedErrorOption } from '../records/edns';
import type { DnsRecord } from '../records/types';
import type { TransportName } from '../transports/types';
import type { HeaderFlags, Message, ResourceRecord } from '../wire/message';
import { canonicalName } from '../wire/names';

// the answer both resolvers return: what the server said, typed and raw

export interface Answer<Rec extends DnsRecord = DnsRecord> {
  // the question, as it was asked
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

  // who answered, and how
  server: string;
  // the server's name, where the resolver knows it
  serverName?: string;
  port: number;
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

  // the `dig` command that asks the answering server the same question
  toDig(): string;
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
// CNAMEs the section holds
export function aliasTarget(name: string, answers: readonly DnsRecord[]): string {
  let current = canonicalName(name);
  // a chain cannot be longer than the section, which also stops a loop
  for (let step = 0; step <= answers.length; step++) {
    const alias = answers.find(
      record => record.type === 'CNAME' && canonicalName(record.name) === current
    );
    if (!alias || alias.type !== 'CNAME') break;
    current = canonicalName(alias.target);
  }
  return current;
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
    records: matchingRecords(name, result.query.type, answers),
    answers,
    authorities: aged(decodeRecords(message.authorities, options)),
    additionals: aged(decodeRecords(message.additionals, options)),
    extendedErrors: extendedErrors(message.edns),
    message: copyMessage(message),
    bytes: result.bytes.slice(),
    server: result.server,
    ...(extras.serverName && { serverName: extras.serverName }),
    port: result.port,
    transport: result.transport,
    elapsed: extras.elapsed ?? result.elapsed,
    attempts: extras.attempts ?? result.attempts,
    timestamp: extras.timestamp ?? new Date(),
    cached: extras.cached ?? false,
    ...(extras.trace && { trace: extras.trace }),
    toDig: () => result.toDig(),
  };
}
