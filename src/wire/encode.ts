import { InvalidQueryError, ParseError } from '../errors';
import { classCode, RECORD_CLASSES } from '../protocol/classes';
import { DEFAULT_UDP_PAYLOAD_SIZE } from '../protocol/edns';
import { HEADER_FLAGS } from '../protocol/header';
import { RECORD_TYPES, typeCode } from '../protocol/types';
import { concatBytes, writeU16, writeU32 } from './bytes';
import type { Edns, EdnsOption, Message } from './message';
import { encodeName } from './names';

// encoding: queries for sending, and whole messages for building responses in tests.
// Names are always written in full, never compressed.

/** the EDNS record a query carries */
export interface QueryEdns {
  /** the largest UDP response the sender will accept. Default 1232 */
  udpPayloadSize?: number;
  /** set the DO bit: ask for DNSSEC records */
  dnssecOk?: boolean;
  options?: readonly EdnsOption[];
}

/** what `encodeQuery` takes: a question, its flags and its EDNS settings */
export interface Query {
  /** the message ID. The caller chooses it, so the codec stays deterministic */
  id: number;
  name: string;
  /** a mnemonic ('MX'), an RFC 3597 'TYPE65', or a number */
  type: string | number;
  /** default IN */
  class?: string | number;
  /** RD: ask the server to recurse */
  recursionDesired?: boolean;
  /** CD: ask a validating resolver to return data even if validation fails */
  checkingDisabled?: boolean;
  /** AD in a query: ask to be told whether the answer was authenticated */
  authenticData?: boolean;
  /** EDNS is on by default; pass false to send a plain RFC 1035 query */
  edns?: QueryEdns | false;
}

function header(id: number, flags: number, counts: readonly number[]): Uint8Array {
  const out = new Uint8Array(12);
  writeU16(out, 0, id);
  writeU16(out, 2, flags);
  counts.forEach((count, index) => writeU16(out, 4 + index * 2, count));
  return out;
}

function optRecord(edns: Edns, rcode: number): Uint8Array {
  const options = concatBytes(
    edns.options.flatMap(option => {
      const head = new Uint8Array(4);
      writeU16(head, 0, option.code);
      writeU16(head, 2, option.data.length);
      return [head, option.data];
    })
  );
  // root owner name, type, class (payload size), TTL (extended rcode, version, flags), length
  const fixed = new Uint8Array(11);
  writeU16(fixed, 1, RECORD_TYPES.OPT);
  writeU16(fixed, 3, edns.udpPayloadSize);
  fixed[5] = (rcode >>> 4) & 0xff;
  fixed[6] = edns.version;
  writeU16(fixed, 7, edns.dnssecOk ? 0x8000 : 0);
  writeU16(fixed, 9, options.length);
  return concatBytes([fixed, options]);
}

function question(name: string, type: number, cls: number): Uint8Array {
  const encoded = encodeName(name);
  const out = new Uint8Array(encoded.length + 4);
  out.set(encoded, 0);
  writeU16(out, encoded.length, type);
  writeU16(out, encoded.length + 2, cls);
  return out;
}

/** encode one question as a query message */
export function encodeQuery(query: Query): Uint8Array {
  if (!Number.isInteger(query.id) || query.id < 0 || query.id > 0xffff) {
    throw new InvalidQueryError(`Message ID out of range: ${query.id}`);
  }
  let encodedQuestion: Uint8Array;
  try {
    encodedQuestion = question(
      query.name,
      typeCode(query.type),
      classCode(query.class ?? RECORD_CLASSES.IN)
    );
  } catch (error) {
    // a name that cannot be written is a problem with the question, not with a response
    if (error instanceof ParseError) throw new InvalidQueryError(error.message, { cause: error });
    throw error;
  }

  const flags =
    (query.recursionDesired ? HEADER_FLAGS.RD : 0) |
    (query.checkingDisabled ? HEADER_FLAGS.CD : 0) |
    (query.authenticData ? HEADER_FLAGS.AD : 0);

  const parts = [header(query.id, flags, [1, 0, 0, query.edns === false ? 0 : 1]), encodedQuestion];
  if (query.edns !== false) {
    parts.push(
      optRecord(
        {
          udpPayloadSize: query.edns?.udpPayloadSize ?? DEFAULT_UDP_PAYLOAD_SIZE,
          version: 0,
          dnssecOk: query.edns?.dnssecOk ?? false,
          options: [...(query.edns?.options ?? [])],
        },
        0
      )
    );
  }
  return concatBytes(parts);
}

/** what `encodeMessage` needs: a decoded message, with the parts that have defaults optional */
export type EncodableMessage = Pick<Message, 'id'> &
  Partial<
    Pick<
      Message,
      'opcode' | 'rcode' | 'questions' | 'answers' | 'authorities' | 'additionals' | 'edns'
    >
  > & {
    flags?: Partial<Message['flags']>;
  };

/**
 * encode a whole message. This is the inverse of `decodeMessage`, used to build responses
 * for tests and fixtures; RDATA is written as given
 */
export function encodeMessage(message: EncodableMessage): Uint8Array {
  const rcode = message.rcode ?? 0;
  if (rcode > 0x0f && !message.edns) {
    throw new ParseError(`Response code ${rcode} needs EDNS to be encoded`);
  }
  const flags =
    (message.flags?.qr ? HEADER_FLAGS.QR : 0) |
    (((message.opcode ?? 0) & 0x0f) << 11) |
    (message.flags?.aa ? HEADER_FLAGS.AA : 0) |
    (message.flags?.tc ? HEADER_FLAGS.TC : 0) |
    (message.flags?.rd ? HEADER_FLAGS.RD : 0) |
    (message.flags?.ra ? HEADER_FLAGS.RA : 0) |
    (message.flags?.ad ? HEADER_FLAGS.AD : 0) |
    (message.flags?.cd ? HEADER_FLAGS.CD : 0) |
    (rcode & 0x0f);

  const questions = message.questions ?? [];
  const sections = [message.answers ?? [], message.authorities ?? [], message.additionals ?? []];

  const parts: Uint8Array[] = [
    header(message.id, flags, [
      questions.length,
      sections[0].length,
      sections[1].length,
      sections[2].length + (message.edns ? 1 : 0),
    ]),
    ...questions.map(q => question(q.name, q.type, q.class)),
  ];
  for (const section of sections) {
    for (const record of section) {
      const name = encodeName(record.name);
      const fixed = new Uint8Array(10);
      writeU16(fixed, 0, record.type);
      writeU16(fixed, 2, record.class);
      writeU32(fixed, 4, record.ttl);
      writeU16(fixed, 8, record.rdata.length);
      parts.push(name, fixed, record.rdata);
    }
  }
  if (message.edns) parts.push(optRecord(message.edns, rcode));
  return concatBytes(parts);
}
