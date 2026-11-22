import { ParseError } from '../errors';
import { HEADER_FLAGS } from '../protocol/header';
import { RECORD_TYPES } from '../protocol/types';
import { concatBytes, readU16, readU32 } from './bytes';
import { labelsToName, readName } from './names';

// decoding a DNS message into its parts, keeping each record's RDATA as bytes. Nothing
// here interprets RDATA beyond what is needed to make it self-contained; the typed
// records are built from these bytes by the records layer.

/** the section of a message a record came in */
export type Section = 'answer' | 'authority' | 'additional';

/** a question: a name, a type code and a class code */
export interface Question {
  name: string;
  type: number;
  class: number;
}

/**
 * a record as it was on the wire: name, type and class codes, TTL, and its data as bytes.
 * `decodeRecord` in `/records` types it
 */
export interface ResourceRecord {
  /** owner name, in the case the server sent it */
  name: string;
  type: number;
  class: number;
  ttl: number;
  /**
   * the record's data. Names inside it are written out in full, so the bytes stand on
   * their own without the message they came from; nothing else is changed
   */
  rdata: Uint8Array;
  section: Section;
}

/** an EDNS option as it was on the wire: its code and bytes */
export interface EdnsOption {
  code: number;
  data: Uint8Array;
}

/** the EDNS(0) state carried by the OPT pseudo-record (RFC 6891) */
export interface Edns {
  /** the largest UDP payload the sender can receive */
  udpPayloadSize: number;
  version: number;
  /** the DO bit: the sender wants DNSSEC records */
  dnssecOk: boolean;
  options: EdnsOption[];
}

/** a message header's flags, as booleans */
export interface HeaderFlags {
  qr: boolean;
  aa: boolean;
  tc: boolean;
  rd: boolean;
  ra: boolean;
  ad: boolean;
  cd: boolean;
}

/**
 * a DNS message, decoded: header, flags, question, the three record sections and EDNS. Record data
 * stays as bytes
 */
export interface Message {
  id: number;
  opcode: number;
  /** the full response code: the header's four bits, extended by the OPT record's eight */
  rcode: number;
  flags: HeaderFlags;
  questions: Question[];
  answers: ResourceRecord[];
  authorities: ResourceRecord[];
  /** without the OPT pseudo-record, which is reported as `edns` */
  additionals: ResourceRecord[];
  edns?: Edns;
  /** the size of the message on the wire */
  bytes: number;
}

// the offset of a name that follows fields of varying length, found from the RDATA itself
type NameOffset = (rdata: Uint8Array) => number;

// NAPTR's replacement comes after order and preference and three character strings:
// flags, services and regexp (RFC 3403 §4.1)
const naptrReplacement: NameOffset = rdata => {
  let offset = 4;
  for (let i = 0; i < 3 && offset < rdata.length; i++) offset += 1 + rdata[offset];
  return offset;
};

// where domain names sit inside the RDATA of the types that may carry compressed names:
// the offset each name starts at, with -1 meaning "straight after the previous name".
// RFC 3597 forbids compression in any type defined later. These are the well-known types
// of RFC 1035, the ones RFC 3597 §4 says to decompress too (RP, AFSDB, RT, SIG, PX, NXT,
// NAPTR, SRV), and the handful that servers compress in practice
const NAMES_IN_RDATA: Record<number, readonly (number | NameOffset)[]> = {
  2: [0], // NS
  3: [0], // MD
  4: [0], // MF
  5: [0], // CNAME
  6: [0, -1], // SOA: mname, rname, then five integers
  7: [0], // MB
  8: [0], // MG
  9: [0], // MR
  12: [0], // PTR
  14: [0, -1], // MINFO
  15: [2], // MX: preference first
  17: [0, -1], // RP
  18: [2], // AFSDB
  21: [2], // RT
  24: [18], // SIG: signer name after the fixed fields
  26: [2, -1], // PX
  30: [0], // NXT
  33: [6], // SRV: priority, weight, port
  35: [naptrReplacement], // NAPTR: the replacement, after three character strings
  36: [2], // KX
  39: [0], // DNAME
  46: [18], // RRSIG: signer name after the fixed fields
  47: [0], // NSEC: next domain name
};

// a name written out in full, in the case it arrived in
function expandName(labels: readonly Uint8Array[]): Uint8Array {
  const parts: Uint8Array[] = [];
  for (const label of labels) parts.push(Uint8Array.of(label.length), label);
  parts.push(Uint8Array.of(0));
  return concatBytes(parts);
}

// RDATA with any compressed names inside it written out in full
function readRdata(message: Uint8Array, type: number, start: number, length: number): Uint8Array {
  const end = start + length;
  const layout = NAMES_IN_RDATA[type];
  if (!layout) return message.subarray(start, end);

  const chunks: Uint8Array[] = [];
  let position = start;
  for (const entry of layout) {
    const declared = typeof entry === 'function' ? entry(message.subarray(start, end)) : entry;
    if (declared >= 0) {
      const nameStart = start + declared;
      // RDATA too short to hold this name: leave what there is untouched
      if (nameStart >= end) break;
      if (nameStart > position) {
        chunks.push(message.subarray(position, nameStart));
        position = nameStart;
      }
    }
    if (position >= end) break;
    const name = readName(message, position);
    if (name.end > end) throw new ParseError('Name runs past the end of its record');
    chunks.push(expandName(name.labels));
    position = name.end;
  }
  // whatever follows the last name: SOA's integers, NSEC's type bitmap, a signature
  if (position < end) chunks.push(message.subarray(position, end));
  return concatBytes(chunks);
}

function readEdnsOptions(rdata: Uint8Array): EdnsOption[] {
  const options: EdnsOption[] = [];
  let position = 0;
  while (position + 4 <= rdata.length) {
    const code = readU16(rdata, position);
    const length = readU16(rdata, position + 2);
    if (position + 4 + length > rdata.length) throw new ParseError('Truncated EDNS option');
    options.push({ code, data: rdata.subarray(position + 4, position + 4 + length) });
    position += 4 + length;
  }
  return options;
}

/** decode a complete DNS message */
export function decodeMessage(bytes: Uint8Array): Message {
  if (bytes.length < 12) throw new ParseError('Message is shorter than a DNS header');

  const flags = readU16(bytes, 2);
  const counts = [readU16(bytes, 4), readU16(bytes, 6), readU16(bytes, 8), readU16(bytes, 10)];

  const message: Message = {
    id: readU16(bytes, 0),
    opcode: (flags >>> 11) & 0x0f,
    rcode: flags & 0x000f,
    flags: {
      qr: Boolean(flags & HEADER_FLAGS.QR),
      aa: Boolean(flags & HEADER_FLAGS.AA),
      tc: Boolean(flags & HEADER_FLAGS.TC),
      rd: Boolean(flags & HEADER_FLAGS.RD),
      ra: Boolean(flags & HEADER_FLAGS.RA),
      ad: Boolean(flags & HEADER_FLAGS.AD),
      cd: Boolean(flags & HEADER_FLAGS.CD),
    },
    questions: [],
    answers: [],
    authorities: [],
    additionals: [],
    bytes: bytes.length,
  };

  let offset = 12;

  for (let i = 0; i < counts[0]; i++) {
    const name = readName(bytes, offset);
    if (name.end + 4 > bytes.length) throw new ParseError('Truncated question');
    message.questions.push({
      name: labelsToName(name.labels),
      type: readU16(bytes, name.end),
      class: readU16(bytes, name.end + 2),
    });
    offset = name.end + 4;
  }

  const sections: [number, Section, ResourceRecord[]][] = [
    [counts[1], 'answer', message.answers],
    [counts[2], 'authority', message.authorities],
    [counts[3], 'additional', message.additionals],
  ];

  for (const [count, section, target] of sections) {
    for (let i = 0; i < count; i++) {
      const name = readName(bytes, offset);
      if (name.end + 10 > bytes.length) throw new ParseError('Truncated record header');
      const type = readU16(bytes, name.end);
      const cls = readU16(bytes, name.end + 2);
      const ttl = readU32(bytes, name.end + 4);
      const length = readU16(bytes, name.end + 8);
      const start = name.end + 10;
      if (start + length > bytes.length) throw new ParseError('Record data runs past the message');
      offset = start + length;

      // OPT is not zone data: its class and TTL fields carry the EDNS state
      if (type === RECORD_TYPES.OPT) {
        message.edns = {
          udpPayloadSize: cls,
          version: (ttl >>> 16) & 0xff,
          dnssecOk: Boolean(ttl & 0x8000),
          options: readEdnsOptions(bytes.subarray(start, start + length)),
        };
        // the upper eight bits of the response code live in the top byte of the TTL
        message.rcode |= ((ttl >>> 24) & 0xff) << 4;
        continue;
      }

      target.push({
        name: labelsToName(name.labels),
        type,
        class: cls,
        ttl,
        rdata: readRdata(bytes, type, start, length),
        section,
      });
    }
  }

  return message;
}
