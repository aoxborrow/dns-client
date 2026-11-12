import { typeName } from '../protocol/types';
import {
  compareBytes,
  concatBytes,
  readU16,
  readU32,
  toBase32Hex,
  toBase64,
  toHex,
  utf8Decode,
  writeU16,
  writeU32,
} from '../wire/bytes';
import type { Message, ResourceRecord } from '../wire/message';
import { endsWithRootDot, isSubdomain } from '../wire/names';
import { sha1, sha256, sha384 } from './hash';

// the DNSSEC view of a DNS message, and the RFC 4034 primitives built on it: key tag, DS
// digest, the bytes an RRSIG covers, NSEC3 hashing, type bitmaps.
//
// verification needs the exact bytes the signer signed. The library's decoder keeps each
// record's data as it arrived, with names inside it written out in full; what this adds
// is the canonical form of RFC 4034 §6.2 (those names downcased, for the types the RFC
// lists), which is what a signature is computed over

export function recordTypeName(type: number): string {
  return typeName(type);
}

export const TYPE_A = 1;
export const TYPE_NS = 2;
export const TYPE_CNAME = 5;
export const TYPE_SOA = 6;
export const TYPE_MX = 15;
export const TYPE_TXT = 16;
export const TYPE_AAAA = 28;
export const TYPE_DS = 43;
export const TYPE_RRSIG = 46;
export const TYPE_NSEC = 47;
export const TYPE_DNSKEY = 48;
export const TYPE_NSEC3 = 50;
export const TYPE_NSEC3PARAM = 51;
export const TYPE_CDS = 59;
export const TYPE_CDNSKEY = 60;
export const TYPE_OPT = 41;

// the offset of a name that follows fields of varying length, found from the RDATA itself
type NameOffset = (rdata: Uint8Array) => number;

// NAPTR's replacement comes after order and preference and three character strings:
// flags, services and regexp (RFC 3403 §4.1)
const naptrReplacement: NameOffset = rdata => {
  let offset = 4;
  for (let i = 0; i < 3 && offset < rdata.length; i++) offset += 1 + rdata[offset];
  return offset;
};

// A6's prefix name comes after the prefix length and the address suffix, whose length is
// what the prefix leaves of 128 bits (RFC 2874 §3.1.1). A prefix length of 0 has no name
const a6PrefixName: NameOffset = rdata =>
  rdata[0] === 0 ? rdata.length : 1 + Math.ceil((128 - rdata[0]) / 8);

// RDATA layouts that embed domain names, mapped to the byte offset each name starts at,
// with -1 meaning "straight after the previous name". The names to downcase for canonical
// form are found by walking these
const NAME_OFFSETS_IN_RDATA: Record<number, (number | NameOffset)[]> = {
  2: [0], // NS
  3: [0], // MD
  4: [0], // MF
  5: [0], // CNAME
  7: [0], // MB
  8: [0], // MG
  9: [0], // MR
  12: [0], // PTR
  39: [0], // DNAME
  17: [0, -1], // RP — two names back to back
  14: [0, -1], // MINFO — two names back to back
  6: [0, -1], // SOA — mname, rname, then fixed integers
  15: [2], // MX — 2-byte preference first
  21: [2], // RT
  18: [2], // AFSDB
  36: [2], // KX
  24: [18], // SIG — signer name after the fixed fields
  26: [2, -1], // PX — preference, then MAP822 and MAPX400 back to back
  30: [0], // NXT — next domain name, then a type bitmap
  33: [6], // SRV — priority, weight, port
  35: [naptrReplacement], // NAPTR — the replacement, after three character strings
  38: [a6PrefixName], // A6 — the prefix name, after the address suffix
  47: [0], // NSEC — next domain name
};

// RFC 4034 §6.2 item 3 as RFC 6840 §5.1 corrects it: the types whose embedded names are
// downcased for canonical form. HINFO holds no names and NSEC is left as published, so an
// NSEC next-domain name keeps the case the signer gave it. RRSIG stays on the list, but
// its signer name is downcased where the signed data is built (decodeRrsig), so it needs
// no entry here
const DOWNCASE_NAMES_IN_RDATA = new Set([
  2, 3, 4, 5, 6, 7, 8, 9, 12, 14, 15, 17, 18, 21, 24, 26, 30, 33, 35, 36, 38, 39,
]);

export type WireSection = 'answer' | 'authority' | 'additional';

export interface WireRecord {
  // owner name, lowercased, without the trailing dot (root is '.')
  name: string;
  type: number;
  typeName: string;
  class: number;
  ttl: number;
  // RDATA in RFC 4034 §6.2 canonical form — this is what gets signed
  rdata: Uint8Array;
  section: WireSection;
}

export interface WireMessage {
  id: number;
  rcode: number;
  // header flags
  qr: boolean;
  aa: boolean;
  tc: boolean;
  rd: boolean;
  ra: boolean;
  ad: boolean;
  cd: boolean;
  question?: { name: string; type: number; class: number };
  answers: WireRecord[];
  authorities: WireRecord[];
  additionals: WireRecord[];
  // EDNS
  ednsUdpSize?: number;
  doBit: boolean;
  extendedErrorCode?: number;
  extendedErrorText?: string;
  bytes: number;
}

// ---------------------------------------------------------------------------
// names
// ---------------------------------------------------------------------------

// read a (possibly compressed) name starting at `offset`. returns the decoded labels and
// the offset just past the name *in the outer message* — pointer chases don't advance it
function readName(buf: Uint8Array, offset: number): { labels: Uint8Array[]; end: number } {
  const labels: Uint8Array[] = [];
  let pos = offset;
  let end = -1;
  let jumps = 0;

  for (;;) {
    if (pos >= buf.length) throw new Error('truncated name');
    const len = buf[pos];

    if (len === 0) {
      pos += 1;
      if (end < 0) end = pos;
      break;
    }

    // compression pointer: top two bits set, 14-bit offset follows
    if ((len & 0xc0) === 0xc0) {
      if (pos + 1 >= buf.length) throw new Error('truncated compression pointer');
      const target = ((len & 0x3f) << 8) | buf[pos + 1];
      if (end < 0) end = pos + 2;
      // a pointer must always point backwards; the jump cap is the belt to that braces
      if (target >= pos || ++jumps > 128) throw new Error('invalid compression pointer');
      pos = target;
      continue;
    }

    if ((len & 0xc0) !== 0) throw new Error('unknown label type');
    if (pos + 1 + len > buf.length) throw new Error('truncated label');
    labels.push(buf.subarray(pos + 1, pos + 1 + len));
    pos += 1 + len;
  }

  return { labels, end };
}

// labels -> a display name, with the DNS presentation escapes applied
function labelsToName(labels: Uint8Array[]): string {
  if (labels.length === 0) return '.';
  return labels.map(l => escapeLabel(l)).join('.');
}

function escapeLabel(label: Uint8Array): string {
  let out = '';
  for (const byte of label) {
    if (byte === 0x2e || byte === 0x5c) {
      // '.' and '\' are escaped with a backslash
      out += '\\' + String.fromCharCode(byte);
    } else if (byte < 0x21 || byte > 0x7e) {
      out += '\\' + byte.toString().padStart(3, '0');
    } else {
      out += String.fromCharCode(byte);
    }
  }
  return out;
}

// encode a name to uncompressed, lowercased wire form — the canonical form for signing
export function encodeName(name: string): Uint8Array {
  const trimmed = endsWithRootDot(name) ? name.slice(0, -1) : name;
  if (trimmed === '' || trimmed === '.') return Uint8Array.from([0]);

  const parts: Uint8Array[] = [];
  for (const label of splitName(trimmed)) {
    const bytes = unescapeLabel(label);
    if (bytes.length > 63) throw new Error(`label too long: ${label}`);
    parts.push(Uint8Array.from([bytes.length]), lowercaseAscii(bytes));
  }
  parts.push(Uint8Array.from([0]));
  return concatBytes(parts);
}

// split on unescaped dots
function splitName(name: string): string[] {
  const out: string[] = [];
  let current = '';
  for (let i = 0; i < name.length; i++) {
    const ch = name[i];
    if (ch === '\\') {
      current += ch + (name[i + 1] ?? '');
      i += 1;
    } else if (ch === '.') {
      out.push(current);
      current = '';
    } else {
      current += ch;
    }
  }
  out.push(current);
  return out;
}

function unescapeLabel(label: string): Uint8Array {
  const bytes: number[] = [];
  for (let i = 0; i < label.length; i++) {
    if (label[i] === '\\') {
      const digits = label.slice(i + 1, i + 4);
      if (/^\d{3}$/.test(digits)) {
        bytes.push(parseInt(digits, 10));
        i += 3;
      } else {
        bytes.push(label.charCodeAt(i + 1));
        i += 1;
      }
    } else {
      bytes.push(label.charCodeAt(i));
    }
  }
  return Uint8Array.from(bytes);
}

function lowercaseAscii(buf: Uint8Array): Uint8Array {
  const out = Uint8Array.from(buf);
  for (let i = 0; i < out.length; i++) {
    if (out[i] >= 0x41 && out[i] <= 0x5a) out[i] += 0x20;
  }
  return out;
}

// normalise a name for comparison and display: lowercase, no trailing dot, '.' for root.
// Only the root's dot goes: `a\.` keeps its escaped dot, and `foo\\.` loses the root's
export function canonicalName(name: string): string {
  const trimmed = endsWithRootDot(name) ? name.slice(0, -1) : name;
  return trimmed === '' ? '.' : trimmed.toLowerCase();
}

// number of labels in a name, excluding the root label (RFC 4034 §3.1.3)
export function countLabels(name: string): number {
  const n = canonicalName(name);
  if (n === '.') return 0;
  return splitName(n).length;
}

// the name one label up: 'a.b.example.com' -> 'b.example.com', 'com' -> '.'
export function parentName(name: string): string {
  const n = canonicalName(name);
  if (n === '.') return '.';
  const parts = splitName(n);
  return parts.length <= 1 ? '.' : parts.slice(1).join('.');
}

// true when `name` is at or below `zone`, label by label: `a\.example.com` is not below
// example.com, since `a.example` is one label
export function isInZone(name: string, zone: string): boolean {
  return isSubdomain(canonicalName(name), canonicalName(zone));
}

// ---------------------------------------------------------------------------
// message parsing
// ---------------------------------------------------------------------------

// canonicalise RDATA (RFC 4034 §6.2): downcase the names embedded in it, for the types the
// RFC lists. The decoder has already written those names out in full, so they are walked
// in place; every other byte is left as it was
export function canonicalRdata(type: number, rdata: Uint8Array): Uint8Array {
  const layout = NAME_OFFSETS_IN_RDATA[type];
  if (!layout || !DOWNCASE_NAMES_IN_RDATA.has(type)) return rdata;

  const out = Uint8Array.from(rdata);
  let pos = 0;
  for (const entry of layout) {
    const declared = typeof entry === 'function' ? entry(out) : entry;
    // a declared offset of -1 means "immediately after the previous name"
    if (declared >= 0) pos = declared;
    for (;;) {
      const length = out[pos];
      // a name that runs off the end, or is not plain labels, is left for the decoders
      // to reject
      if (length === undefined || (length & 0xc0) !== 0) return out;
      pos += 1;
      if (length === 0) break;
      for (let i = pos; i < pos + length && i < out.length; i++) {
        if (out[i] >= 0x41 && out[i] <= 0x5a) out[i] += 0x20;
      }
      pos += length;
    }
  }
  return out;
}

// a decoded message as the DNSSEC code reads it: names lowercased, record data in
// canonical form, the EDNS state flattened
export function toWireMessage(message: Message): WireMessage {
  const record = (rr: ResourceRecord): WireRecord => ({
    name: canonicalName(rr.name),
    type: rr.type,
    typeName: recordTypeName(rr.type),
    class: rr.class,
    ttl: rr.ttl,
    rdata: canonicalRdata(rr.type, rr.rdata),
    section: rr.section,
  });
  const [question] = message.questions;
  const wire: WireMessage = {
    id: message.id,
    rcode: message.rcode,
    qr: message.flags.qr,
    aa: message.flags.aa,
    tc: message.flags.tc,
    rd: message.flags.rd,
    ra: message.flags.ra,
    ad: message.flags.ad,
    cd: message.flags.cd,
    answers: message.answers.map(record),
    authorities: message.authorities.map(record),
    additionals: message.additionals.map(record),
    doBit: message.edns?.dnssecOk ?? false,
    bytes: message.bytes,
  };
  if (question) {
    wire.question = {
      name: canonicalName(question.name),
      type: question.type,
      class: question.class,
    };
  }
  if (message.edns) {
    wire.ednsUdpSize = message.edns.udpPayloadSize;
    // the extended DNS error (RFC 8914), if the server sent one
    for (const option of message.edns.options) {
      if (option.code === 15 && option.data.length >= 2) {
        wire.extendedErrorCode = readU16(option.data, 0);
        // eslint-disable-next-line no-control-regex
        const text = utf8Decode(option.data.subarray(2)).replace(/\u0000+$/, '');
        if (text) wire.extendedErrorText = text;
      }
    }
  }
  return wire;
}

// ---------------------------------------------------------------------------
// RRsets
// ---------------------------------------------------------------------------

export interface Rrset {
  name: string;
  type: number;
  typeName: string;
  class: number;
  ttl: number;
  records: WireRecord[];
}

// group records into RRsets keyed by (name, class, type), as RFC 2181 defines them
export function groupRrsets(records: WireRecord[]): Rrset[] {
  const map = new Map<string, Rrset>();
  for (const rr of records) {
    if (rr.type === TYPE_RRSIG || rr.type === TYPE_OPT) continue;
    const key = `${rr.name}/${rr.class}/${rr.type}`;
    const existing = map.get(key);
    if (existing) {
      existing.records.push(rr);
      existing.ttl = Math.min(existing.ttl, rr.ttl);
    } else {
      map.set(key, {
        name: rr.name,
        type: rr.type,
        typeName: rr.typeName,
        class: rr.class,
        ttl: rr.ttl,
        records: [rr],
      });
    }
  }
  return [...map.values()];
}

// ---------------------------------------------------------------------------
// RFC 4034 primitives
// ---------------------------------------------------------------------------

// key tag over canonical DNSKEY RDATA (RFC 4034 Appendix B), including the algorithm-1
// special case. this is the single implementation — key tag is the join key for nearly
// every other check, so a second, drifting copy manufactures false orphans
export function computeKeyTag(rdata: Uint8Array): number {
  const algorithm = rdata.length > 3 ? rdata[3] : 0;

  // RFC 4034 Appendix B.1: for RSA/MD5 the tag is the next-to-last two bytes of the modulus
  if (algorithm === 1) {
    if (rdata.length < 7) return 0;
    return (rdata[rdata.length - 3] << 8) | rdata[rdata.length - 2];
  }

  let ac = 0;
  for (let i = 0; i < rdata.length; i++) {
    ac += i & 1 ? rdata[i] : rdata[i] << 8;
  }
  ac += (ac >> 16) & 0xffff;
  return ac & 0xffff;
}

// DS digest (RFC 4034 §5.1.4): digest(canonical owner name || DNSKEY RDATA). Null for a
// digest type that cannot be computed here
export function computeDsDigest(
  ownerName: string,
  dnskeyRdata: Uint8Array,
  digestType: number
): Uint8Array | null {
  const input = concatBytes([encodeName(ownerName), dnskeyRdata]);
  switch (digestType) {
    case 1:
      return sha1(input);
    case 2:
      return sha256(input);
    case 4:
      return sha384(input);
    default:
      return null;
  }
}

export interface RrsigFields {
  typeCovered: number;
  algorithm: number;
  labels: number;
  originalTtl: number;
  expiration: number;
  inception: number;
  keyTag: number;
  signerName: string;
  signature: Uint8Array;
  // RRSIG RDATA truncated just after the signer name — the prefix that is itself signed
  signedPrefix: Uint8Array;
}

export function decodeRrsig(rdata: Uint8Array): RrsigFields | null {
  if (rdata.length < 18) return null;
  const typeCovered = readU16(rdata, 0);
  const algorithm = rdata[2];
  const labels = rdata[3];
  const originalTtl = readU32(rdata, 4);
  const expiration = readU32(rdata, 8);
  const inception = readU32(rdata, 12);
  const keyTag = readU16(rdata, 16);

  let signer: { labels: Uint8Array[]; end: number };
  try {
    // the signer name inside RRSIG RDATA is never compressed (RFC 4034 §3.1.7)
    signer = readName(rdata, 18);
  } catch {
    return null;
  }

  // RFC 4034 §3.1.8.1 signs the RDATA through the signer name, with the signature omitted.
  // the signer name is downcased for this purpose even though §6.2 leaves the stored copy be
  const canonicalSigner = encodeName(labelsToName(signer.labels));
  const signedPrefix = concatBytes([rdata.subarray(0, 18), canonicalSigner]);

  return {
    typeCovered,
    algorithm,
    labels,
    originalTtl,
    expiration,
    inception,
    keyTag,
    signerName: canonicalName(labelsToName(signer.labels)),
    signature: Uint8Array.from(rdata.subarray(signer.end)),
    signedPrefix,
  };
}

export interface DnskeyFields {
  flags: number;
  protocol: number;
  algorithm: number;
  publicKey: Uint8Array;
}

export function decodeDnskey(rdata: Uint8Array): DnskeyFields | null {
  if (rdata.length < 4) return null;
  return {
    flags: readU16(rdata, 0),
    protocol: rdata[2],
    algorithm: rdata[3],
    publicKey: Uint8Array.from(rdata.subarray(4)),
  };
}

export interface DsFields {
  keyTag: number;
  algorithm: number;
  digestType: number;
  digest: Uint8Array;
}

export function decodeDs(rdata: Uint8Array): DsFields | null {
  if (rdata.length < 5) return null;
  return {
    keyTag: readU16(rdata, 0),
    algorithm: rdata[2],
    digestType: rdata[3],
    digest: Uint8Array.from(rdata.subarray(4)),
  };
}

export interface NsecFields {
  nextDomain: string;
  types: number[];
}

export function decodeNsec(rdata: Uint8Array): NsecFields | null {
  try {
    const { labels, end } = readName(rdata, 0);
    return {
      nextDomain: canonicalName(labelsToName(labels)),
      types: decodeTypeBitmap(rdata.subarray(end)),
    };
  } catch {
    return null;
  }
}

export interface Nsec3Fields {
  hashAlgorithm: number;
  flags: number;
  iterations: number;
  salt: Uint8Array;
  nextHashed: Uint8Array;
  types: number[];
}

export function decodeNsec3(rdata: Uint8Array): Nsec3Fields | null {
  if (rdata.length < 6) return null;
  const hashAlgorithm = rdata[0];
  const flags = rdata[1];
  const iterations = readU16(rdata, 2);
  const saltLength = rdata[4];
  if (5 + saltLength + 1 > rdata.length) return null;
  const salt = Uint8Array.from(rdata.subarray(5, 5 + saltLength));
  const hashLength = rdata[5 + saltLength];
  const hashStart = 6 + saltLength;
  if (hashStart + hashLength > rdata.length) return null;

  return {
    hashAlgorithm,
    flags,
    iterations,
    salt,
    nextHashed: Uint8Array.from(rdata.subarray(hashStart, hashStart + hashLength)),
    types: decodeTypeBitmap(rdata.subarray(hashStart + hashLength)),
  };
}

export interface Nsec3ParamFields {
  hashAlgorithm: number;
  flags: number;
  iterations: number;
  salt: Uint8Array;
}

export function decodeNsec3Param(rdata: Uint8Array): Nsec3ParamFields | null {
  if (rdata.length < 5) return null;
  const saltLength = rdata[4];
  if (5 + saltLength > rdata.length) return null;
  return {
    hashAlgorithm: rdata[0],
    flags: rdata[1],
    iterations: readU16(rdata, 2),
    salt: Uint8Array.from(rdata.subarray(5, 5 + saltLength)),
  };
}

// RFC 4034 §4.1.2 type bitmaps: a sequence of (window, length, bytes) blocks
export function decodeTypeBitmap(buf: Uint8Array): number[] {
  const types: number[] = [];
  let pos = 0;
  while (pos + 2 <= buf.length) {
    const window = buf[pos];
    const length = buf[pos + 1];
    pos += 2;
    for (let i = 0; i < length && pos + i < buf.length; i++) {
      const byte = buf[pos + i];
      for (let bit = 0; bit < 8; bit++) {
        if (byte & (0x80 >> bit)) types.push(window * 256 + i * 8 + bit);
      }
    }
    pos += length;
  }
  return types;
}

// ---------------------------------------------------------------------------
// signed data reconstruction
// ---------------------------------------------------------------------------

// canonical RR ordering within an RRset (RFC 4034 §6.3): sort by RDATA, treated as an
// unsigned left-justified octet sequence
function compareRdata(a: WireRecord, b: WireRecord): number {
  return compareBytes(a.rdata, b.rdata);
}

// the wildcard an answer at `name` was synthesised from, given its RRSIG's labels field: `*.`
// and the rightmost `labels` labels, the source of synthesis (RFC 4035 §5.3.2)
export function wildcardOwner(name: string, labels: number): string {
  const parts = splitName(canonicalName(name));
  return `*.${parts.slice(parts.length - labels).join('.')}`;
}

// the exact bytes an RRSIG covers: `RRSIG RDATA (through the signer name) || canonical RRset`
// (RFC 4034 §3.1.8.1). returns null when the RRset cannot be canonicalised
export function buildSignedData(
  rrsig: RrsigFields,
  rrset: Rrset
): { data: Uint8Array; ownerName: string; wildcard: boolean } | null {
  const ownerLabels = countLabels(rrset.name);
  if (rrsig.labels > ownerLabels) return null;

  // RFC 4035 §5.3.2: fewer labels in the RRSIG than in the owner name means the answer was
  // synthesised from a wildcard, and the name that was actually signed is *.<closest encloser>
  const wildcard = rrsig.labels < ownerLabels;
  const signedOwner = wildcard ? wildcardOwner(rrset.name, rrsig.labels) : rrset.name;

  const encodedOwner = encodeName(signedOwner);
  const parts: Uint8Array[] = [rrsig.signedPrefix];

  // deduplicate identical RDATA before ordering: a duplicate RR in the wire response is not
  // part of the RRset and would corrupt the digest if included twice
  const seen = new Set<string>();
  const unique = rrset.records.filter(rr => {
    const key = toBase64(rr.rdata);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  for (const rr of [...unique].sort(compareRdata)) {
    const header = new Uint8Array(10);
    writeU16(header, 0, rrset.type);
    writeU16(header, 2, rrset.class);
    // the original TTL from the RRSIG, not the TTL the record arrived with
    writeU32(header, 4, rrsig.originalTtl);
    writeU16(header, 8, rr.rdata.length);
    parts.push(encodedOwner, header, rr.rdata);
  }

  return { data: concatBytes(parts), ownerName: signedOwner, wildcard };
}

// ---------------------------------------------------------------------------
// NSEC3 hashing
// ---------------------------------------------------------------------------

// RFC 9276 §3.1: a validator may treat NSEC3 iteration counts above 500 as SERVFAIL. the count is
// an attacker-controlled uint16 and each round is a SHA-1 over the running digest, so an uncapped
// loop over a hostile zone's records is a CPU-exhaustion vector on a shared backend. refuse to hash
// beyond the cap — callers already treat a null hash as an unverifiable proof, which is the correct
// outcome for an over-limit zone
export const NSEC3_MAX_ITERATIONS = 500;

// RFC 5155 §5: iterated SHA-1 over the canonical name with the salt appended each round
export function nsec3Hash(
  name: string,
  salt: Uint8Array,
  iterations: number,
  hashAlgorithm = 1
): string | null {
  if (hashAlgorithm !== 1) return null;
  if (iterations > NSEC3_MAX_ITERATIONS) return null;
  let digest = sha1(concatBytes([encodeName(name), salt]));
  for (let i = 0; i < iterations; i++) digest = sha1(concatBytes([digest, salt]));
  return toBase32Hex(digest).toLowerCase();
}

// base32hex-encode a raw NSEC3 next-hashed field for comparison and display
export function toNsec3Label(hash: Uint8Array): string {
  return toBase32Hex(hash).toLowerCase();
}

// ---------------------------------------------------------------------------
// presentation format
// ---------------------------------------------------------------------------

// render a record in zone-file presentation format. RDATA the tool does not decode is shown
// in RFC 3597 unknown-type form rather than guessed at
export function presentRecord(rr: WireRecord): string {
  const owner = rr.name === '.' ? '.' : `${rr.name}.`;
  const head = `${owner}\t${rr.ttl}\tIN\t${rr.typeName}`;
  return `${head}\t${presentRdata(rr)}`;
}

function presentRdata(rr: WireRecord): string {
  switch (rr.type) {
    case TYPE_A:
      return rr.rdata.length === 4 ? rr.rdata.join('.') : unknownRdata(rr.rdata);
    case TYPE_AAAA: {
      if (rr.rdata.length !== 16) return unknownRdata(rr.rdata);
      const groups: string[] = [];
      for (let i = 0; i < 16; i += 2) groups.push(readU16(rr.rdata, i).toString(16));
      return groups.join(':');
    }
    case TYPE_NS:
    case TYPE_CNAME:
    case 12: // PTR
    case 39: {
      // DNAME
      const decoded = decodeNsec(rr.rdata);
      return decoded ? `${decoded.nextDomain}.` : unknownRdata(rr.rdata);
    }
    case TYPE_TXT: {
      const strings: string[] = [];
      let pos = 0;
      while (pos < rr.rdata.length) {
        const len = rr.rdata[pos];
        strings.push(JSON.stringify(utf8Decode(rr.rdata.subarray(pos + 1, pos + 1 + len))));
        pos += 1 + len;
      }
      return strings.join(' ');
    }
    case TYPE_DNSKEY:
    case TYPE_CDNSKEY: {
      const key = decodeDnskey(rr.rdata);
      if (!key) return unknownRdata(rr.rdata);
      return `${key.flags} ${key.protocol} ${key.algorithm} ${toBase64(key.publicKey)}`;
    }
    case TYPE_DS:
    case TYPE_CDS: {
      const ds = decodeDs(rr.rdata);
      if (!ds) return unknownRdata(rr.rdata);
      return `${ds.keyTag} ${ds.algorithm} ${ds.digestType} ${toHex(ds.digest).toUpperCase()}`;
    }
    case TYPE_RRSIG: {
      const sig = decodeRrsig(rr.rdata);
      if (!sig) return unknownRdata(rr.rdata);
      return [
        recordTypeName(sig.typeCovered),
        sig.algorithm,
        sig.labels,
        sig.originalTtl,
        formatSigTime(sig.expiration),
        formatSigTime(sig.inception),
        sig.keyTag,
        `${sig.signerName === '.' ? '' : sig.signerName}.`,
        toBase64(sig.signature),
      ].join(' ');
    }
    case TYPE_NSEC: {
      const nsec = decodeNsec(rr.rdata);
      if (!nsec) return unknownRdata(rr.rdata);
      return `${nsec.nextDomain}. ${nsec.types.map(recordTypeName).join(' ')}`;
    }
    case TYPE_NSEC3: {
      const nsec3 = decodeNsec3(rr.rdata);
      if (!nsec3) return unknownRdata(rr.rdata);
      const salt = nsec3.salt.length ? toHex(nsec3.salt).toUpperCase() : '-';
      return `${nsec3.hashAlgorithm} ${nsec3.flags} ${nsec3.iterations} ${salt} ${toNsec3Label(nsec3.nextHashed).toUpperCase()} ${nsec3.types.map(recordTypeName).join(' ')}`;
    }
    case TYPE_SOA: {
      try {
        const mname = readName(rr.rdata, 0);
        const rname = readName(rr.rdata, mname.end);
        const rest = rr.rdata.subarray(rname.end);
        if (rest.length < 20) return unknownRdata(rr.rdata);
        return [
          `${labelsToName(mname.labels)}.`,
          `${labelsToName(rname.labels)}.`,
          readU32(rest, 0),
          readU32(rest, 4),
          readU32(rest, 8),
          readU32(rest, 12),
          readU32(rest, 16),
        ].join(' ');
      } catch {
        return unknownRdata(rr.rdata);
      }
    }
    case TYPE_MX: {
      if (rr.rdata.length < 3) return unknownRdata(rr.rdata);
      try {
        const { labels } = readName(rr.rdata, 2);
        return `${readU16(rr.rdata, 0)} ${labelsToName(labels)}.`;
      } catch {
        return unknownRdata(rr.rdata);
      }
    }
    default:
      return unknownRdata(rr.rdata);
  }
}

// RFC 3597 §5 unknown-RR presentation
function unknownRdata(rdata: Uint8Array): string {
  return `\\# ${rdata.length}${rdata.length ? ' ' + toHex(rdata).toUpperCase() : ''}`;
}

// RRSIG timestamps are presented as YYYYMMDDHHmmSS, not as an epoch
export function formatSigTime(epochSeconds: number): string {
  const d = new Date(epochSeconds * 1000);
  const pad = (n: number, w = 2) => String(n).padStart(w, '0');
  return (
    `${pad(d.getUTCFullYear(), 4)}${pad(d.getUTCMonth() + 1)}${pad(d.getUTCDate())}` +
    `${pad(d.getUTCHours())}${pad(d.getUTCMinutes())}${pad(d.getUTCSeconds())}`
  );
}
