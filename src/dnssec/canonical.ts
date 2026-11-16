import { RECORD_TYPES, typeName } from '../protocol/types';
import type { RrsigFields } from '../records/decode';
import {
  compareBytes,
  concatBytes,
  readU16,
  toBase32Hex,
  toBase64,
  utf8Decode,
  writeU16,
  writeU32,
} from '../wire/bytes';
import type { Message, ResourceRecord } from '../wire/message';
import { canonicalName, countLabels, encodeName, splitName } from '../wire/names';
import { sha1, sha256, sha384 } from './hash';

// the DNSSEC view of a DNS message, and the RFC 4034 primitives built on it: key tag, DS
// digest, the bytes an RRSIG covers, NSEC3 hashing.
//
// verification needs the exact bytes the signer signed. The library's decoder keeps each
// record's data as it arrived, with names inside it written out in full; what this adds
// is the canonical form of RFC 4034 §6.2 (those names downcased, for the types the RFC
// lists), which is what a signature is computed over. Names and record data are read
// with the codec in `/wire` and `/records`

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
// its signer name is downcased where the signed data is built (buildSignedData), so it
// needs no entry here
const DOWNCASE_NAMES_IN_RDATA = new Set([
  2, 3, 4, 5, 6, 7, 8, 9, 12, 14, 15, 17, 18, 21, 24, 26, 30, 33, 35, 36, 38, 39,
]);

export type WireSection = 'answer' | 'authority' | 'additional';

export interface WireRecord {
  // owner name as the server wrote it, without the trailing dot (root is '.'). Compare
  // with `canonicalName`
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

// a decoded message as the DNSSEC code reads it: names in the case the server wrote them,
// record data in canonical form, the EDNS state flattened
export function toWireMessage(message: Message): WireMessage {
  const record = (rr: ResourceRecord): WireRecord => ({
    name: rr.name,
    type: rr.type,
    typeName: typeName(rr.type),
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
      name: question.name,
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

// group records into RRsets keyed by (name, class, type), as RFC 2181 defines them. Names
// are compared without regard to case; the RRset takes its first record's spelling
export function groupRrsets(records: WireRecord[]): Rrset[] {
  const map = new Map<string, Rrset>();
  for (const rr of records) {
    if (rr.type === RECORD_TYPES.RRSIG || rr.type === RECORD_TYPES.OPT) continue;
    const key = `${canonicalName(rr.name)}/${rr.class}/${rr.type}`;
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

// a name in canonical wire form (RFC 4034 §6.2): uncompressed and lowercased
function canonicalWireName(name: string): Uint8Array {
  return encodeName(canonicalName(name));
}

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
  const input = concatBytes([canonicalWireName(ownerName), dnskeyRdata]);
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

// the RRSIG RDATA through the signer name, with the signature left off (RFC 4034
// §3.1.8.1). The signer name is downcased here even though §6.2 leaves the stored copy be
function signedPrefix(rrsig: RrsigFields): Uint8Array {
  const fixed = new Uint8Array(18);
  writeU16(fixed, 0, rrsig.typeCovered);
  fixed[2] = rrsig.algorithm;
  fixed[3] = rrsig.labels;
  writeU32(fixed, 4, rrsig.originalTtl);
  writeU32(fixed, 8, rrsig.expiration);
  writeU32(fixed, 12, rrsig.inception);
  writeU16(fixed, 16, rrsig.keyTag);
  return concatBytes([fixed, canonicalWireName(rrsig.signerName)]);
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

  const encodedOwner = canonicalWireName(signedOwner);
  const parts: Uint8Array[] = [signedPrefix(rrsig)];

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
  let digest = sha1(concatBytes([canonicalWireName(name), salt]));
  for (let i = 0; i < iterations; i++) digest = sha1(concatBytes([digest, salt]));
  return toBase32Hex(digest).toLowerCase();
}

// base32hex-encode a raw NSEC3 next-hashed field for comparison and display
export function toNsec3Label(hash: Uint8Array): string {
  return toBase32Hex(hash).toLowerCase();
}
