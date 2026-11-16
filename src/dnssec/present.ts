import { ParseError } from '../errors';
import { RECORD_TYPES, typeName } from '../protocol/types';
import { decodeDnskey, decodeDs, decodeNsec, decodeNsec3, decodeRrsig } from '../records/decode';
import { formatSignatureTime } from '../records/format';
import { readU16, readU32, toBase64, toHex, utf8Decode } from '../wire/bytes';
import { canonicalName, labelsToName, readName } from '../wire/names';
import { toNsec3Label } from './canonical';
import type { WireRecord } from './canonical';

const { A, AAAA, NS, CNAME, PTR, DNAME, SOA, MX, TXT } = RECORD_TYPES;
const { DNSKEY, CDNSKEY, DS, CDS, RRSIG, NSEC, NSEC3 } = RECORD_TYPES;

// render a record in zone-file presentation format. RDATA the tool does not decode, or
// cannot, is shown in RFC 3597 unknown-type form rather than guessed at
export function presentRecord(rr: WireRecord): string {
  const owner = rr.name === '.' ? '.' : `${rr.name}.`;
  const head = `${owner}\t${rr.ttl}\tIN\t${rr.typeName}`;
  let data: string;
  try {
    data = presentRdata(rr);
  } catch (error) {
    if (!(error instanceof ParseError)) throw error;
    data = unknownRdata(rr.rdata);
  }
  return `${head}\t${data}`;
}

// the name at `offset` in record data, as the presentation form writes it
function nameAt(rdata: Uint8Array, offset: number): { name: string; end: number } {
  const { labels, end } = readName(rdata, offset);
  return { name: labelsToName(labels), end };
}

function presentRdata(rr: WireRecord): string {
  switch (rr.type) {
    case A:
      return rr.rdata.length === 4 ? rr.rdata.join('.') : unknownRdata(rr.rdata);
    case AAAA: {
      if (rr.rdata.length !== 16) return unknownRdata(rr.rdata);
      const groups: string[] = [];
      for (let i = 0; i < 16; i += 2) groups.push(readU16(rr.rdata, i).toString(16));
      return groups.join(':');
    }
    case NS:
    case CNAME:
    case PTR:
    case DNAME:
      return `${canonicalName(nameAt(rr.rdata, 0).name)}.`;
    case TXT: {
      const strings: string[] = [];
      let pos = 0;
      while (pos < rr.rdata.length) {
        const len = rr.rdata[pos];
        strings.push(JSON.stringify(utf8Decode(rr.rdata.subarray(pos + 1, pos + 1 + len))));
        pos += 1 + len;
      }
      return strings.join(' ');
    }
    case DNSKEY:
    case CDNSKEY: {
      const key = decodeDnskey(rr.rdata);
      return `${key.flags} ${key.protocol} ${key.algorithm} ${toBase64(key.publicKey)}`;
    }
    case DS:
    case CDS: {
      const ds = decodeDs(rr.rdata);
      return `${ds.keyTag} ${ds.algorithm} ${ds.digestType} ${toHex(ds.digest).toUpperCase()}`;
    }
    case RRSIG: {
      const sig = decodeRrsig(rr.rdata);
      const signer = canonicalName(sig.signerName);
      return [
        typeName(sig.typeCovered),
        sig.algorithm,
        sig.labels,
        sig.originalTtl,
        formatSignatureTime(sig.expiration),
        formatSignatureTime(sig.inception),
        sig.keyTag,
        `${signer === '.' ? '' : signer}.`,
        toBase64(sig.signature),
      ].join(' ');
    }
    case NSEC: {
      const nsec = decodeNsec(rr.rdata);
      return `${canonicalName(nsec.nextDomain)}. ${nsec.types.map(typeName).join(' ')}`;
    }
    case NSEC3: {
      const nsec3 = decodeNsec3(rr.rdata);
      const salt = nsec3.salt.length ? toHex(nsec3.salt).toUpperCase() : '-';
      return `${nsec3.hashAlgorithm} ${nsec3.flags} ${nsec3.iterations} ${salt} ${toNsec3Label(nsec3.nextHashed).toUpperCase()} ${nsec3.types.map(typeName).join(' ')}`;
    }
    case SOA: {
      const mname = nameAt(rr.rdata, 0);
      const rname = nameAt(rr.rdata, mname.end);
      const rest = rr.rdata.subarray(rname.end);
      if (rest.length < 20) return unknownRdata(rr.rdata);
      return [
        `${mname.name}.`,
        `${rname.name}.`,
        readU32(rest, 0),
        readU32(rest, 4),
        readU32(rest, 8),
        readU32(rest, 12),
        readU32(rest, 16),
      ].join(' ');
    }
    case MX: {
      if (rr.rdata.length < 3) return unknownRdata(rr.rdata);
      return `${readU16(rr.rdata, 0)} ${nameAt(rr.rdata, 2).name}.`;
    }
    default:
      return unknownRdata(rr.rdata);
  }
}

// RFC 3597 §5 unknown-RR presentation
function unknownRdata(rdata: Uint8Array): string {
  return `\\# ${rdata.length}${rdata.length ? ' ' + toHex(rdata).toUpperCase() : ''}`;
}
