import { ParseError } from '../errors';
import { className } from '../protocol/classes';
import { RECORD_TYPES, typeName } from '../protocol/types';
import {
  escapeText,
  formatIpv4,
  formatIpv6,
  readU16,
  readU32,
  toBase32Hex,
  toBase64,
  toHex,
} from '../wire/bytes';
import type { ResourceRecord } from '../wire/message';
import { labelsToName, readName } from '../wire/names';
import type { DnsRecord, ServiceParams, UnknownRecord } from './types';

// turning a record's RDATA into typed fields. Each decoder reads its type's layout from
// the bytes the wire layer kept, and must account for every byte: data that is too short,
// or has bytes left over, is malformed.

// a cursor over one record's data
class Reader {
  offset = 0;

  constructor(readonly bytes: Uint8Array) {}

  get remaining(): number {
    return this.bytes.length - this.offset;
  }

  private need(length: number): void {
    if (this.remaining < length) throw new ParseError('record data is too short');
  }

  u8(): number {
    this.need(1);
    return this.bytes[this.offset++];
  }

  u16(): number {
    this.need(2);
    const value = readU16(this.bytes, this.offset);
    this.offset += 2;
    return value;
  }

  u32(): number {
    this.need(4);
    const value = readU32(this.bytes, this.offset);
    this.offset += 4;
    return value;
  }

  take(length: number): Uint8Array {
    this.need(length);
    const out = this.bytes.subarray(this.offset, this.offset + length);
    this.offset += length;
    return out;
  }

  rest(): Uint8Array {
    return this.take(this.remaining);
  }

  // a domain name. The wire layer has already written out any compressed name
  name(): string {
    const read = readName(this.bytes, this.offset);
    this.offset = read.end;
    return labelsToName(read.labels);
  }

  // a <character-string>: one length byte, then that many bytes
  characterString(): Uint8Array {
    return this.take(this.u8());
  }
}

// the type bitmap of NSEC and NSEC3 (RFC 4034 §4.1.2): windows of up to 256 types each,
// as type codes
function readTypeBitmap(reader: Reader): number[] {
  const types: number[] = [];
  while (reader.remaining > 0) {
    const window = reader.u8();
    const length = reader.u8();
    if (length < 1 || length > 32) throw new ParseError('invalid type bitmap');
    const bitmap = reader.take(length);
    for (let index = 0; index < bitmap.length; index++) {
      for (let bit = 0; bit < 8; bit++) {
        if (bitmap[index] & (0x80 >> bit)) types.push(window * 256 + index * 8 + bit);
      }
    }
  }
  return types;
}

// the fields of the DNSSEC record types as the wire has them: type codes as numbers, keys,
// digests and signatures as bytes, times as seconds since the epoch, names as the server
// sent them. What the DNSSEC primitives compute over; `decodeRecord` presents the same
// fields as text

/** the fields of DS or CDS data, as `decodeDs` gives them */
export interface DsFields {
  keyTag: number;
  algorithm: number;
  digestType: number;
  digest: Uint8Array;
}

/** the fields of DNSKEY, CDNSKEY or KEY data, as `decodeDnskey` gives them */
export interface DnskeyFields {
  flags: number;
  protocol: number;
  algorithm: number;
  publicKey: Uint8Array;
}

/** the fields of RRSIG or SIG data, as `decodeRrsig` gives them */
export interface RrsigFields {
  typeCovered: number;
  algorithm: number;
  labels: number;
  originalTtl: number;
  /** seconds since the epoch (RFC 4034 §3.1.5) */
  expiration: number;
  inception: number;
  keyTag: number;
  signerName: string;
  signature: Uint8Array;
}

/** the fields of NSEC data, as `decodeNsec` gives them */
export interface NsecFields {
  nextDomain: string;
  types: number[];
}

/** the fields of NSEC3 data, as `decodeNsec3` gives them */
export interface Nsec3Fields {
  hashAlgorithm: number;
  flags: number;
  iterations: number;
  salt: Uint8Array;
  nextHashed: Uint8Array;
  types: number[];
}

/** the fields of NSEC3PARAM data, as `decodeNsec3Param` gives them */
export interface Nsec3ParamFields {
  hashAlgorithm: number;
  flags: number;
  iterations: number;
  salt: Uint8Array;
}

const readDs = (reader: Reader): DsFields => ({
  keyTag: reader.u16(),
  algorithm: reader.u8(),
  digestType: reader.u8(),
  digest: Uint8Array.from(reader.rest()),
});

const readDnskey = (reader: Reader): DnskeyFields => ({
  flags: reader.u16(),
  protocol: reader.u8(),
  algorithm: reader.u8(),
  publicKey: Uint8Array.from(reader.rest()),
});

const readRrsig = (reader: Reader): RrsigFields => ({
  typeCovered: reader.u16(),
  algorithm: reader.u8(),
  labels: reader.u8(),
  originalTtl: reader.u32(),
  expiration: reader.u32(),
  inception: reader.u32(),
  keyTag: reader.u16(),
  signerName: reader.name(),
  signature: Uint8Array.from(reader.rest()),
});

const readNsec = (reader: Reader): NsecFields => ({
  nextDomain: reader.name(),
  types: readTypeBitmap(reader),
});

const readNsec3 = (reader: Reader): Nsec3Fields => ({
  hashAlgorithm: reader.u8(),
  flags: reader.u8(),
  iterations: reader.u16(),
  salt: Uint8Array.from(reader.characterString()),
  nextHashed: Uint8Array.from(reader.characterString()),
  types: readTypeBitmap(reader),
});

const readNsec3Param = (reader: Reader): Nsec3ParamFields => ({
  hashAlgorithm: reader.u8(),
  flags: reader.u8(),
  iterations: reader.u16(),
  salt: Uint8Array.from(reader.characterString()),
});

// read one record's data, all of it, with `read`. Throws ParseError for data that is too
// short or has bytes left over
function decodeData<T>(rdata: Uint8Array, read: (reader: Reader) => T, what: string): T {
  try {
    const reader = new Reader(rdata);
    const fields = read(reader);
    if (reader.remaining > 0) throw new ParseError('record data has bytes left over');
    return fields;
  } catch (error) {
    if (!(error instanceof ParseError)) throw error;
    throw new ParseError(`Malformed ${what}: ${error.message}`, { cause: error });
  }
}

/** DS or CDS data (RFC 4034 §5.1) */
export function decodeDs(rdata: Uint8Array): DsFields {
  return decodeData(rdata, readDs, 'DS data');
}

/** DNSKEY, CDNSKEY or KEY data (RFC 4034 §2.1) */
export function decodeDnskey(rdata: Uint8Array): DnskeyFields {
  return decodeData(rdata, readDnskey, 'DNSKEY data');
}

/** RRSIG or SIG data (RFC 4034 §3.1) */
export function decodeRrsig(rdata: Uint8Array): RrsigFields {
  return decodeData(rdata, readRrsig, 'RRSIG data');
}

/** NSEC data (RFC 4034 §4.1) */
export function decodeNsec(rdata: Uint8Array): NsecFields {
  return decodeData(rdata, readNsec, 'NSEC data');
}

/** NSEC3 data (RFC 5155 §3.2) */
export function decodeNsec3(rdata: Uint8Array): Nsec3Fields {
  return decodeData(rdata, readNsec3, 'NSEC3 data');
}

/** NSEC3PARAM data (RFC 5155 §4.2) */
export function decodeNsec3Param(rdata: Uint8Array): Nsec3ParamFields {
  return decodeData(rdata, readNsec3Param, 'NSEC3PARAM data');
}

/** an NSEC or NSEC3 type bitmap (RFC 4034 §4.1.2), as type codes */
export function decodeTypeBitmap(bitmap: Uint8Array): number[] {
  return decodeData(bitmap, readTypeBitmap, 'type bitmap');
}

const delegationSigner = (reader: Reader) => {
  const ds = readDs(reader);
  return { ...ds, digest: toHex(ds.digest) };
};

const publicKey = (reader: Reader) => {
  const key = readDnskey(reader);
  return { ...key, publicKey: toBase64(key.publicKey) };
};

const signature = (reader: Reader) => {
  const sig = readRrsig(reader);
  return {
    typeCovered: typeName(sig.typeCovered),
    algorithm: sig.algorithm,
    labels: sig.labels,
    originalTtl: sig.originalTtl,
    signatureExpiration: sig.expiration,
    signatureInception: sig.inception,
    keyTag: sig.keyTag,
    signerName: sig.signerName,
    signature: toBase64(sig.signature),
  };
};

const target = (reader: Reader) => ({ target: reader.name() });

// a LOC size or precision: one byte, a base in the top four bits and a power of ten in
// the bottom four, in centimetres (RFC 1876 §2). Returned in metres
function locSize(byte: number): number {
  const base = byte >> 4;
  const exponent = byte & 0x0f;
  if (base > 9 || exponent > 9) throw new ParseError('invalid LOC size');
  return (base * 10 ** exponent) / 100;
}

const SERVICE_PARAM_NAMES: Record<number, string> = {
  0: 'mandatory',
  1: 'alpn',
  2: 'no-default-alpn',
  3: 'port',
  4: 'ipv4hint',
  5: 'ech',
  6: 'ipv6hint',
  7: 'dohpath',
  8: 'ohttp',
};

/** the name a service parameter key is written with: its mnemonic, or `key<n>` */
export function serviceParamName(key: number): string {
  return SERVICE_PARAM_NAMES[key] ?? `key${key}`;
}

function addresses(value: Uint8Array, size: 4 | 16): string[] {
  if (value.length === 0 || value.length % size !== 0) {
    throw new ParseError('invalid address hint');
  }
  const out: string[] = [];
  for (let offset = 0; offset < value.length; offset += size) {
    const address = value.subarray(offset, offset + size);
    out.push(size === 4 ? formatIpv4(address) : formatIpv6(address));
  }
  return out;
}

// SVCB and HTTPS (RFC 9460 §2.2): priority, target, then parameters in ascending key order
function serviceBinding(reader: Reader) {
  const priority = reader.u16();
  const targetName = reader.name();
  const params: ServiceParams = {};
  let previous = -1;
  while (reader.remaining > 0) {
    const key = reader.u16();
    if (key <= previous) throw new ParseError('service parameters are out of order');
    previous = key;
    const value = reader.take(reader.u16());
    switch (key) {
      case 0: {
        if (value.length === 0 || value.length % 2 !== 0) {
          throw new ParseError('invalid mandatory parameter');
        }
        params.mandatory = [];
        for (let offset = 0; offset < value.length; offset += 2) {
          params.mandatory.push(serviceParamName(readU16(value, offset)));
        }
        break;
      }
      case 1: {
        const ids = new Reader(value);
        params.alpn = [];
        while (ids.remaining > 0) params.alpn.push(escapeText(ids.characterString()));
        if (params.alpn.length === 0) throw new ParseError('empty alpn parameter');
        break;
      }
      case 2:
        if (value.length !== 0) throw new ParseError('no-default-alpn takes no value');
        params.noDefaultAlpn = true;
        break;
      case 3:
        if (value.length !== 2) throw new ParseError('invalid port parameter');
        params.port = readU16(value, 0);
        break;
      case 4:
        params.ipv4Hint = addresses(value, 4);
        break;
      case 5:
        params.ech = toBase64(value);
        break;
      case 6:
        params.ipv6Hint = addresses(value, 16);
        break;
      case 7:
        params.dohPath = escapeText(value);
        break;
      case 8:
        if (value.length !== 0) throw new ParseError('ohttp takes no value');
        params.ohttp = true;
        break;
      default:
        params.other = { ...params.other, [key]: toHex(value) };
    }
  }
  return { priority, target: targetName, params };
}

type Decoder = (reader: Reader) => Record<string, unknown>;

const DECODERS: Record<number, Decoder> = {
  [RECORD_TYPES.A]: reader => ({ address: formatIpv4(reader.take(4)) }),
  [RECORD_TYPES.AAAA]: reader => ({ address: formatIpv6(reader.take(16)) }),
  [RECORD_TYPES.NS]: target,
  [RECORD_TYPES.CNAME]: target,
  [RECORD_TYPES.PTR]: target,
  [RECORD_TYPES.DNAME]: target,
  [RECORD_TYPES.SOA]: reader => ({
    mname: reader.name(),
    rname: reader.name(),
    serial: reader.u32(),
    refresh: reader.u32(),
    retry: reader.u32(),
    expire: reader.u32(),
    minimum: reader.u32(),
  }),
  [RECORD_TYPES.MX]: reader => ({ preference: reader.u16(), exchange: reader.name() }),
  [RECORD_TYPES.TXT]: reader => {
    const strings: string[] = [];
    while (reader.remaining > 0) strings.push(escapeText(reader.characterString()));
    return { strings };
  },
  [RECORD_TYPES.CAA]: reader => ({
    flags: reader.u8(),
    tag: escapeText(reader.characterString()),
    value: escapeText(reader.rest()),
  }),
  [RECORD_TYPES.TLSA]: reader => ({
    usage: reader.u8(),
    selector: reader.u8(),
    matchingType: reader.u8(),
    certificate: toHex(reader.rest()),
  }),
  [RECORD_TYPES.DS]: delegationSigner,
  [RECORD_TYPES.CDS]: delegationSigner,
  [RECORD_TYPES.DNSKEY]: publicKey,
  [RECORD_TYPES.CDNSKEY]: publicKey,
  [RECORD_TYPES.KEY]: publicKey,
  [RECORD_TYPES.RRSIG]: signature,
  [RECORD_TYPES.SIG]: signature,
  [RECORD_TYPES.NSEC]: reader => {
    const nsec = readNsec(reader);
    return { nextDomain: nsec.nextDomain, types: nsec.types.map(typeName) };
  },
  [RECORD_TYPES.NSEC3]: reader => {
    const nsec3 = readNsec3(reader);
    return {
      algorithm: nsec3.hashAlgorithm,
      flags: nsec3.flags,
      iterations: nsec3.iterations,
      salt: toHex(nsec3.salt),
      nextDomain: toBase32Hex(nsec3.nextHashed),
      types: nsec3.types.map(typeName),
    };
  },
  [RECORD_TYPES.NSEC3PARAM]: reader => {
    const param = readNsec3Param(reader);
    return {
      algorithm: param.hashAlgorithm,
      flags: param.flags,
      iterations: param.iterations,
      salt: toHex(param.salt),
    };
  },
  [RECORD_TYPES.SRV]: reader => ({
    priority: reader.u16(),
    weight: reader.u16(),
    port: reader.u16(),
    target: reader.name(),
  }),
  [RECORD_TYPES.SVCB]: serviceBinding,
  [RECORD_TYPES.HTTPS]: serviceBinding,
  [RECORD_TYPES.CERT]: reader => ({
    certificateType: reader.u16(),
    keyTag: reader.u16(),
    algorithm: reader.u8(),
    certificate: toBase64(reader.rest()),
  }),
  [RECORD_TYPES.HINFO]: reader => ({
    cpu: escapeText(reader.characterString()),
    os: escapeText(reader.characterString()),
  }),
  [RECORD_TYPES.TSIG]: reader => {
    const algorithm = reader.name();
    // 48 bits of seconds: too wide for a 32-bit shift
    const timeSigned = reader.u16() * 0x100000000 + reader.u32();
    const fudge = reader.u16();
    const mac = toBase64(reader.take(reader.u16()));
    const originalId = reader.u16();
    const error = reader.u16();
    const otherData = toBase64(reader.take(reader.u16()));
    return { algorithm, timeSigned, fudge, mac, originalId, error, otherData };
  },
  [RECORD_TYPES.OPENPGPKEY]: reader => ({ key: toBase64(reader.rest()) }),
  [RECORD_TYPES.RP]: reader => ({ mbox: reader.name(), txt: reader.name() }),
  [RECORD_TYPES.SSHFP]: reader => ({
    algorithm: reader.u8(),
    fingerprintType: reader.u8(),
    fingerprint: toHex(reader.rest()),
  }),
  [RECORD_TYPES.URI]: reader => ({
    priority: reader.u16(),
    weight: reader.u16(),
    target: escapeText(reader.rest()),
  }),
  [RECORD_TYPES.NAPTR]: reader => ({
    order: reader.u16(),
    preference: reader.u16(),
    flags: escapeText(reader.characterString()),
    services: escapeText(reader.characterString()),
    regexp: escapeText(reader.characterString()),
    replacement: reader.name(),
  }),
  [RECORD_TYPES.LOC]: reader => {
    const version = reader.u8();
    if (version !== 0) throw new ParseError(`unsupported LOC version ${version}`);
    return {
      version,
      size: locSize(reader.u8()),
      horizontalPrecision: locSize(reader.u8()),
      verticalPrecision: locSize(reader.u8()),
      // thousandths of an arc second, offset so that 2^31 is the equator or prime meridian
      latitude: (reader.u32() - 0x80000000) / 3_600_000,
      longitude: (reader.u32() - 0x80000000) / 3_600_000,
      // centimetres, offset so that zero is 100,000 m below the spheroid
      altitude: (reader.u32() - 10_000_000) / 100,
    };
  },
};

/** the options of `decodeRecord` and `decodeRecords` */
export interface DecodeOptions {
  /**
   * malformed record data is an error. By default such a record comes back in the
   * generic form, as an UnknownRecord
   */
  strict?: boolean;
}

function unknownRecord(record: ResourceRecord): UnknownRecord {
  return {
    name: record.name,
    type: `TYPE${record.type}`,
    class: className(record.class),
    ttl: record.ttl,
    data: toHex(record.rdata),
  };
}

/** whether the library decodes this type into its own fields */
export function isKnownRecordType(type: number): boolean {
  return type in DECODERS;
}

/** decode one record's data into typed fields */
export function decodeRecord(record: ResourceRecord, options: DecodeOptions = {}): DnsRecord {
  const decoder = DECODERS[record.type];
  if (!decoder) return unknownRecord(record);
  try {
    const reader = new Reader(record.rdata);
    const fields = decoder(reader);
    if (reader.remaining > 0) throw new ParseError('record data has bytes left over');
    return {
      name: record.name,
      type: typeName(record.type),
      class: className(record.class),
      ttl: record.ttl,
      ...fields,
    } as DnsRecord;
  } catch (error) {
    if (!(error instanceof ParseError)) throw error;
    if (!options.strict) return unknownRecord(record);
    throw new ParseError(
      `Malformed ${typeName(record.type)} record at ${record.name}: ${error.message}`,
      { cause: error }
    );
  }
}

/** decode every record in a section */
export function decodeRecords(
  records: readonly ResourceRecord[],
  options: DecodeOptions = {}
): DnsRecord[] {
  return records.map(record => decodeRecord(record, options));
}
