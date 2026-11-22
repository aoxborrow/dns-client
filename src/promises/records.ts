import type { DnsRecord } from '../records/types';
import { fromHex, unescapeText, utf8Decode } from '../wire/bytes';

// the library's records in the shapes `node:dns` returns them in. The interfaces repeat
// Node's own (`@types/node`'s `dns` module) field for field

/** Node's `RecordWithTtl`, as `node:dns` returns it */
export interface RecordWithTtl {
  address: string;
  ttl: number;
}

/** Node's `CaaRecord`, as `node:dns` returns it */
export interface CaaRecord {
  critical: number;
  issue?: string;
  issuewild?: string;
  iodef?: string;
  contactemail?: string;
  contactphone?: string;
}

/** Node's `MxRecord`, as `node:dns` returns it */
export interface MxRecord {
  priority: number;
  exchange: string;
}

/** Node's `NaptrRecord`, as `node:dns` returns it */
export interface NaptrRecord {
  flags: string;
  service: string;
  regexp: string;
  replacement: string;
  order: number;
  preference: number;
}

/** Node's `SoaRecord`, as `node:dns` returns it */
export interface SoaRecord {
  nsname: string;
  hostmaster: string;
  serial: number;
  refresh: number;
  retry: number;
  expire: number;
  minttl: number;
}

/** Node's `SrvRecord`, as `node:dns` returns it */
export interface SrvRecord {
  priority: number;
  weight: number;
  port: number;
  name: string;
}

/** Node's `TlsaRecord`, as `node:dns` returns it */
export interface TlsaRecord {
  certUsage: number;
  selector: number;
  match: number;
  data: ArrayBuffer;
}

/** Node's `AnyARecord`, as `node:dns` returns it */
export interface AnyARecord extends RecordWithTtl {
  type: 'A';
}
/** Node's `AnyAaaaRecord`, as `node:dns` returns it */
export interface AnyAaaaRecord extends RecordWithTtl {
  type: 'AAAA';
}
/** Node's `AnyCaaRecord`, as `node:dns` returns it */
export interface AnyCaaRecord extends CaaRecord {
  type: 'CAA';
}
/** Node's `AnyMxRecord`, as `node:dns` returns it */
export interface AnyMxRecord extends MxRecord {
  type: 'MX';
}
/** Node's `AnyNaptrRecord`, as `node:dns` returns it */
export interface AnyNaptrRecord extends NaptrRecord {
  type: 'NAPTR';
}
/** Node's `AnySoaRecord`, as `node:dns` returns it */
export interface AnySoaRecord extends SoaRecord {
  type: 'SOA';
}
/** Node's `AnySrvRecord`, as `node:dns` returns it */
export interface AnySrvRecord extends SrvRecord {
  type: 'SRV';
}
/** Node's `AnyTlsaRecord`, as `node:dns` returns it */
export interface AnyTlsaRecord extends TlsaRecord {
  type: 'TLSA';
}
/** Node's `AnyTxtRecord`, as `node:dns` returns it */
export interface AnyTxtRecord {
  type: 'TXT';
  entries: string[];
}
/** Node's `AnyNsRecord`, as `node:dns` returns it */
export interface AnyNsRecord {
  type: 'NS';
  value: string;
}
/** Node's `AnyPtrRecord`, as `node:dns` returns it */
export interface AnyPtrRecord {
  type: 'PTR';
  value: string;
}
/** Node's `AnyCnameRecord`, as `node:dns` returns it */
export interface AnyCnameRecord {
  type: 'CNAME';
  value: string;
}

/** Node's `AnyRecord`, as `node:dns` returns it */
export type AnyRecord =
  | AnyARecord
  | AnyAaaaRecord
  | AnyCaaRecord
  | AnyCnameRecord
  | AnyMxRecord
  | AnyNaptrRecord
  | AnyNsRecord
  | AnyPtrRecord
  | AnySoaRecord
  | AnySrvRecord
  | AnyTlsaRecord
  | AnyTxtRecord;

type Of<Type extends DnsRecord['type']> = Extract<DnsRecord, { type: Type }>;

// a name as Node writes it: the root is the empty string (a null MX's exchange, an SRV
// target meaning "no such service"), where the library writes `.`
export const nodeName = (name: string): string => (name === '.' ? '' : name);

// a character-string as Node gives it: plain text, with the library's escapes undone
export const nodeText = (field: string): string => utf8Decode(unescapeText(field));

// Node 24 puts `type` on MX, SRV and CAA results, though its types leave it out
export const toCaa = (record: Of<'CAA'>): CaaRecord =>
  ({
    critical: record.flags,
    type: 'CAA',
    [nodeText(record.tag)]: nodeText(record.value),
  }) as CaaRecord;

export const toMx = (record: Of<'MX'>): MxRecord =>
  ({ exchange: nodeName(record.exchange), priority: record.preference, type: 'MX' }) as MxRecord;

export const toNaptr = (record: Of<'NAPTR'>): NaptrRecord => ({
  flags: nodeText(record.flags),
  service: nodeText(record.services),
  regexp: nodeText(record.regexp),
  replacement: nodeName(record.replacement),
  order: record.order,
  preference: record.preference,
});

export const toSoa = (record: Of<'SOA'>): SoaRecord => ({
  nsname: nodeName(record.mname),
  hostmaster: nodeName(record.rname),
  serial: record.serial,
  refresh: record.refresh,
  retry: record.retry,
  expire: record.expire,
  minttl: record.minimum,
});

export const toSrv = (record: Of<'SRV'>): SrvRecord =>
  ({
    name: nodeName(record.target),
    port: record.port,
    priority: record.priority,
    weight: record.weight,
    type: 'SRV',
  }) as SrvRecord;

export function toTlsa(record: Of<'TLSA'>): TlsaRecord {
  const bytes = fromHex(record.certificate);
  return {
    certUsage: record.usage,
    selector: record.selector,
    match: record.matchingType,
    data: bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer,
  };
}

// the order Node lists an ANY answer in: by type, in this order, and within a type as
// the records came
const ANY_ORDER = [
  'A',
  'AAAA',
  'CNAME',
  'MX',
  'NS',
  'TXT',
  'SRV',
  'PTR',
  'NAPTR',
  'SOA',
  'CAA',
  'TLSA',
];

export function toAnyList(records: readonly DnsRecord[], aliasTtl: number): AnyRecord[] {
  return ANY_ORDER.flatMap(type =>
    records.flatMap(record => (record.type === type ? (toAny(record, aliasTtl) ?? []) : []))
  );
}

// one record of an ANY answer, or undefined for a type Node leaves out
function toAny(record: DnsRecord, aliasTtl: number): AnyRecord | undefined {
  switch (record.type) {
    case 'A':
    case 'AAAA':
      return { address: record.address, ttl: Math.min(record.ttl, aliasTtl), type: record.type };
    case 'CNAME':
    case 'NS':
    case 'PTR':
      return { value: nodeName(record.target), type: record.type };
    case 'MX':
      return { ...toMx(record), type: 'MX' };
    case 'TXT':
      return { entries: record.strings.map(nodeText), type: 'TXT' };
    case 'SOA':
      return { ...toSoa(record), type: 'SOA' };
    case 'SRV':
      return { ...toSrv(record), type: 'SRV' };
    case 'NAPTR':
      return { ...toNaptr(record), type: 'NAPTR' };
    case 'CAA':
      return { ...toCaa(record), type: 'CAA' };
    case 'TLSA':
      return { ...toTlsa(record), type: 'TLSA' };
    default:
      return undefined;
  }
}
