import type { DnsRecord } from '../records/types';
import { fromHex } from '../wire/bytes';

// the library's records in the shapes `node:dns` returns them in. The interfaces repeat
// Node's own (`@types/node`'s `dns` module) field for field

export interface RecordWithTtl {
  address: string;
  ttl: number;
}

export interface CaaRecord {
  critical: number;
  issue?: string;
  issuewild?: string;
  iodef?: string;
  contactemail?: string;
  contactphone?: string;
}

export interface MxRecord {
  priority: number;
  exchange: string;
}

export interface NaptrRecord {
  flags: string;
  service: string;
  regexp: string;
  replacement: string;
  order: number;
  preference: number;
}

export interface SoaRecord {
  nsname: string;
  hostmaster: string;
  serial: number;
  refresh: number;
  retry: number;
  expire: number;
  minttl: number;
}

export interface SrvRecord {
  priority: number;
  weight: number;
  port: number;
  name: string;
}

export interface TlsaRecord {
  certUsage: number;
  selector: number;
  match: number;
  data: ArrayBuffer;
}

export interface AnyARecord extends RecordWithTtl {
  type: 'A';
}
export interface AnyAaaaRecord extends RecordWithTtl {
  type: 'AAAA';
}
export interface AnyCaaRecord extends CaaRecord {
  type: 'CAA';
}
export interface AnyMxRecord extends MxRecord {
  type: 'MX';
}
export interface AnyNaptrRecord extends NaptrRecord {
  type: 'NAPTR';
}
export interface AnySoaRecord extends SoaRecord {
  type: 'SOA';
}
export interface AnySrvRecord extends SrvRecord {
  type: 'SRV';
}
export interface AnyTlsaRecord extends TlsaRecord {
  type: 'TLSA';
}
export interface AnyTxtRecord {
  type: 'TXT';
  entries: string[];
}
export interface AnyNsRecord {
  type: 'NS';
  value: string;
}
export interface AnyPtrRecord {
  type: 'PTR';
  value: string;
}
export interface AnyCnameRecord {
  type: 'CNAME';
  value: string;
}

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

// Node 24 puts `type` on MX, SRV and CAA results, though its types leave it out
export const toCaa = (record: Of<'CAA'>): CaaRecord =>
  ({ critical: record.flags, type: 'CAA', [record.tag]: record.value }) as CaaRecord;

export const toMx = (record: Of<'MX'>): MxRecord =>
  ({ exchange: record.exchange, priority: record.preference, type: 'MX' }) as MxRecord;

export const toNaptr = (record: Of<'NAPTR'>): NaptrRecord => ({
  flags: record.flags,
  service: record.services,
  regexp: record.regexp,
  replacement: record.replacement,
  order: record.order,
  preference: record.preference,
});

export const toSoa = (record: Of<'SOA'>): SoaRecord => ({
  nsname: record.mname,
  hostmaster: record.rname,
  serial: record.serial,
  refresh: record.refresh,
  retry: record.retry,
  expire: record.expire,
  minttl: record.minimum,
});

export const toSrv = (record: Of<'SRV'>): SrvRecord =>
  ({
    name: record.target,
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
      return { value: record.target, type: record.type };
    case 'MX':
      return { ...toMx(record), type: 'MX' };
    case 'TXT':
      return { entries: record.strings, type: 'TXT' };
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
