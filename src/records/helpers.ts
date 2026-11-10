import { typeCode } from '../protocol/types';
import { canonicalName, compareNames } from '../wire/names';
import { formatRecordData } from './format';
import type { DnsRecord } from './types';

// working with lists of records

// a record reduced to four strings and a number, for showing in a table or writing a
// zone file: the type-specific fields become one `content` string in presentation format
export interface FlatRecord {
  name: string;
  type: string;
  ttl: number;
  content: string;
}

export function flattenRecord(record: DnsRecord): FlatRecord {
  return {
    name: record.name,
    type: record.type,
    ttl: record.ttl,
    content: formatRecordData(record),
  };
}

export function flattenRecords(records: readonly DnsRecord[]): FlatRecord[] {
  return records.map(flattenRecord);
}

// what makes two records the same record: owner (case-insensitively), class, type and
// data. The TTL is not part of a record's identity
function identity(record: DnsRecord): string {
  return `${canonicalName(record.name)}\t${record.class}\t${record.type}\t${formatRecordData(record)}`;
}

// drop records that repeat an earlier one, keeping the first of each. Records that differ
// only in TTL count as the same
export function deduplicateRecords<T extends DnsRecord>(records: readonly T[]): T[] {
  const seen = new Set<string>();
  const out: T[] = [];
  for (const record of records) {
    const key = identity(record);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(record);
  }
  return out;
}

// sort into canonical order: by owner name in DNS order (RFC 4034 §6.1, so a name comes
// before the names below it), then by type code, then by data. Returns a new array
export function sortRecords<T extends DnsRecord>(records: readonly T[]): T[] {
  return [...records].sort((a, b) => {
    const byName = compareNames(a.name, b.name);
    if (byName !== 0) return byName;
    const byType = typeCode(a.type) - typeCode(b.type);
    if (byType !== 0) return byType;
    const left = formatRecordData(a);
    const right = formatRecordData(b);
    return left < right ? -1 : left > right ? 1 : 0;
  });
}
