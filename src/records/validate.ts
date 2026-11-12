import { ParseError, RecordSyntaxError } from '../errors';
import { className } from '../protocol/classes';
import { typeCode, typeName } from '../protocol/types';
import {
  canonicalName,
  endsWithRootDot,
  isSubdomain,
  nameToLabels,
  splitName,
  toAsciiName,
} from '../wire/names';
import { formatRecordData } from './format';
import type { FlatRecord } from './helpers';
import { hasRecordParser, parseRecordData } from './parse';
import type { DnsRecord } from './types';

// checking records before they are saved, and comparing records that are spelled
// differently. Everything here is a pure function of the text it is given.
//
// these functions take full names: `www.example.com`, never `www` or `@`. `qualify` turns
// names written relative to a zone into full names first, and `relativize` goes back.

// ---------------------------------------------------------------------------
// names
// ---------------------------------------------------------------------------

type NameRole =
  // a name that owns records: one leftmost `*` label is allowed
  | 'owner'
  // a host named inside record data: no wildcard
  | 'target';

const LABEL = /^[a-z0-9_-]+$/;

// a full name in canonical form: ASCII, lowercase, no trailing dot. Unicode is converted,
// and the labels must be made of letters, digits, hyphens and underscores
function canonicalHostName(name: string, role: NameRole, what: string): string {
  const trimmed = name.trim();
  if (trimmed === '') throw new RecordSyntaxError(`${what} is empty`);
  if (trimmed === '@') {
    throw new RecordSyntaxError(`${what} is "@", which only means something relative to a zone`);
  }
  let ascii: string;
  try {
    ascii = canonicalName(toAsciiName(trimmed));
    nameToLabels(ascii);
  } catch (error) {
    if (!(error instanceof ParseError)) throw error;
    throw new RecordSyntaxError(`${what} is not a valid name: ${error.message}`, { cause: error });
  }
  if (ascii === '.') return ascii;

  splitName(ascii).forEach((label, index) => {
    if (label === '*') {
      if (role === 'owner' && index === 0) return;
      throw new RecordSyntaxError(
        role === 'owner'
          ? `${what} may only have "*" as its first label`
          : `${what} may not be a wildcard`
      );
    }
    if (!LABEL.test(label)) {
      throw new RecordSyntaxError(
        `${what} has a label that is not letters, digits, hyphens or underscores: "${label}"`
      );
    }
  });
  return ascii;
}

// ---------------------------------------------------------------------------
// one record
// ---------------------------------------------------------------------------

export interface ValidateOptions {
  // the zone the record belongs to. When given, a record whose name is outside it is
  // rejected, which also catches a relative name that was never qualified
  zone?: string;
}

const TTL_LIMIT = 0x7fffffff;

// provider features that look like record types but never appear on the wire: the
// provider's nameserver resolves the target and answers with A and AAAA records
const ALIAS_TYPES = new Set(['ALIAS', 'ANAME']);

// digest lengths in bytes for the DS digest types in use
const DIGEST_BYTES: Record<number, number> = { 1: 20, 2: 32, 4: 48 };

interface Envelope {
  name: string;
  type: string;
  ttl: number;
}

function envelope(input: FlatRecord, options: ValidateOptions): Envelope {
  if (!Number.isInteger(input.ttl) || input.ttl < 0 || input.ttl > TTL_LIMIT) {
    throw new RecordSyntaxError('TTL must be a whole number from 0 to 2147483647');
  }
  const type = input.type.trim().toUpperCase();
  if (type === '') throw new RecordSyntaxError('Record type is empty');
  const name = canonicalHostName(input.name, 'owner', 'The record name');
  if (
    options.zone !== undefined &&
    !isSubdomain(name, canonicalHostName(options.zone, 'target', 'The zone'))
  ) {
    throw new RecordSyntaxError(`${name} is not inside the zone ${options.zone}`);
  }
  return { name, type, ttl: input.ttl };
}

// the rules on top of syntax, for the types that have them. Names inside the record are
// put in canonical form here as well
function validated(record: DnsRecord): DnsRecord {
  const target = (name: string, what: string) => canonicalHostName(name, 'target', what);
  switch (record.type) {
    case 'CNAME': {
      const to = target(record.target, 'The CNAME target');
      if (to === record.name) throw new RecordSyntaxError('A CNAME cannot point at its own name');
      return { ...record, target: to };
    }
    case 'NS':
    case 'PTR':
    case 'DNAME':
      return { ...record, target: target(record.target, `The ${record.type} target`) };
    case 'MX': {
      const exchange = target(record.exchange, 'The mail server');
      // a null MX says the domain accepts no mail: preference 0 and the root (RFC 7505)
      if (exchange === '.' && record.preference !== 0) {
        throw new RecordSyntaxError('An MX record pointing at "." must have preference 0');
      }
      return { ...record, exchange };
    }
    case 'SRV':
      return { ...record, target: target(record.target, 'The SRV target') };
    case 'SVCB':
    case 'HTTPS':
      return { ...record, target: target(record.target, `The ${record.type} target`) };
    case 'NAPTR':
      return { ...record, replacement: target(record.replacement, 'The NAPTR replacement') };
    case 'SOA':
      return {
        ...record,
        mname: target(record.mname, 'The primary nameserver'),
        // a mailbox written as a name: the part before the first dot may contain escapes
        rname: canonicalName(record.rname),
      };
    case 'RP':
      return { ...record, mbox: canonicalName(record.mbox), txt: canonicalName(record.txt) };
    case 'RRSIG':
    case 'SIG':
      return { ...record, signerName: canonicalName(record.signerName) };
    case 'CAA': {
      // letters and digits only, and tags are matched case-insensitively (RFC 8659 §4.1)
      if (!/^[A-Za-z0-9]+$/.test(record.tag)) {
        throw new RecordSyntaxError(
          `The CAA tag may only contain letters and digits: "${record.tag}"`
        );
      }
      return { ...record, tag: record.tag.toLowerCase() };
    }
    case 'DS':
    case 'CDS': {
      // CDS "0 0 0 00" asks the parent to remove the DS records (RFC 8078 §4)
      const removal = record.type === 'CDS' && record.algorithm === 0 && record.digest === '00';
      const expected = DIGEST_BYTES[record.digestType];
      if (!removal && expected !== undefined && record.digest.length !== expected * 2) {
        throw new RecordSyntaxError(
          `A digest of type ${record.digestType} is ${expected} bytes, not ${record.digest.length / 2}`
        );
      }
      return record;
    }
    case 'TXT':
      return { ...record, strings: textStrings(record.strings.join('')) };
    default:
      return record;
  }
}

const utf8 = new TextEncoder();

// text as the character-strings of a TXT record: as few as possible, each at most 255
// bytes, never splitting a character. Where the boundaries fall carries no meaning to the
// things that read TXT records, which join the strings, so the canonical form always
// splits the same way
function textStrings(text: string): string[] {
  const strings: string[] = [];
  let current = '';
  let bytes = 0;
  let total = 0;
  for (const char of text) {
    const size = utf8.encode(char).length;
    if (bytes + size > 255) {
      strings.push(current);
      current = '';
      bytes = 0;
    }
    current += char;
    bytes += size;
    total += size;
  }
  strings.push(current);
  // the record's data holds the strings and one length byte for each
  if (total + strings.length > 0xffff)
    throw new RecordSyntaxError('TXT data is longer than a record can hold');
  return strings;
}

// a name inside record data, as written, to its ASCII form without the trailing dot
function fullAsciiName(written: string): string {
  const ascii = toAsciiName(written);
  return ascii !== '.' && endsWithRootDot(ascii) ? ascii.slice(0, -1) : ascii;
}

function parseKnown(head: Envelope, data: string): DnsRecord {
  // TXT data that does not open with a quote is plain text, taken whole: this is how
  // provider dashboards and APIs take it. With a quote, it is zone-file syntax
  const plainText =
    head.type === 'TXT' && !data.trim().startsWith('"') && !data.trim().startsWith('\\#');
  const fields = plainText
    ? { strings: [data.trim()] }
    : parseRecordData(head.type, data, { readName: fullAsciiName });
  if (plainText && data.trim() === '') throw new RecordSyntaxError('TXT record has no data');
  return validated({
    name: head.name,
    type: typeName(typeCode(head.type)),
    class: className(1),
    ttl: head.ttl,
    ...fields,
  } as DnsRecord);
}

// whether a type string is one the wire knows: a mnemonic or the generic TYPEnnn form
function isWireType(type: string): boolean {
  try {
    typeCode(type);
    return true;
  } catch {
    return false;
  }
}

// check one record and return it typed. The name must be a full name. Throws
// RecordSyntaxError with a message that can be shown to the person who typed the record
export function parseRecord(input: FlatRecord, options: ValidateOptions = {}): DnsRecord {
  const head = envelope(input, options);
  if (!isWireType(head.type)) {
    throw new RecordSyntaxError(
      ALIAS_TYPES.has(head.type)
        ? `${head.type} is a provider feature, not a DNS record type, so it has no fields to parse`
        : `Unknown record type: "${input.type}"`
    );
  }
  return parseKnown(head, input.data);
}

// check one record and return it in canonical spelling: the same shape, with the name,
// type and data written the one way this library writes them. Two records are the same
// record exactly when their canonical forms are equal, TTL aside.
//
// ALIAS and ANAME are accepted with a target name as data. Any other type the library
// does not know has its data trimmed and passed through, so a provider-specific type
// still round-trips
export function canonicalRecord(input: FlatRecord, options: ValidateOptions = {}): FlatRecord {
  const head = envelope(input, options);
  if (ALIAS_TYPES.has(head.type)) {
    const to = canonicalHostName(input.data, 'target', `The ${head.type} target`);
    if (to === head.name) throw new RecordSyntaxError(`${head.type} cannot point at its own name`);
    return { ...head, data: to === '.' ? '.' : `${to}.` };
  }
  if (
    !isWireType(head.type) ||
    (!hasRecordParser(head.type) && !input.data.trim().startsWith('\\#'))
  ) {
    const data = input.data.trim();
    if (data === '') throw new RecordSyntaxError(`${head.type} record has no data`);
    return { ...head, data };
  }
  const record = parseKnown(head, input.data);
  return { name: head.name, type: record.type, ttl: head.ttl, data: formatRecordData(record) };
}

// ---------------------------------------------------------------------------
// names relative to a zone
// ---------------------------------------------------------------------------

export interface QualifyOptions {
  // how to read a name with no trailing dot that already ends in the zone.
  // 'absolute' (the default) takes `www.example.com` in zone `example.com` as it stands,
  // which is how most provider APIs write names. 'relative' appends the zone to it, as a
  // zone file would, giving `www.example.com.example.com`
  namesEndingInZone?: 'absolute' | 'relative';
}

// one name, as written, to a full name without a trailing dot
function qualifyName(written: string, zone: string, options: QualifyOptions): string {
  const text = written.trim();
  if (text === '@') return zone;
  if (text === '.') return '.';
  // a trailing dot says the name is already complete
  if (endsWithRootDot(text)) return text.slice(0, -1);
  if (
    (options.namesEndingInZone ?? 'absolute') === 'absolute' &&
    isSubdomain(toAsciiName(text), zone)
  ) {
    return text;
  }
  return zone === '.' ? text : `${text}.${zone}`;
}

// the types whose data is nothing but names and numbers, where a name can be relative
const HAS_NAMES_IN_DATA = new Set([
  'NS',
  'CNAME',
  'PTR',
  'DNAME',
  'MX',
  'SRV',
  'SOA',
  'RP',
  'NAPTR',
  'SVCB',
  'HTTPS',
  'NSEC',
  'RRSIG',
  'SIG',
]);

// expand names written relative to a zone into full names: in the record's own name, and
// in the names inside its data. `@` is the zone itself, and a trailing dot marks a name
// that is already full. The result is what the validators take
export function qualify(input: FlatRecord, zone: string, options: QualifyOptions = {}): FlatRecord {
  const origin = canonicalHostName(zone, 'target', 'The zone');
  const type = input.type.trim().toUpperCase();
  const name = qualifyName(input.name, origin, options);
  const readName = (written: string) => qualifyName(written, origin, options);

  if (ALIAS_TYPES.has(type)) {
    const to = readName(input.data);
    return { ...input, name, data: to === '.' ? '.' : `${to}.` };
  }
  if (!HAS_NAMES_IN_DATA.has(type) || input.data.trim().startsWith('\\#')) {
    return { ...input, name };
  }
  const fields = parseRecordData(type, input.data, { readName });
  const record = { name, type, class: 'IN', ttl: input.ttl, ...fields } as DnsRecord;
  return { ...input, name, data: formatRecordData(record) };
}

// one full name, written relative to a zone: `@` for the zone, the labels in front of it
// for a name inside it, and the full name with a trailing dot for a name outside it
function relativeName(name: string, zone: string): string {
  if (name === '.') return '.';
  if (canonicalName(name) === zone) return '@';
  if (zone !== '.' && isSubdomain(name, zone)) {
    return splitName(name)
      .slice(0, splitName(name).length - splitName(zone).length)
      .join('.');
  }
  return `${name}.`;
}

// the reverse of `qualify`: write the record's name and the names inside its data
// relative to the zone, for a UI or a provider API that wants them short
export function relativize(input: FlatRecord, zone: string): FlatRecord {
  const origin = canonicalHostName(zone, 'target', 'The zone');
  const type = input.type.trim().toUpperCase();
  const strip = (written: string) => {
    const text = written.trim();
    return endsWithRootDot(text) && text !== '.' ? text.slice(0, -1) : text;
  };
  const name = relativeName(strip(input.name), origin);

  if (ALIAS_TYPES.has(type)) {
    return { ...input, name, data: relativeName(strip(input.data), origin) };
  }
  if (!HAS_NAMES_IN_DATA.has(type) || input.data.trim().startsWith('\\#')) {
    return { ...input, name };
  }
  const fields = parseRecordData(type, input.data);
  const record = {
    name: strip(input.name),
    type,
    class: 'IN',
    ttl: input.ttl,
    ...fields,
  } as DnsRecord;
  return {
    ...input,
    name,
    data: formatRecordData(record, { formatName: full => relativeName(full, origin) }),
  };
}

// ---------------------------------------------------------------------------
// sets of records
// ---------------------------------------------------------------------------

// something wrong with a set of records. `detail` can be shown to a person
export interface RecordClash {
  name: string;
  type: string;
  detail: string;
}

// each record in canonical form, or the reason it has none
function canonicalAll(records: readonly FlatRecord[], options: ValidateOptions) {
  const valid: FlatRecord[] = [];
  const clashes: RecordClash[] = [];
  for (const record of records) {
    try {
      valid.push(canonicalRecord(record, options));
    } catch (error) {
      if (!(error instanceof RecordSyntaxError)) throw error;
      clashes.push({ name: record.name, type: record.type, detail: error.message });
    }
  }
  return { valid, clashes };
}

// the types that may share a name with a CNAME: the DNSSEC records that sign it and
// prove it (RFC 4034 §2.5 and §4)
const ALLOWED_BESIDE_CNAME = new Set(['CNAME', 'RRSIG', 'NSEC', 'NSEC3']);

// the alias rule for a set of records that will exist together: a name may have at most
// one CNAME, and a name with a CNAME may have nothing else. A record that is not valid on
// its own is reported too. This says what is wrong, not which change to make first
export function findCnameConflicts(
  records: readonly FlatRecord[],
  options: ValidateOptions = {}
): RecordClash[] {
  const { valid, clashes } = canonicalAll(records, options);
  const byName = new Map<string, FlatRecord[]>();
  for (const record of valid) byName.set(record.name, [...(byName.get(record.name) ?? []), record]);

  for (const [name, group] of byName) {
    const cnames = group.filter(record => record.type === 'CNAME');
    if (cnames.length === 0) continue;
    if (new Set(cnames.map(record => record.data)).size > 1) {
      clashes.push({ name, type: 'CNAME', detail: `${name} has more than one CNAME record` });
    }
    const others = [...new Set(group.map(record => record.type))].filter(
      type => !ALLOWED_BESIDE_CNAME.has(type)
    );
    if (others.length > 0) {
      clashes.push({
        name,
        type: 'CNAME',
        detail: `${name} has a CNAME record, so it cannot also have ${others.join(', ')} records`,
      });
    }
  }
  return clashes;
}

// records that appear more than once in a set, compared in canonical form with the TTL
// left out. One clash per repeated record
export function findRepeatedRecords(
  records: readonly FlatRecord[],
  options: ValidateOptions = {}
): RecordClash[] {
  const { valid, clashes } = canonicalAll(records, options);
  const counts = new Map<string, { record: FlatRecord; count: number }>();
  for (const record of valid) {
    const key = `${record.name}\t${record.type}\t${record.data}`;
    const entry = counts.get(key);
    if (entry) entry.count += 1;
    else counts.set(key, { record, count: 1 });
  }
  for (const { record, count } of counts.values()) {
    if (count > 1) {
      clashes.push({
        name: record.name,
        type: record.type,
        detail: `${record.name} ${record.type} ${record.data} appears ${count} times`,
      });
    }
  }
  return clashes;
}

export interface RecordDiff {
  // in `intended` but not in `actual`
  missing: FlatRecord[];
  // in `actual` but not in `intended`
  unexpected: FlatRecord[];
}

export interface DiffOptions extends ValidateOptions {
  // count a different TTL as a different record. Off by default: a resolver's answer
  // carries the time left in its cache, not the TTL that was set
  compareTtl?: boolean;
}

// compare two sets of records in canonical form: what was intended, and what is actually
// there (for example, what a resolver returned, through `flattenRecords`). Both sets must
// be valid; an invalid record throws
export function diffRecords(
  intended: readonly FlatRecord[],
  actual: readonly FlatRecord[],
  options: DiffOptions = {}
): RecordDiff {
  const key = (record: FlatRecord) =>
    `${record.name}\t${record.type}\t${record.data}${options.compareTtl ? `\t${record.ttl}` : ''}`;
  const index = (records: readonly FlatRecord[]) => {
    const map = new Map<string, FlatRecord>();
    for (const record of records) {
      const canonical = canonicalRecord(record, options);
      map.set(key(canonical), canonical);
    }
    return map;
  };
  const want = index(intended);
  const have = index(actual);
  return {
    missing: [...want].filter(([k]) => !have.has(k)).map(([, record]) => record),
    unexpected: [...have].filter(([k]) => !want.has(k)).map(([, record]) => record),
  };
}
