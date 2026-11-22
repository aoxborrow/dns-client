import { RecordSyntaxError } from '../errors';
import { classCode, className } from '../protocol/classes';
import { typeCode, typeName } from '../protocol/types';
import { unescapeText } from '../wire/bytes';
import { canonicalName, endsWithRootDot, isSubdomain, toAsciiName } from '../wire/names';
import { formatRecordData } from './format';
import type { FlatRecord, FlatRecordInput } from './helpers';
import { canonicalHostName } from './names';
import { hasRecordParser, parseRecordData } from './parse';
import { recordError, recordErrors } from './problems';
import type { RecordClash, RecordProblem } from './problems';
import type { DnsRecord } from './types';

// checking records before they are saved, and comparing records that are spelled
// differently. Everything here is a pure function of the text it is given.
//
// these functions take full names: `www.example.com`, never `www` or `@`. `qualify` turns
// names written relative to a zone into full names first, and `relativize` goes back.
//
// what they accept is what the RFCs and zone files accept. A record that breaks a rule
// throws a RecordSyntaxError whose `problems` list everything found wrong with it, each
// with a code; the checks over sets of records return the same problems as data

// ---------------------------------------------------------------------------
// one record
// ---------------------------------------------------------------------------

export interface ValidateOptions {
  // the zone the record belongs to. When given, a record whose name is outside it is
  // rejected, which also catches a relative name that was never qualified
  zone?: string;
}

const TTL_LIMIT = 0x7fffffff;

// digest lengths in bytes for the DS digest types in use
const DIGEST_BYTES: Record<number, number> = { 1: 20, 2: 32, 4: 48 };

interface Envelope {
  name: string;
  type: string;
  class: string;
  ttl: number;
}

// the problems a check found, or none
function problemsOf(check: () => void): RecordProblem[] {
  try {
    check();
    return [];
  } catch (error) {
    if (!(error instanceof RecordSyntaxError)) throw error;
    return error.problems;
  }
}

// the name, type, class and TTL, each checked. All four are checked before throwing, so
// a record with several things wrong with it reports them together
function envelope(input: FlatRecordInput, options: ValidateOptions): Envelope {
  const head: Envelope = { name: '', type: '', class: 'IN', ttl: input.ttl };
  const problems = [
    ...problemsOf(() => {
      if (!Number.isInteger(input.ttl) || input.ttl < 0 || input.ttl > TTL_LIMIT) {
        throw recordError(
          'invalid-ttl',
          { ttl: input.ttl },
          'TTL must be a whole number from 0 to 2147483647'
        );
      }
    }),
    ...problemsOf(() => {
      head.type = input.type.trim().toUpperCase();
      if (head.type === '') throw recordError('missing-type', {}, 'Record type is empty');
      if (!isWireType(head.type)) {
        throw recordError(
          'unknown-type',
          { type: input.type },
          `Unknown record type: "${input.type}"`
        );
      }
      head.type = typeName(typeCode(head.type));
    }),
    ...problemsOf(() => {
      const written = input.class ?? 'IN';
      try {
        head.class = className(classCode(written));
      } catch {
        throw recordError(
          'unknown-class',
          { class: written },
          `Unknown record class: "${written}"`
        );
      }
    }),
    ...problemsOf(() => {
      head.name = canonicalHostName(input.name, 'owner', 'name', 'The record name');
      if (options.zone === undefined) return;
      const zone = canonicalHostName(options.zone, 'target', 'zone', 'The zone');
      if (!isSubdomain(head.name, zone)) {
        throw recordError(
          'outside-zone',
          { zone: options.zone },
          `${head.name} is not inside the zone ${options.zone}`
        );
      }
    }),
  ];
  if (problems.length > 0) throw recordErrors(problems);
  return head;
}

// the rules on top of syntax, for the types that have them. Names inside the record are
// put in canonical form here as well
function validated(record: DnsRecord): DnsRecord {
  const target = (name: string, field: string, what: string) =>
    canonicalHostName(name, 'target', field, what);
  switch (record.type) {
    case 'CNAME': {
      const to = target(record.target, 'target', 'The CNAME target');
      if (to === record.name) {
        throw recordError('cname-to-self', {}, 'A CNAME cannot point at its own name');
      }
      return { ...record, target: to };
    }
    case 'NS':
    case 'PTR':
    case 'DNAME':
    case 'SRV':
    case 'SVCB':
    case 'HTTPS':
      return { ...record, target: target(record.target, 'target', `The ${record.type} target`) };
    case 'MX': {
      const exchange = target(record.exchange, 'exchange', 'The mail server');
      // a null MX says the domain accepts no mail: preference 0 and the root (RFC 7505)
      if (exchange === '.' && record.preference !== 0) {
        throw recordError(
          'null-mx-preference',
          { preference: record.preference },
          'An MX record pointing at "." must have preference 0'
        );
      }
      return { ...record, exchange };
    }
    case 'NAPTR':
      return {
        ...record,
        replacement: target(record.replacement, 'replacement', 'The NAPTR replacement'),
      };
    case 'SOA':
      return {
        ...record,
        mname: target(record.mname, 'mname', 'The primary nameserver'),
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
        throw recordError(
          'invalid-caa-tag',
          { tag: record.tag },
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
      const actual = record.digest.length / 2;
      if (!removal && expected !== undefined && actual !== expected) {
        throw recordError(
          'digest-length',
          { digestType: record.digestType, expected, actual },
          `A digest of type ${record.digestType} is ${expected} bytes, not ${actual}`
        );
      }
      return record;
    }
    case 'TXT':
      // the strings stay as they were written: where one ends and the next begins means
      // something to DNS-SD (RFC 6763 §6), so two spellings that split the text
      // differently are two different records
      checkTextLength(record.strings);
      return record;
    default:
      return record;
  }
}

const utf8 = new TextEncoder();

// the record's data holds the strings and one length byte for each
function checkTextLength(strings: readonly string[]): void {
  const total = strings.reduce((sum, text) => sum + unescapeText(text).length + 1, 0);
  if (total > 0xffff) {
    throw recordError('data-too-long', {}, 'TXT data is longer than a record can hold');
  }
}

// plain text as the character-strings of a TXT record: one string when it fits in 255
// bytes, as it was written. Longer text cannot be one string, so it is cut into as few
// strings as possible, each at most 255 bytes, never splitting a character
function textStrings(text: string): string[] {
  const strings: string[] = [];
  let current = '';
  let bytes = 0;
  for (const char of text) {
    const size = utf8.encode(char).length;
    if (bytes + size > 255) {
      strings.push(current);
      current = '';
      bytes = 0;
    }
    // a backslash in plain text is itself, so the field escapes it
    current += char === '\\' ? '\\\\' : char;
    bytes += size;
  }
  strings.push(current);
  return strings;
}

// a name inside record data, as written, to its ASCII form without the trailing dot
function fullAsciiName(written: string): string {
  const ascii = toAsciiName(written);
  return ascii !== '.' && endsWithRootDot(ascii) ? ascii.slice(0, -1) : ascii;
}

function parseKnown(head: Envelope, data: string): DnsRecord {
  // TXT data that does not open with a quote is plain text, taken whole as one string. With
  // a quote, it is zone-file syntax, and each quoted string stays a string of its own
  const trimmed = data.trim();
  const plainText = head.type === 'TXT' && !trimmed.startsWith('"') && !trimmed.startsWith('\\#');
  if (plainText && trimmed === '') throw recordError('no-data', {}, 'TXT record has no data');
  const fields = plainText
    ? { strings: textStrings(trimmed) }
    : parseRecordData(head.type, data, { readName: fullAsciiName });
  return validated({ ...head, ...fields } as DnsRecord);
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

// run a check of one record, and mark every problem it finds with the record's name and
// type as they were given
function aboutRecord<T>(input: FlatRecordInput, check: () => T): T {
  try {
    return check();
  } catch (error) {
    if (!(error instanceof RecordSyntaxError)) throw error;
    for (const problem of error.problems) {
      problem.name ??= input.name;
      problem.type ??= input.type;
    }
    throw error;
  }
}

// check one record and return it typed. The name must be a full name. Throws
// RecordSyntaxError with a message that can be shown to the person who typed the record
export function parseRecord(input: FlatRecordInput, options: ValidateOptions = {}): DnsRecord {
  return aboutRecord(input, () => parseKnown(envelope(input, options), input.data));
}

// check one record and return it in canonical spelling: the same shape, with the name,
// type, class and data written the one way this library writes them. Two records are the
// same record exactly when their canonical forms are equal, TTL aside.
//
// a type the wire knows but this library has no parser for has its data trimmed and
// passed through, unless it is in the generic form (`\# 4 c0000201`)
export function canonicalRecord(input: FlatRecordInput, options: ValidateOptions = {}): FlatRecord {
  return aboutRecord(input, () => {
    const head = envelope(input, options);
    const data = input.data.trim();
    if (!hasRecordParser(head.type) && !data.startsWith('\\#')) {
      if (data === '') throw recordError('no-data', {}, `${head.type} record has no data`);
      return { ...head, data };
    }
    return { ...head, data: formatRecordData(parseKnown(head, input.data)) };
  });
}

// ---------------------------------------------------------------------------
// sets of records
// ---------------------------------------------------------------------------

// each record in canonical form, and the problems of the ones that have none
function canonicalAll(records: readonly FlatRecordInput[], options: ValidateOptions) {
  const valid: FlatRecord[] = [];
  const clashes: RecordClash[] = [];
  for (const record of records) {
    try {
      valid.push(canonicalRecord(record, options));
    } catch (error) {
      if (!(error instanceof RecordSyntaxError)) throw error;
      clashes.push(...(error.problems as RecordClash[]));
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
  records: readonly FlatRecordInput[],
  options: ValidateOptions = {}
): RecordClash[] {
  const { valid, clashes } = canonicalAll(records, options);
  const byName = new Map<string, FlatRecord[]>();
  for (const record of valid) {
    const key = `${record.name}\t${record.class}`;
    byName.set(key, [...(byName.get(key) ?? []), record]);
  }

  for (const group of byName.values()) {
    const { name } = group[0];
    const targets = [
      ...new Set(group.filter(record => record.type === 'CNAME').map(record => record.data)),
    ];
    if (targets.length === 0) continue;
    if (targets.length > 1) {
      clashes.push({
        code: 'multiple-cnames',
        values: { targets },
        name,
        type: 'CNAME',
        detail: `${name} has more than one CNAME record`,
      });
    }
    const types = [...new Set(group.map(record => record.type))].filter(
      type => !ALLOWED_BESIDE_CNAME.has(type)
    );
    if (types.length > 0) {
      clashes.push({
        code: 'cname-and-other-data',
        values: { types },
        name,
        type: 'CNAME',
        detail: `${name} has a CNAME record, so it cannot also have ${types.join(', ')} records`,
      });
    }
  }
  return clashes;
}

// what makes two canonical records the same record: everything but the TTL
const identity = (record: FlatRecord) =>
  `${record.name}\t${record.class}\t${record.type}\t${record.data}`;

// records that appear more than once in a set, compared in canonical form with the TTL
// left out. One clash per repeated record
export function findRepeatedRecords(
  records: readonly FlatRecordInput[],
  options: ValidateOptions = {}
): RecordClash[] {
  const { valid, clashes } = canonicalAll(records, options);
  const counts = new Map<string, { record: FlatRecord; count: number }>();
  for (const record of valid) {
    const key = identity(record);
    const entry = counts.get(key);
    if (entry) entry.count += 1;
    else counts.set(key, { record, count: 1 });
  }
  for (const { record, count } of counts.values()) {
    if (count > 1) {
      clashes.push({
        code: 'repeated-record',
        values: { data: record.data, count },
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
// be valid: one RecordSyntaxError lists the problems of every record that is not
export function diffRecords(
  intended: readonly FlatRecordInput[],
  actual: readonly FlatRecordInput[],
  options: DiffOptions = {}
): RecordDiff {
  const key = (record: FlatRecord) =>
    `${identity(record)}${options.compareTtl ? `\t${record.ttl}` : ''}`;
  const want = canonicalAll(intended, options);
  const have = canonicalAll(actual, options);
  const problems = [...want.clashes, ...have.clashes];
  if (problems.length > 0) throw recordErrors(problems);

  const index = (records: FlatRecord[]) => new Map(records.map(record => [key(record), record]));
  const wanted = index(want.valid);
  const had = index(have.valid);
  return {
    missing: [...wanted].filter(([k]) => !had.has(k)).map(([, record]) => record),
    unexpected: [...had].filter(([k]) => !wanted.has(k)).map(([, record]) => record),
  };
}
