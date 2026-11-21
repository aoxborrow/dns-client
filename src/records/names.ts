import { ParseError } from '../errors';
import {
  canonicalName,
  comparableName,
  endsWithRootDot,
  isSubdomain,
  splitName,
  toAsciiName,
} from '../wire/names';
import { formatRecordData } from './format';
import type { FlatRecordInput } from './helpers';
import { parseRecordData } from './parse';
import { recordError } from './problems';
import type { DnsRecord } from './types';

// names in records a person writes: checking them, and writing them relative to a zone
// and back

// ---------------------------------------------------------------------------
// checking a name
// ---------------------------------------------------------------------------

export type NameRole =
  // a name that owns records: one leftmost `*` label is allowed
  | 'owner'
  // a host named inside record data: no wildcard
  | 'target';

// a label as written: visible ASCII, after a Unicode label is converted. Any other byte,
// a space included, is written as an escape (`\032`), as in a zone file. This takes every
// name the DNS can hold, underscore labels and RFC 2317 classless reverse names
// (`0/25.2.0.192.in-addr.arpa`) included; the hostname rules (letters, digits and
// hyphens) are for hosts, not for names in general
const LABEL = /^[\x21-\x7e]+$/;

// a full name in canonical form: ASCII, lowercase, escapes spelled one way, no trailing
// dot. Unicode is converted. `field` names the part of the record the name is in, for the
// problem's values; `what` names it in English, for its detail
export function canonicalHostName(
  name: string,
  role: NameRole,
  field: string,
  what: string
): string {
  const trimmed = name.trim();
  if (trimmed === '') throw recordError('empty-name', { field }, `${what} is empty`);
  if (trimmed === '@') {
    throw recordError(
      'zone-relative-name',
      { field },
      `${what} is "@", which only means something relative to a zone`
    );
  }
  let ascii: string;
  let canonical: string;
  try {
    ascii = toAsciiName(trimmed);
    canonical = comparableName(ascii);
  } catch (error) {
    if (!(error instanceof ParseError)) throw error;
    throw recordError(
      'invalid-name',
      { field, reason: error.message },
      `${what} is not a valid name: ${error.message}`,
      { cause: error }
    );
  }
  if (canonical === '.') return canonical;

  splitName(ascii).forEach((label, index) => {
    if (label === '*') {
      if (role === 'owner' && index === 0) return;
      throw role === 'owner'
        ? recordError(
            'misplaced-wildcard',
            { field },
            `${what} may only have "*" as its first label`
          )
        : recordError('wildcard-target', { field }, `${what} may not be a wildcard`);
    }
    if (!LABEL.test(label)) {
      throw recordError(
        'invalid-label',
        { field, label },
        `${what} has a label with a space or control character, which must be escaped: "${label}"`
      );
    }
  });
  return canonical;
}

// ---------------------------------------------------------------------------
// names relative to a zone
// ---------------------------------------------------------------------------

// one name, as written, to a full name without a trailing dot. A name with a trailing dot
// is already full; any other name is relative to the zone, as in a zone file (RFC 1035
// §5.1), so `www.example.com` in zone `example.com` is `www.example.com.example.com`
function qualifyName(written: string, zone: string): string {
  const text = written.trim();
  if (text === '@') return zone;
  if (text === '.') return '.';
  if (endsWithRootDot(text)) return text.slice(0, -1);
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

const theZone = (zone: string) => canonicalHostName(zone, 'target', 'zone', 'The zone');

// expand names written relative to a zone into full names: in the record's own name, and
// in the names inside its data. `@` is the zone itself, a trailing dot marks a name that
// is already full, and every other name is relative to the zone. The result is what the
// validators take
export function qualify<T extends FlatRecordInput>(input: T, zone: string): T {
  const origin = theZone(zone);
  const type = input.type.trim().toUpperCase();
  const name = qualifyName(input.name, origin);
  if (!HAS_NAMES_IN_DATA.has(type) || input.data.trim().startsWith('\\#')) {
    return { ...input, name };
  }
  const fields = parseRecordData(type, input.data, {
    readName: written => qualifyName(written, origin),
  });
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
// relative to the zone, for a UI or a provider API that wants them short. A name outside
// the zone is written in full, with its trailing dot
export function relativize<T extends FlatRecordInput>(input: T, zone: string): T {
  const origin = theZone(zone);
  const type = input.type.trim().toUpperCase();
  const strip = (written: string) => {
    const text = written.trim();
    return endsWithRootDot(text) && text !== '.' ? text.slice(0, -1) : text;
  };
  const name = relativeName(strip(input.name), origin);
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
