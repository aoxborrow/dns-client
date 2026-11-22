import { escapeText, fromHex, latin1Decode, unescapeText } from '../wire/bytes';
import { serviceParamName } from './decode';
import type { DnsRecord, ServiceParams } from './types';

// presentation format: a record's data as text, the way a zone file or `dig` writes it.
// This is the text the parsers read back, so format followed by parse gives the same
// record. Names are written absolute, with a trailing dot. Hex is lowercase.

// a name as it appears in a zone file
const defaultName = (name: string) => (name === '.' ? '.' : `${name}.`);

export interface FormatOptions {
  // how to write a domain name inside the data. The default writes it absolute, with a
  // trailing dot
  formatName?: (name: string) => string;
}

// a <character-string> in quotes: backslash and quote escaped, control characters as \DDD
function quote(text: string): string {
  let out = '"';
  for (const char of text) {
    const code = char.codePointAt(0)!;
    if (char === '"' || char === '\\') out += `\\${char}`;
    else if (code < 0x20 || code === 0x7f) out += `\\${String(code).padStart(3, '0')}`;
    else out += char;
  }
  return `${out}"`;
}

// a <character-string> field in quotes. The field already holds its escapes (`\\` and
// `\DDD`); it is read back to bytes and written again so a stray backslash cannot open an
// escape the field did not mean, then quotes and control characters are escaped
function quoteString(field: string): string {
  let out = '"';
  for (const char of escapeText(unescapeText(field))) {
    const code = char.codePointAt(0)!;
    if (char === '"') out += '\\"';
    else if (code < 0x20 || code === 0x7f) out += `\\${String(code).padStart(3, '0')}`;
    else out += char;
  }
  return `${out}"`;
}

// RRSIG times are written YYYYMMDDHHmmSS in UTC, not as a number (RFC 4034 §3.2)
export function formatSignatureTime(seconds: number): string {
  const date = new Date(seconds * 1000);
  const pad = (value: number, width = 2) => String(value).padStart(width, '0');
  return (
    pad(date.getUTCFullYear(), 4) +
    pad(date.getUTCMonth() + 1) +
    pad(date.getUTCDate()) +
    pad(date.getUTCHours()) +
    pad(date.getUTCMinutes()) +
    pad(date.getUTCSeconds())
  );
}

// a LOC coordinate: degrees, minutes, seconds to the millisecond, and a hemisphere
function coordinate(degrees: number, positive: string, negative: string): string {
  // work in thousandths of an arc second, the unit on the wire, to avoid drift
  const total = Math.round(Math.abs(degrees) * 3_600_000);
  const d = Math.floor(total / 3_600_000);
  const m = Math.floor((total % 3_600_000) / 60_000);
  const s = ((total % 60_000) / 1000).toFixed(3);
  return `${d} ${m} ${s} ${degrees < 0 ? negative : positive}`;
}

const metres = (value: number) => `${Number.isInteger(value) ? value : value.toFixed(2)}m`;

// a list value inside a service parameter: commas and backslashes in an item are escaped
const listItem = (item: string) => item.replace(/\\/g, '\\\\').replace(/,/g, '\\,');

// service parameters in ascending key order, as RFC 9460 §2.1 writes them
function serviceParams(params: ServiceParams): string[] {
  const out: [number, string][] = [];
  if (params.mandatory) out.push([0, `mandatory=${params.mandatory.join(',')}`]);
  if (params.alpn) out.push([1, `alpn=${quote(params.alpn.map(listItem).join(','))}`]);
  if (params.noDefaultAlpn) out.push([2, 'no-default-alpn']);
  if (params.port !== undefined) out.push([3, `port=${params.port}`]);
  if (params.ipv4Hint) out.push([4, `ipv4hint=${params.ipv4Hint.join(',')}`]);
  if (params.ech !== undefined) out.push([5, `ech=${quote(params.ech)}`]);
  if (params.ipv6Hint) out.push([6, `ipv6hint=${params.ipv6Hint.join(',')}`]);
  if (params.dohPath !== undefined) out.push([7, `dohpath=${quote(params.dohPath)}`]);
  if (params.ohttp) out.push([8, 'ohttp']);
  for (const [key, hex] of Object.entries(params.other ?? {})) {
    const value = fromHex(hex);
    out.push([
      Number(key),
      value.length
        ? `${serviceParamName(Number(key))}=${quote(latin1Decode(value))}`
        : serviceParamName(Number(key)),
    ]);
  }
  return out.sort((a, b) => a[0] - b[0]).map(([, text]) => text);
}

// the data of a record in presentation format: everything after the type on a zone-file line
export function formatRecordData(record: DnsRecord, options: FormatOptions = {}): string {
  const absolute = options.formatName ?? defaultName;
  switch (record.type) {
    case 'A':
    case 'AAAA':
      return record.address;
    case 'NS':
    case 'CNAME':
    case 'PTR':
    case 'DNAME':
      return absolute(record.target);
    case 'SOA':
      return [
        absolute(record.mname),
        absolute(record.rname),
        record.serial,
        record.refresh,
        record.retry,
        record.expire,
        record.minimum,
      ].join(' ');
    case 'MX':
      return `${record.preference} ${absolute(record.exchange)}`;
    case 'TXT':
      return record.strings.map(quoteString).join(' ');
    case 'CAA':
      return `${record.flags} ${record.tag} ${quoteString(record.value)}`;
    case 'TLSA':
      return `${record.usage} ${record.selector} ${record.matchingType} ${record.certificate}`;
    case 'DS':
    case 'CDS':
      return `${record.keyTag} ${record.algorithm} ${record.digestType} ${record.digest}`;
    case 'DNSKEY':
    case 'CDNSKEY':
    case 'KEY':
      return `${record.flags} ${record.protocol} ${record.algorithm} ${record.publicKey}`;
    case 'RRSIG':
    case 'SIG':
      return [
        record.typeCovered,
        record.algorithm,
        record.labels,
        record.originalTtl,
        formatSignatureTime(record.signatureExpiration),
        formatSignatureTime(record.signatureInception),
        record.keyTag,
        absolute(record.signerName),
        record.signature,
      ].join(' ');
    case 'NSEC':
      return [absolute(record.nextDomain), ...record.types].join(' ');
    case 'NSEC3':
      return [
        record.algorithm,
        record.flags,
        record.iterations,
        record.salt || '-',
        record.nextDomain,
        ...record.types,
      ].join(' ');
    case 'NSEC3PARAM':
      return `${record.algorithm} ${record.flags} ${record.iterations} ${record.salt || '-'}`;
    case 'SRV':
      return `${record.priority} ${record.weight} ${record.port} ${absolute(record.target)}`;
    case 'SVCB':
    case 'HTTPS':
      return [record.priority, absolute(record.target), ...serviceParams(record.params)].join(' ');
    case 'CERT':
      return `${record.certificateType} ${record.keyTag} ${record.algorithm} ${record.certificate}`;
    case 'HINFO':
      return `${quoteString(record.cpu)} ${quoteString(record.os)}`;
    case 'TSIG':
      return [
        absolute(record.algorithm),
        record.timeSigned,
        record.fudge,
        record.mac || '-',
        record.originalId,
        record.error,
        record.otherData || '-',
      ].join(' ');
    case 'OPENPGPKEY':
      return record.key;
    case 'RP':
      return `${absolute(record.mbox)} ${absolute(record.txt)}`;
    case 'SSHFP':
      return `${record.algorithm} ${record.fingerprintType} ${record.fingerprint}`;
    case 'URI':
      return `${record.priority} ${record.weight} ${quoteString(record.target)}`;
    case 'NAPTR':
      return [
        record.order,
        record.preference,
        quoteString(record.flags),
        quoteString(record.services),
        quoteString(record.regexp),
        absolute(record.replacement),
      ].join(' ');
    case 'LOC':
      return [
        coordinate(record.latitude, 'N', 'S'),
        coordinate(record.longitude, 'E', 'W'),
        `${record.altitude.toFixed(2)}m`,
        metres(record.size),
        metres(record.horizontalPrecision),
        metres(record.verticalPrecision),
      ].join(' ');
    default:
      // the RFC 3597 generic form: \# <length> <hex>
      return `\\# ${record.data.length / 2}${record.data ? ` ${record.data}` : ''}`;
  }
}

// a whole zone-file line: owner, TTL, class, type and data, separated by tabs
export function formatRecord(record: DnsRecord): string {
  return [
    defaultName(record.name),
    record.ttl,
    record.class,
    record.type,
    formatRecordData(record),
  ].join('\t');
}
