import { ROOT_SERVERS } from './caches/nameservers.js';
import {
  A_RECORD,
  AAAA_RECORD,
  CAA_RECORD,
  CERT_RECORD,
  CNAME_RECORD,
  DNS_RECORD_TYPES,
  DNSKEY_RECORD,
  DS_RECORD,
  KEY_RECORD,
  MX_RECORD,
  NAPTR_RECORD,
  NS_RECORD,
  PTR_RECORD,
  RRSIG_RECORD,
  SIG_RECORD,
  SOA_RECORD,
  SRV_RECORD,
  TLSA_RECORD,
  TXT_RECORD,
  CDNSKEY_RECORD,
  CDS_RECORD,
  DNAME_RECORD,
  NSEC_RECORD,
  NSEC3_RECORD,
  NSEC3PARAM_RECORD,
  TSIG_RECORD,
  HTTPS_RECORD,
  LOC_RECORD,
  OPENPGPKEY_RECORD,
  SSHFP_RECORD,
  SVCB_RECORD,
  URI_RECORD,
} from './constants.js';
import type { DnsRecord, DnsAnswer, FlatDnsRecord } from './types.js';

// flatten records from answers
export function getRecords(answers: DnsAnswer[]): DnsRecord[] {
  return answers.flatMap(answer => answer.records ?? []);
}

// detect DoH server from a string
export function detectDohServer(server: string): boolean {
  server = String(server).trim().toLowerCase();
  return server.startsWith('http') || server.endsWith('/dns-query') || server.endsWith('/resolve');
}

// get a random root server hostname
export function getRandomRootServer(): string {
  const rootServerHosts = Object.keys(ROOT_SERVERS);
  const randomHost = rootServerHosts[Math.floor(Math.random() * rootServerHosts.length)];
  return randomHost; // return hostname, not IP
}

// natural sort comparison function for strings with numeric handling
export function naturalCompare(a: string, b: string): number {
  return a.localeCompare(b, undefined, {
    numeric: true,
    sensitivity: 'accent',
  });
}

// sort array values in natural order
export function naturalSort(array: string[]): string[] {
  return [...array].sort(naturalCompare);
}

// sort object keys naturally (non-recursively)
export function sortObjectKeys(obj: unknown): unknown {
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
    return obj;
  }
  const sortedKeys = Object.keys(obj as Record<string, unknown>).sort(naturalCompare);
  const sortedObj: Record<string, unknown> = {};
  for (const key of sortedKeys) {
    sortedObj[key] = (obj as Record<string, unknown>)[key];
  }
  return sortedObj;
}

// check for empty values: undefined, null, empty string, empty array, 0, false, NaN, empty objects
export function isEmpty(value: unknown): boolean {
  if (!value) {
    return true;
  }
  if (typeof value === 'string') {
    const trimmed = value.trim();
    return trimmed === '' || trimmed === 'null' || trimmed === 'undefined';
  }
  if (Array.isArray(value)) {
    return value.length === 0 || value.every(v => isEmpty(v));
  }
  if (typeof value === 'object') {
    return Object.keys(value as Record<string, unknown>).length === 0;
  }
  return false;
}

// normalize host, remove leading/trailing periods/slashes, etc.
export const normalizeHost = (host: string, removeProtocol = true): string => {
  if (isEmpty(host)) return '';
  // trim spaces, leading/trailing periods, and lowercase
  host = String(host)
    .trim()
    .replace(/^[.]+|[.]+$/g, '')
    .toLowerCase();
  // remove protocol by default
  if (removeProtocol) {
    // strip protocols like http, https, or whois
    host = stripProtocol(host);
  }
  return host
    .replace(/\/$/, '') // remove trailing slash if present
    .replace(/^\.+|\.+$/g, '') // remove leading and trailing periods
    .trim(); // one last trim
};

// strip http, https, or whois protocol from a url
export function stripProtocol(url: string): string {
  // strip only alphabetic protocols followed by ://
  return String(url)
    .trim()
    .replace(/^[a-zA-Z]+:\/\//, '');
}

// strip trailing dot from a string
export function stripTrailingDot(str: string): string {
  return str.endsWith('.') ? str.slice(0, -1) : str;
}

// sanitize string - removes null bytes and other problematic characters
export function sanitizeString(domain: string): string {
  return (
    domain
      // eslint-disable-next-line no-control-regex
      .replace(/\u0000/g, '') // remove null bytes that cause PostgreSQL errors
      // eslint-disable-next-line no-control-regex
      .replace(/[\x00-\x1F\x7F]/g, '') // remove other control characters
      .trim()
  );
}

// query is an IPv4/IPv6 address
export function isValidIp(ip: string): boolean {
  return isValidIpv4(ip) || isValidIpv6(ip);
}

// check for valid ipv4 (surface-level check to differentiate from IPv6)
export const isValidIpv4 = (ip: string) => {
  if (isEmpty(ip)) return false;
  ip = String(ip).trim();

  // reject if contains colons (IPv6 indicator)
  if (ip.includes(':')) {
    return false;
  }

  // extract IP part if CIDR notation
  const ipPart = ip.includes('/') ? ip.split('/')[0] : ip;
  if (!ipPart) return false;

  // must contain dots and only digits, dots
  if (!/^[\d.]+$/.test(ipPart)) {
    return false;
  }

  const parts = ipPart.split('.');
  // require at least 3 octets (as per original requirement)
  if (parts.length < 3 || parts.length > 4) {
    return false;
  }

  // basic validation - check each part is numeric and in range
  for (const part of parts) {
    if (part === '' || !/^\d+$/.test(part)) {
      return false;
    }
    const num = parseInt(part, 10);
    if (isNaN(num) || num < 0 || num > 255) {
      return false;
    }
  }

  return true;
};

// check for valid ipv6 (surface-level check to differentiate from IPv4)
export const isValidIpv6 = (ip: string) => {
  if (isEmpty(ip)) return false;
  ip = String(ip).trim();

  // must contain colons (IPv6 indicator)
  if (!ip.includes(':')) {
    return false;
  }

  // extract IP part if CIDR notation
  const ipPart = ip.includes('/') ? ip.split('/')[0] : ip;
  if (!ipPart) return false;

  // allow hex, colons, dots (for IPv4-mapped)
  if (!/^[0-9a-fA-F:.]+$/i.test(ipPart)) {
    return false;
  }

  const parts = ipPart.split(':');

  // require at least 3 parts (or :: for compression)
  if (parts.length < 3 && ipPart !== '::') {
    return false;
  }

  return true;
};

// flatten a list of DNS records into a list of FlatDnsRecord for display
export function flattenRecords(records: DnsRecord[]): FlatDnsRecord[] {
  const flattened: FlatDnsRecord[] = [];
  if (records) {
    for (const record of records) {
      flattened.push(flattenRecord(record));
    }
  }
  return flattened;
}

// flatten a single DNS record into a FlatDnsRecord for display
export function flattenRecord(record: DnsRecord): FlatDnsRecord {
  // base structure that's common to all records
  const base: FlatDnsRecord = {
    type: record.type,
    name: record.name,
    ttl: record.ttl,
    content: '',
  };

  // set content and priority based on record type
  switch (record.type) {
    case A_RECORD:
      base.content = record.address;
      break;

    case AAAA_RECORD:
      base.content = record.address;
      break;

    case CAA_RECORD:
      base.content = `${record.flags} ${record.tag} "${record.value}"`;
      break;

    case CERT_RECORD:
      base.content = `${record.certificate_type} ${record.key_tag} ${record.algorithm} ${record.certificate}`;
      break;

    case CNAME_RECORD:
      base.content = record.value;
      break;

    case DNSKEY_RECORD:
      base.content = `${record.flags} ${record.protocol} ${record.algorithm} ${record.public_key}`;
      break;

    case DS_RECORD:
      base.content = `${record.key_tag} ${record.algorithm} ${record.digest_type} ${record.digest}`;
      break;

    case HTTPS_RECORD:
      base.content = `${record.svc_priority} ${record.target_name} ${Object.entries(
        record.svc_params
      )
        .map(([key, value]) => `${key}=${String(value)}`)
        .join(' ')}`;
      break;

    case KEY_RECORD:
      base.content = `${record.flags} ${record.protocol} ${record.algorithm} ${record.public_key}`;
      break;

    case MX_RECORD:
      base.content = `${record.priority} ${record.exchange}`;
      break;

    case NAPTR_RECORD:
      base.content = `${record.order} ${record.flags}`;
      break;

    case NS_RECORD:
      base.content = record.value;
      break;

    case PTR_RECORD:
      base.content = record.value;
      break;

    case RRSIG_RECORD:
      base.content = `${record.type_covered} ${record.algorithm} ${record.labels} ${record.original_ttl} ${record.signature_expiration} ${record.signature_inception} ${record.key_tag} ${record.signer_name} ${record.signature}`;
      break;

    case SIG_RECORD:
      base.content = `${record.type_covered} ${record.algorithm} ${record.labels} ${record.original_ttl} ${record.signature_expiration} ${record.signature_inception} ${record.key_tag} ${record.signer_name} ${record.signature}`;
      break;

    case SOA_RECORD:
      base.content = `${record.nsname} ${record.hostmaster} ${record.serial} ${record.refresh} ${record.retry} ${record.expire} ${record.minimum}`;
      break;

    case SRV_RECORD:
      base.content = `${record.priority} ${record.weight} ${record.port} ${record.target}`;
      break;

    case TLSA_RECORD:
      base.content = `${record.usage} ${record.selector} ${record.mtype} ${record.cert}`;
      break;

    case TXT_RECORD:
      base.content = record.value;
      break;

    case CDNSKEY_RECORD:
      base.content = `${record.flags} ${record.protocol} ${record.algorithm} ${record.public_key}`;
      break;

    case CDS_RECORD:
      base.content = `${record.key_tag} ${record.algorithm} ${record.digest_type} ${record.digest}`;
      break;

    case DNAME_RECORD:
      base.content = record.value;
      break;

    case NSEC_RECORD:
      base.content = `${record.next_domain} ${record.rr_types.join(' ')}`;
      break;

    case NSEC3_RECORD:
      base.content = `${record.algorithm} ${record.flags} ${record.iterations} ${record.salt || '-'} ${record.next_domain} ${record.rr_types.join(' ')}`;
      break;

    case NSEC3PARAM_RECORD:
      base.content = `${record.algorithm} ${record.flags} ${record.iterations} ${record.salt || '-'}`;
      break;

    case TSIG_RECORD:
      base.content = `${record.algorithm} ${record.time_signed} ${record.fudge} ${record.mac_size} ${record.mac} ${record.original_id} ${record.error} ${record.other_len} ${record.other_data}`;
      break;

    case SSHFP_RECORD:
      base.content = `${record.algorithm} ${record.fp_type} ${record.fingerprint}`;
      break;

    case SVCB_RECORD:
      base.content = `${record.svc_priority} ${record.target_name} ${Object.entries(
        record.svc_params
      )
        .map(([key, value]) => `${key}=${String(value)}`)
        .join(' ')}`;
      break;

    case URI_RECORD:
      base.content = `${record.priority} ${record.weight} ${record.target}`;
      break;

    case LOC_RECORD:
      base.content = `${record.version} ${record.size} ${record.horiz_pre} ${record.vert_pre} ${record.latitude} ${record.longitude} ${record.altitude}`;
      break;

    case OPENPGPKEY_RECORD:
      base.content = record.key;
      break;

    default: {
      // flatten anything to string with spaces
      const dataParts: string[] = [];
      for (const [key, value] of Object.entries(record)) {
        // exclude standard fields already handled in base
        if (key !== 'type' && key !== 'name' && key !== 'ttl') {
          dataParts.push(String(value));
        }
      }
      base.content = dataParts.join(' ');
      break;
    }
  }

  return base;
}

// deduplicate DNS records, ignoring TTL and other frequently changing fields for comparison
export function deduplicateRecords(records: DnsRecord[]): DnsRecord[] {
  const seenRecords = new Set<string>();
  const uniqueRecords: DnsRecord[] = [];

  // fields to ignore during comparison (by record type)
  const ignoredFields: Record<string, string[]> = {
    SOA: ['serial'], // SOA serial numbers change frequently
    // RRSIG/SIG signature fields are important for DNSSEC validation, so we keep them
    // TSIG: ['time_signed', 'mac'], // TSIG timestamps and MACs change per transaction
    // add more ignored fields as needed for other record types
  };

  // global fields to ignore for all record types
  const globalIgnoredFields = ['ttl']; // TTL values change over time

  for (const record of records) {
    // create a normalized record for comparison by removing ignored fields
    const normalizedRecord = { ...record };
    const recordType = record.type;

    // remove global ignored fields
    for (const field of globalIgnoredFields) {
      delete (normalizedRecord as Record<string, unknown>)[field];
    }

    // remove record-type specific ignored fields
    if (ignoredFields[recordType]) {
      for (const field of ignoredFields[recordType]) {
        delete (normalizedRecord as Record<string, unknown>)[field];
      }
    }

    // create a unique key for this record based on all remaining fields
    const recordKey = JSON.stringify(normalizedRecord, Object.keys(normalizedRecord).sort());

    // only add if we haven't seen this exact record before
    if (!seenRecords.has(recordKey)) {
      seenRecords.add(recordKey);
      uniqueRecords.push(record);
    }
  }
  return uniqueRecords;
}

// sort DNS records in canonical order by name, type, content, ttl
export function sortRecordsCanonical(records: DnsRecord[]): DnsRecord[] {
  // create a map of record types to their order in DNS_RECORD_TYPES
  const recordTypeOrder = DNS_RECORD_TYPES.reduce(
    (acc, recordType, index) => {
      acc[recordType] = index;
      return acc;
    },
    {} as Record<string, number>
  );

  // sort records by canonical order: name, type, content (includes priority), ttl
  return [...records].sort((a, b) => {
    // 1. sort by name using hostname comparison (hierarchy, natural sort)
    const nameCompare = compareHostnamesCanonical(a.name, b.name);
    if (nameCompare !== 0) {
      return nameCompare;
    }

    // 2. sort by type (canonical DNS order)
    const orderA = recordTypeOrder[a.type] ?? Number.MAX_SAFE_INTEGER;
    const orderB = recordTypeOrder[b.type] ?? Number.MAX_SAFE_INTEGER;
    if (orderA !== orderB) {
      return orderA - orderB;
    }

    // 3. sort by content (natural sort, includes priority when applicable)
    const contentA = flattenRecord(a).content;
    const contentB = flattenRecord(b).content;
    const contentCompare = naturalCompare(contentA, contentB);
    if (contentCompare !== 0) {
      return contentCompare;
    }

    // 4. sort by ttl (numeric)
    return (a.ttl || 0) - (b.ttl || 0);
  });
}

// helper function to count subdomain levels (number of dots in domain)
export function countDomainLevels(domain: string): number {
  return (domain.match(/\./g) || []).length;
}

// compare two hostnames using hierarchy and natural sort
// returns: negative if a < b, positive if a > b, 0 if equal
export function compareHostnamesCanonical(hostnameA: string, hostnameB: string): number {
  // 1. sort by domain hierarchy (level count)
  const levelsA = countDomainLevels(hostnameA);
  const levelsB = countDomainLevels(hostnameB);

  // base domains (fewer levels) come first
  if (levelsA !== levelsB) {
    return levelsA - levelsB;
  }

  // 2. use natural sort when levels are equal
  return naturalCompare(hostnameA, hostnameB);
}

// convert an IP address to its reverse DNS format
export function reverseIp(ip: string): string {
  const cleanIp = ip.trim();

  if (isValidIpv4(cleanIp)) {
    // for IPv4: reverse the octets and append .in-addr.arpa
    // e.g. 1.0.0.1 -> 1.0.0.1.in-addr.arpa
    const octets = cleanIp.split('.');
    const reversedOctets = octets.reverse();
    return `${reversedOctets.join('.')}.in-addr.arpa`;
  }

  if (isValidIpv6(cleanIp)) {
    // for IPv6: expand to full form, remove colons, reverse nibbles, and append .ip6.arpa
    // e.g. 2606:4700:4700::1111 -> 1.1.1.1.0.0.0.0.0.0.0.0.0.0.7.4.0.0.7.4.6.0.6.2.ip6.arpa

    // expand IPv6 to full 32-character hex string
    const expandedIpv6 = expandIpv6(cleanIp);
    if (expandedIpv6) {
      // remove colons and reverse the nibbles (each hex character)
      const hexChars = expandedIpv6.replace(/:/g, '').split('').reverse();

      // join with dots and append .ip6.arpa
      return `${hexChars.join('.')}.ip6.arpa`;
    }
  }

  // invalid IP
  return ip;
}

// helper function to expand IPv6 address to full 32-character format
function expandIpv6(ipv6: string): string | null {
  // handle :: expansion
  const parts = ipv6.split('::');
  if (parts.length > 2) return null; // invalid format

  let leftPart = parts[0] ? parts[0].split(':') : [];
  let rightPart = parts[1] ? parts[1].split(':') : [];

  // remove empty strings from splitting
  leftPart = leftPart.filter(part => part !== '');
  rightPart = rightPart.filter(part => part !== '');

  // calculate missing groups
  const totalGroups = 8;
  const missingGroups = totalGroups - leftPart.length - rightPart.length;

  // build the full address
  const fullGroups: string[] = [
    ...leftPart,
    ...(Array(missingGroups).fill('0000') as string[]),
    ...rightPart,
  ];

  // pad each group to 4 characters
  const paddedGroups = fullGroups.map(group => group.padStart(4, '0'));

  return paddedGroups.join(':');
}

// convert a Buffer to uppercase base32hex encoding without padding
export function toBase32Hex(buffer: Buffer): string {
  // base32hex alphabet: 0-9, A-V (32 characters total)
  const alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUV';
  let result = '';
  let bits = 0;
  let value = 0;
  for (let i = 0; i < buffer.length; i++) {
    // add 8 bits from current byte
    value = (value << 8) | buffer[i];
    bits += 8;

    // extract 5-bit chunks and convert to base32hex
    while (bits >= 5) {
      bits -= 5;
      const index = (value >>> bits) & 0x1f;
      result += alphabet[index];
    }
  }
  // handle remaining bits (if any)
  if (bits > 0) {
    // pad with zeros to make a complete 5-bit chunk
    value = value << (5 - bits);
    const index = value & 0x1f;
    result += alphabet[index];
  }
  return result;
}
