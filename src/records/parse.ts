import { ParseError } from '../errors';
import { typeCode, typeName } from '../protocol/types';
import { formatIpv4, formatIpv6, toHex, utf8Decode } from '../wire/bytes';
import { endsWithRootDot, nameToLabels } from '../wire/names';
import { parseIpv4, parseIpv6 } from './addresses';
import { decodeRecord, isKnownRecordType } from './decode';
import { formatSignatureTime } from './format';
import { recordError } from './problems';
import type { DnsRecord, KnownRecordType, RecordOf, ServiceParams, UnknownRecord } from './types';

// reading presentation format: the text of a record's data, as a zone file or `dig`
// writes it, into the same typed fields the decoders produce. This is the inverse of
// `formatRecordData`. It checks syntax and field widths, which is everything needed to
// put the record on the wire; rules about what a sensible record looks like are the
// validators' job.

// the type-specific fields of a record, without its envelope
export type RecordData<T extends KnownRecordType> = Omit<
  RecordOf<T>,
  'name' | 'class' | 'ttl' | 'type'
>;

// ---------------------------------------------------------------------------
// tokens
// ---------------------------------------------------------------------------

interface Token {
  // the token's bytes: literal characters as UTF-8, `\DDD` escapes as the byte they name
  bytes: number[];
  // the token as written, for fields that are numbers or mnemonics
  raw: string;
  quoted: boolean;
}

const encoder = new TextEncoder();

// split record data into tokens: whitespace separates them, double quotes group one,
// a backslash escapes the next character or a three-digit decimal byte. Parentheses and
// `;` comments, which zone files use to spread a record over lines, are skipped. With
// `innerQuotes`, a quoted run inside a token stays part of it, so a service parameter
// written `key="a value"` is one token (RFC 9460 §2.1)
function tokenize(data: string, { innerQuotes = false } = {}): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  while (i < data.length) {
    const char = data[i];
    if (/\s/.test(char) || char === '(' || char === ')') {
      i += 1;
      continue;
    }
    if (char === ';') {
      while (i < data.length && data[i] !== '\n') i += 1;
      continue;
    }

    const quoted = char === '"';
    const start = i;
    if (quoted) i += 1;
    const bytes: number[] = [];
    let closed = !quoted;
    let inner = false;
    while (i < data.length) {
      const current = data[i];
      if (!quoted && innerQuotes && current === '"') {
        inner = !inner;
        i += 1;
        continue;
      }
      if (quoted ? current === '"' : !inner && /[\s();]/.test(current)) {
        if (quoted) {
          closed = true;
          i += 1;
        }
        break;
      }
      if (current === '\\') {
        const digits = data.slice(i + 1, i + 4);
        if (/^\d{3}$/.test(digits)) {
          if (Number(digits) > 255)
            throw recordError(
              'invalid-escape',
              { escape: `\\${digits}` },
              `Invalid escape \\${digits}`
            );
          bytes.push(Number(digits));
          i += 4;
        } else if (i + 1 < data.length) {
          bytes.push(...encoder.encode(data[i + 1]));
          i += 2;
        } else {
          throw recordError('trailing-backslash', {}, 'Record data ends with a backslash');
        }
        continue;
      }
      // take a whole code point, so a character outside the BMP is not split
      const point = String.fromCodePoint(data.codePointAt(i)!);
      bytes.push(...encoder.encode(point));
      i += point.length;
    }
    if (!closed || inner) throw recordError('unclosed-quote', {}, 'A quoted string is not closed');
    tokens.push({ bytes, raw: data.slice(start, i), quoted });
  }
  return tokens;
}

// a full name as written, without the dot that marks it as absolute
const withoutTrailingDot = (text: string) =>
  text !== '.' && endsWithRootDot(text) ? text.slice(0, -1) : text;

// a cursor over a record's tokens
class Fields {
  private index = 0;

  constructor(
    private readonly tokens: Token[],
    private readonly type: string,
    private readonly readName?: (written: string) => string
  ) {}

  private missing(what: string) {
    return recordError(
      'missing-field',
      { field: what },
      `${this.type} record is missing its ${what}`
    );
  }

  get remaining(): number {
    return this.tokens.length - this.index;
  }

  private next(what: string): Token {
    const token = this.tokens[this.index++];
    if (!token) throw this.missing(what);
    return token;
  }

  // an unquoted word, as written
  word(what: string): string {
    const token = this.next(what);
    if (token.quoted)
      throw recordError('quoted-field', { field: what }, `${what} must not be in quotes`);
    return token.raw;
  }

  uint(what: string, max: number): number {
    const text = this.word(what);
    if (!/^\d+$/.test(text) || Number(text) > max) {
      throw recordError(
        'number-out-of-range',
        { field: what, max, text },
        `${what} must be a whole number from 0 to ${max}, not "${text}"`
      );
    }
    return Number(text);
  }

  u8 = (what: string) => this.uint(what, 0xff);
  u16 = (what: string) => this.uint(what, 0xffff);
  u32 = (what: string) => this.uint(what, 0xffffffff);

  // a domain name, returned without its trailing dot. Any name the wire can carry is
  // accepted, escapes included
  name(what: string): string {
    const text = this.word(what);
    try {
      const name = this.readName ? this.readName(text) : withoutTrailingDot(text);
      nameToLabels(name);
      return name;
    } catch (error) {
      if (error instanceof ParseError) {
        throw recordError(
          'invalid-name',
          { field: what, reason: error.message },
          `${what} is not a valid name: ${error.message}`,
          { cause: error }
        );
      }
      throw error;
    }
  }

  // a <character-string>, quoted or not: at most 255 bytes
  text(what: string): string {
    const token = this.next(what);
    if (token.bytes.length > 255) {
      throw recordError('string-too-long', { field: what }, `${what} is longer than 255 bytes`);
    }
    return utf8Decode(Uint8Array.from(token.bytes));
  }

  // the bytes of a <character-string>
  bytes(what: string): Uint8Array {
    return Uint8Array.from(this.next(what).bytes);
  }

  // every remaining token joined: how zone files write long hex and base64 fields
  private restJoined(what: string): string {
    if (this.remaining === 0) throw this.missing(what);
    let out = '';
    while (this.remaining > 0) out += this.word(what);
    return out;
  }

  hexRest(what: string): string {
    const text = this.restJoined(what);
    if (!/^([0-9a-fA-F]{2})+$/.test(text)) {
      throw recordError('invalid-hex', { field: what }, `${what} is not valid hex`);
    }
    return text.toLowerCase();
  }

  base64Rest(what: string): string {
    return base64(this.restJoined(what), what);
  }

  // the remaining words, e.g. the types in an NSEC bitmap
  words(): string[] {
    const out: string[] = [];
    while (this.remaining > 0) out.push(this.word('value'));
    return out;
  }

  end(): void {
    if (this.remaining > 0) {
      const text = this.tokens[this.index].raw;
      throw recordError(
        'extra-data',
        { text },
        `${this.type} record has unexpected extra data: ${text}`
      );
    }
  }
}

function base64(text: string, what: string): string {
  if (text.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(text)) {
    throw recordError('invalid-base64', { field: what }, `${what} is not valid base64`);
  }
  return text;
}

// ---------------------------------------------------------------------------
// field helpers
// ---------------------------------------------------------------------------

// DNSSEC algorithm mnemonics, as zone files sometimes write them (IANA registry)
const ALGORITHM_MNEMONICS: Record<string, number> = {
  'RSAMD5': 1,
  'DH': 2,
  'DSA': 3,
  'RSASHA1': 5,
  'DSA-NSEC3-SHA1': 6,
  'RSASHA1-NSEC3-SHA1': 7,
  'RSASHA256': 8,
  'RSASHA512': 10,
  'ECC-GOST': 12,
  'ECDSAP256SHA256': 13,
  'ECDSAP384SHA384': 14,
  'ED25519': 15,
  'ED448': 16,
};

// certificate types for CERT (RFC 4398)
const CERTIFICATE_TYPES: Record<string, number> = {
  PKIX: 1,
  SPKI: 2,
  PGP: 3,
  IPKIX: 4,
  ISPKI: 5,
  IPGP: 6,
  ACPKIX: 7,
  IACPKIX: 8,
  URI: 253,
  OID: 254,
};

// a number, or one of the mnemonics in `table`
function numberOrMnemonic(
  fields: Fields,
  what: string,
  max: number,
  table: Record<string, number>
): number {
  const text = fields.word(what);
  if (/^\d+$/.test(text) && Number(text) <= max) return Number(text);
  const known = table[text.toUpperCase()];
  if (known === undefined) {
    throw recordError('unknown-mnemonic', { field: what, text }, `Unknown ${what}: "${text}"`);
  }
  return known;
}

const algorithm = (fields: Fields) =>
  numberOrMnemonic(fields, 'algorithm', 0xff, ALGORITHM_MNEMONICS);

function typeMnemonic(text: string): string {
  try {
    return typeName(typeCode(text));
  } catch {
    throw recordError('unknown-type', { type: text }, `Unknown record type: "${text}"`);
  }
}

// a signature time: YYYYMMDDHHmmSS in UTC, or seconds since 1970
function signatureTime(fields: Fields, what: string): number {
  const text = fields.word(what);
  if (/^\d{14}$/.test(text)) {
    const part = (start: number, length: number) => Number(text.slice(start, start + length));
    const seconds =
      Date.UTC(part(0, 4), part(4, 2) - 1, part(6, 2), part(8, 2), part(10, 2), part(12, 2)) / 1000;
    // a date like February 30th would otherwise be accepted as March 2nd
    if (seconds >= 0 && seconds <= 0xffffffff && formatSignatureTime(seconds) === text)
      return seconds;
    throw recordError(
      'invalid-value',
      { field: what, text },
      `${what} is not a valid time: "${text}"`
    );
  }
  if (/^\d{1,10}$/.test(text) && Number(text) <= 0xffffffff) return Number(text);
  throw recordError(
    'invalid-value',
    { field: what, text },
    `${what} must be YYYYMMDDHHmmSS or seconds since 1970, not "${text}"`
  );
}

const salt = (fields: Fields) => {
  const text = fields.word('salt');
  if (text === '-') return '';
  if (!/^([0-9a-fA-F]{2})+$/.test(text) || text.length > 510)
    throw recordError('invalid-hex', { field: 'salt' }, 'salt is not valid hex');
  return text.toLowerCase();
};

const delegationSigner = (fields: Fields) => ({
  keyTag: fields.u16('key tag'),
  algorithm: algorithm(fields),
  digestType: fields.u8('digest type'),
  digest: fields.hexRest('digest'),
});

const publicKey = (fields: Fields) => ({
  flags: fields.u16('flags'),
  protocol: fields.u8('protocol'),
  algorithm: algorithm(fields),
  publicKey: fields.base64Rest('public key'),
});

const signature = (fields: Fields) => ({
  typeCovered: typeMnemonic(fields.word('type covered')),
  algorithm: algorithm(fields),
  labels: fields.u8('labels'),
  originalTtl: fields.u32('original TTL'),
  signatureExpiration: signatureTime(fields, 'signature expiration'),
  signatureInception: signatureTime(fields, 'signature inception'),
  keyTag: fields.u16('key tag'),
  signerName: fields.name("signer's name"),
  signature: fields.base64Rest('signature'),
});

const target = (fields: Fields) => ({ target: fields.name('target') });

// ---------------------------------------------------------------------------
// LOC (RFC 1876 §3)
// ---------------------------------------------------------------------------

// degrees [minutes [seconds]] and a hemisphere letter
function coordinate(
  fields: Fields,
  what: string,
  limit: number,
  positive: string,
  negative: string
): number {
  const parts: number[] = [];
  for (;;) {
    const text = fields.word(what);
    const upper = text.toUpperCase();
    if (upper === positive || upper === negative) {
      if (parts.length === 0) {
        throw recordError('invalid-value', { field: what, text }, `${what} has no degrees`);
      }
      const [degrees, minutes = 0, seconds = 0] = parts;
      const value = degrees + minutes / 60 + seconds / 3600;
      if (value > limit || minutes >= 60 || seconds >= 60) {
        throw recordError('invalid-value', { field: what, text }, `${what} is out of range`);
      }
      // to the thousandth of an arc second, the precision of the wire format
      const rounded = Math.round(value * 3_600_000) / 3_600_000;
      return upper === positive ? rounded : -rounded;
    }
    // seconds may have up to three decimal places; degrees and minutes are whole
    const pattern = parts.length === 2 ? /^\d+(\.\d{1,3})?$/ : /^\d+$/;
    if (parts.length >= 3 || !pattern.test(text)) {
      throw recordError('invalid-value', { field: what, text }, `${what} is not valid: "${text}"`);
    }
    parts.push(Number(text));
  }
}

// a size or precision in metres, which the wire can only hold as a digit times a power
// of ten centimetres
function locMetres(text: string, what: string): number {
  const match = /^(\d+(?:\.\d{1,2})?)m?$/.exec(text);
  if (!match) {
    throw recordError('invalid-value', { field: what, text }, `${what} is not valid: "${text}"`);
  }
  const centimetres = Math.round(Number(match[1]) * 100);
  const digits = String(centimetres);
  if (centimetres > 0 && (!/^[1-9]0*$/.test(digits) || digits.length > 10)) {
    throw recordError(
      'invalid-value',
      { field: what, text },
      `${what} must be a single digit followed by zeros, in centimetres: "${text}"`
    );
  }
  return centimetres / 100;
}

function location(fields: Fields) {
  const latitude = coordinate(fields, 'latitude', 90, 'N', 'S');
  const longitude = coordinate(fields, 'longitude', 180, 'E', 'W');
  const altitudeText = fields.word('altitude');
  const altitude = /^-?\d+(\.\d{1,2})?m?$/.test(altitudeText)
    ? Number(altitudeText.replace(/m$/, ''))
    : NaN;
  if (Number.isNaN(altitude) || altitude < -100000 || altitude > 42849672.95) {
    throw recordError(
      'invalid-value',
      { field: 'altitude', text: altitudeText },
      `altitude is not valid: "${altitudeText}"`
    );
  }
  // the three sizes are optional, with the defaults RFC 1876 gives
  const optional = (what: string, fallback: number) =>
    fields.remaining > 0 ? locMetres(fields.word(what), what) : fallback;
  return {
    version: 0,
    size: optional('size', 1),
    horizontalPrecision: optional('horizontal precision', 10000),
    verticalPrecision: optional('vertical precision', 10),
    latitude,
    longitude,
    altitude,
  };
}

// ---------------------------------------------------------------------------
// SVCB and HTTPS (RFC 9460 §2.1)
// ---------------------------------------------------------------------------

const SERVICE_PARAM_KEYS: Record<string, number> = {
  'mandatory': 0,
  'alpn': 1,
  'no-default-alpn': 2,
  'port': 3,
  'ipv4hint': 4,
  'ech': 5,
  'ipv6hint': 6,
  'dohpath': 7,
  'ohttp': 8,
};

function serviceParamKey(text: string): number {
  const known = SERVICE_PARAM_KEYS[text];
  if (known !== undefined) return known;
  const generic = /^key(\d{1,5})$/.exec(text);
  if (generic && Number(generic[1]) <= 0xffff) return Number(generic[1]);
  throw recordError(
    'unknown-service-parameter',
    { key: text },
    `Unknown service parameter: "${text}"`
  );
}

// split a list value on its commas, honouring `\,` and `\\`
function listItems(value: string): string[] {
  const items: string[] = [];
  let current = '';
  for (let i = 0; i < value.length; i++) {
    if (value[i] === '\\' && i + 1 < value.length) {
      current += value[++i];
    } else if (value[i] === ',') {
      items.push(current);
      current = '';
    } else {
      current += value[i];
    }
  }
  items.push(current);
  return items;
}

function serviceBinding(fields: Fields, data: string) {
  const priority = fields.u16('priority');
  const targetName = fields.name('target');
  const params: ServiceParams = {};
  const seen = new Set<number>();

  // parameters are `key` or `key=value`; the value may be quoted. Re-tokenize the data so
  // a quoted value stays attached to its key, skipping parentheses and comments as every
  // other type does. Priority and target are plain words, so they are the first two tokens
  for (const { raw } of tokenize(data, { innerQuotes: true }).slice(2)) {
    const equals = raw.indexOf('=');
    const keyText = equals < 0 ? raw : raw.slice(0, equals);
    const key = serviceParamKey(keyText);
    if (seen.has(key)) {
      throw recordError(
        'repeated-service-parameter',
        { key: keyText },
        `Service parameter "${keyText}" appears twice`
      );
    }
    seen.add(key);
    const [valueToken] = equals < 0 ? [] : tokenize(raw.slice(equals + 1));
    const bytes = Uint8Array.from(valueToken?.bytes ?? []);
    const value = utf8Decode(bytes);
    const needsValue = () => {
      if (!valueToken || bytes.length === 0)
        throw recordError('missing-parameter-value', { key: keyText }, `${keyText} needs a value`);
    };
    const noValue = () => {
      if (valueToken) {
        throw recordError(
          'unexpected-parameter-value',
          { key: keyText },
          `${keyText} takes no value`
        );
      }
    };

    switch (key) {
      case 0:
        needsValue();
        params.mandatory = listItems(value).map(item => {
          serviceParamKey(item);
          return item;
        });
        break;
      case 1:
        needsValue();
        params.alpn = listItems(value);
        if (params.alpn.some(id => id.length === 0 || encoder.encode(id).length > 255)) {
          throw recordError(
            'invalid-value',
            { field: 'alpn', text: value },
            'alpn has an empty or over-long protocol name'
          );
        }
        break;
      case 2:
        noValue();
        params.noDefaultAlpn = true;
        break;
      case 3:
        needsValue();
        if (!/^\d+$/.test(value) || Number(value) > 0xffff)
          throw recordError(
            'invalid-value',
            { field: 'port', text: value },
            `port is not valid: "${value}"`
          );
        params.port = Number(value);
        break;
      case 4:
        needsValue();
        params.ipv4Hint = listItems(value).map(item => {
          const address = parseIpv4(item);
          if (!address) {
            throw recordError(
              'invalid-address',
              { field: 'ipv4hint', text: item },
              `ipv4hint has an invalid address: "${item}"`
            );
          }
          return formatIpv4(address);
        });
        break;
      case 5:
        needsValue();
        params.ech = base64(value, 'ech');
        break;
      case 6:
        needsValue();
        params.ipv6Hint = listItems(value).map(item => {
          const address = parseIpv6(item);
          if (!address) {
            throw recordError(
              'invalid-address',
              { field: 'ipv6hint', text: item },
              `ipv6hint has an invalid address: "${item}"`
            );
          }
          return formatIpv6(address);
        });
        break;
      case 7:
        needsValue();
        params.dohPath = value;
        break;
      case 8:
        noValue();
        params.ohttp = true;
        break;
      default:
        params.other = { ...params.other, [key]: toHex(bytes) };
    }
  }
  return { priority, target: targetName, params };
}

// ---------------------------------------------------------------------------
// the parsers
// ---------------------------------------------------------------------------

type Parser = (fields: Fields, data: string) => Record<string, unknown>;

const PARSERS: Record<KnownRecordType, Parser> = {
  A: fields => {
    const text = fields.word('address');
    const address = parseIpv4(text);
    if (!address) {
      throw recordError(
        'invalid-address',
        { field: 'address', text },
        `"${text}" is not an IPv4 address`
      );
    }
    return { address: formatIpv4(address) };
  },
  AAAA: fields => {
    const text = fields.word('address');
    const address = parseIpv6(text);
    if (!address) {
      throw recordError(
        'invalid-address',
        { field: 'address', text },
        `"${text}" is not an IPv6 address`
      );
    }
    return { address: formatIpv6(address) };
  },
  NS: target,
  CNAME: target,
  PTR: target,
  DNAME: target,
  SOA: fields => ({
    mname: fields.name('primary nameserver'),
    rname: fields.name('responsible mailbox'),
    serial: fields.u32('serial'),
    refresh: fields.u32('refresh'),
    retry: fields.u32('retry'),
    expire: fields.u32('expire'),
    minimum: fields.u32('minimum'),
  }),
  MX: fields => ({ preference: fields.u16('preference'), exchange: fields.name('mail server') }),
  TXT: fields => {
    const strings: string[] = [];
    while (fields.remaining > 0) strings.push(fields.text('text'));
    if (strings.length === 0) {
      throw recordError('missing-field', { field: 'text' }, 'TXT record is missing its text');
    }
    return { strings };
  },
  CAA: fields => ({
    flags: fields.u8('flags'),
    tag: fields.word('tag'),
    value: fields.text('value'),
  }),
  TLSA: fields => ({
    usage: fields.u8('usage'),
    selector: fields.u8('selector'),
    matchingType: fields.u8('matching type'),
    certificate: fields.hexRest('certificate data'),
  }),
  DS: delegationSigner,
  CDS: delegationSigner,
  DNSKEY: publicKey,
  CDNSKEY: publicKey,
  KEY: publicKey,
  RRSIG: signature,
  SIG: signature,
  NSEC: fields => ({
    nextDomain: fields.name('next name'),
    types: fields.words().map(typeMnemonic),
  }),
  NSEC3: fields => {
    const head = {
      algorithm: fields.u8('hash algorithm'),
      flags: fields.u8('flags'),
      iterations: fields.u16('iterations'),
      salt: salt(fields),
    };
    const next = fields.word('next hashed name');
    if (!/^[0-9A-Va-v]+$/.test(next))
      throw recordError(
        'invalid-base32hex',
        { field: 'next hashed name' },
        'next hashed name is not valid base32hex'
      );
    return { ...head, nextDomain: next.toUpperCase(), types: fields.words().map(typeMnemonic) };
  },
  NSEC3PARAM: fields => ({
    algorithm: fields.u8('hash algorithm'),
    flags: fields.u8('flags'),
    iterations: fields.u16('iterations'),
    salt: salt(fields),
  }),
  SRV: fields => ({
    priority: fields.u16('priority'),
    weight: fields.u16('weight'),
    port: fields.u16('port'),
    target: fields.name('target'),
  }),
  SVCB: serviceBinding,
  HTTPS: serviceBinding,
  CERT: fields => ({
    certificateType: numberOrMnemonic(fields, 'certificate type', 0xffff, CERTIFICATE_TYPES),
    keyTag: fields.u16('key tag'),
    algorithm: algorithm(fields),
    certificate: fields.base64Rest('certificate'),
  }),
  HINFO: fields => ({ cpu: fields.text('CPU'), os: fields.text('OS') }),
  TSIG: fields => {
    const optionalBase64 = (what: string) => {
      const text = fields.word(what);
      return text === '-' ? '' : base64(text, what);
    };
    return {
      algorithm: fields.name('algorithm'),
      timeSigned: fields.uint('time signed', 0xffffffffffff),
      fudge: fields.u16('fudge'),
      mac: optionalBase64('MAC'),
      originalId: fields.u16('original ID'),
      error: fields.u16('error'),
      otherData: optionalBase64('other data'),
    };
  },
  OPENPGPKEY: fields => ({ key: fields.base64Rest('key') }),
  RP: fields => ({ mbox: fields.name('mailbox'), txt: fields.name('text name') }),
  SSHFP: fields => ({
    algorithm: fields.u8('algorithm'),
    fingerprintType: fields.u8('fingerprint type'),
    fingerprint: fields.hexRest('fingerprint'),
  }),
  URI: fields => ({
    priority: fields.u16('priority'),
    weight: fields.u16('weight'),
    // a URI may be longer than one character-string, so it is not length-checked as one
    target: utf8Decode(fields.bytes('target')),
  }),
  NAPTR: fields => ({
    order: fields.u16('order'),
    preference: fields.u16('preference'),
    flags: fields.text('flags'),
    services: fields.text('services'),
    regexp: fields.text('regular expression'),
    replacement: fields.name('replacement'),
  }),
  LOC: location,
};

// the SVCB-style parsers read their parameters from the data themselves
const SELF_TERMINATING = new Set<string>(['SVCB', 'HTTPS']);

// the RFC 3597 generic form: \# <length> <hex>
function genericData(data: string): Uint8Array | undefined {
  const match = /^\\#\s+(\d+)((?:\s+[0-9a-fA-F]+)*)\s*$/.exec(data.trim());
  if (!match) return undefined;
  const hex = match[2].replace(/\s+/g, '');
  if (hex.length % 2 !== 0 || hex.length / 2 !== Number(match[1])) {
    throw recordError(
      'generic-length-mismatch',
      {},
      'Generic record data does not match its stated length'
    );
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export interface ParseOptions {
  // turn a domain name, as it was written in the data, into the name to store. The
  // default takes it as a full name and drops one trailing dot
  readName?: (written: string) => string;
}

// whether the library can parse this type's own presentation format
export function hasRecordParser(type: string): type is KnownRecordType {
  return Object.hasOwn(PARSERS, type.toUpperCase());
}

// parse a record's data from presentation format into its typed fields.
//
// any type, known or not, may be given in the RFC 3597 generic form (`\# 4 c0000201`). A
// type with no parser of its own can only be given that way, and comes back as hex `data`
export function parseRecordData<T extends KnownRecordType>(
  type: T,
  data: string,
  options?: ParseOptions
): RecordData<T>;
export function parseRecordData(
  type: string,
  data: string,
  options?: ParseOptions
): Record<string, unknown>;
export function parseRecordData(
  type: string,
  data: string,
  options: ParseOptions = {}
): Record<string, unknown> {
  let code: number;
  try {
    code = typeCode(type);
  } catch {
    throw recordError('unknown-type', { type }, `Unknown record type: "${type}"`);
  }
  const mnemonic = typeName(code);
  if (data.trim() === '') throw recordError('no-data', {}, `${mnemonic} record has no data`);

  const generic = genericData(data);
  if (generic) {
    if (!isKnownRecordType(code)) return { data: toHex(generic) };
    try {
      const {
        name: _name,
        type: _type,
        class: _class,
        ttl: _ttl,
        ...fields
      } = decodeRecord({
        name: '.',
        type: code,
        class: 1,
        ttl: 0,
        rdata: generic,
        section: 'answer',
      }) as Exclude<DnsRecord, UnknownRecord>;
      return fields;
    } catch (error) {
      if (!(error instanceof ParseError)) throw error;
      throw recordError(
        'invalid-generic-data',
        { type: mnemonic },
        `Generic data is not a valid ${mnemonic} record`,
        { cause: error }
      );
    }
  }

  if (!hasRecordParser(mnemonic)) {
    throw recordError(
      'generic-form-only',
      { type: mnemonic },
      `${mnemonic} records can only be given in the generic form: \\# <length> <hex>`
    );
  }
  const fields = new Fields(tokenize(data), mnemonic, options.readName);
  const parsed = PARSERS[mnemonic](fields, data);
  if (!SELF_TERMINATING.has(mnemonic)) fields.end();
  return parsed;
}
