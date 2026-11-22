import { ParseError } from '../errors';

// byte helpers on Uint8Array, so nothing in the codec needs Buffer

export function readU16(bytes: Uint8Array, offset: number): number {
  return (bytes[offset] << 8) | bytes[offset + 1];
}

export function readU32(bytes: Uint8Array, offset: number): number {
  // `>>> 0` keeps the result unsigned; a plain shift would go negative past 2^31
  return (
    ((bytes[offset] << 24) |
      (bytes[offset + 1] << 16) |
      (bytes[offset + 2] << 8) |
      bytes[offset + 3]) >>>
    0
  );
}

export function writeU16(bytes: Uint8Array, offset: number, value: number): void {
  bytes[offset] = (value >>> 8) & 0xff;
  bytes[offset + 1] = value & 0xff;
}

export function writeU32(bytes: Uint8Array, offset: number, value: number): void {
  bytes[offset] = (value >>> 24) & 0xff;
  bytes[offset + 1] = (value >>> 16) & 0xff;
  bytes[offset + 2] = (value >>> 8) & 0xff;
  bytes[offset + 3] = value & 0xff;
}

export function concatBytes(chunks: readonly Uint8Array[]): Uint8Array {
  let length = 0;
  for (const chunk of chunks) length += chunk.length;
  const out = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

// one character per byte, for text that is ASCII by definition (labels, mnemonics)
export function latin1Decode(bytes: Uint8Array): string {
  let out = '';
  for (const byte of bytes) out += String.fromCharCode(byte);
  return out;
}

export function latin1Encode(text: string): Uint8Array {
  const out = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) out[i] = text.charCodeAt(i) & 0xff;
  return out;
}

const HEX = '0123456789abcdef';

// lowercase hex
export function toHex(bytes: Uint8Array): string {
  let out = '';
  for (const byte of bytes) out += HEX[byte >> 4] + HEX[byte & 0x0f];
  return out;
}

// standard base64 with padding
export function toBase64(bytes: Uint8Array): string {
  return btoa(latin1Decode(bytes));
}

// base64url without padding, as RFC 8484 §4.1 wants a query in a DoH URL
export function toBase64Url(bytes: Uint8Array): string {
  return toBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

const BASE32HEX = '0123456789ABCDEFGHIJKLMNOPQRSTUV';

// base32 with the extended hex alphabet and no padding (RFC 4648 §7), as NSEC3 uses it
export function toBase32Hex(bytes: Uint8Array): string {
  let out = '';
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32HEX[(buffer >>> (bits - 5)) & 0x1f];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32HEX[(buffer << (5 - bits)) & 0x1f];
  return out;
}

const utf8 = new TextDecoder('utf-8');

// text for people: UTF-8, with anything undecodable replaced rather than thrown
export function utf8Decode(bytes: Uint8Array): string {
  return utf8.decode(bytes);
}

export function formatIpv4(bytes: Uint8Array): string {
  return `${bytes[0]}.${bytes[1]}.${bytes[2]}.${bytes[3]}`;
}

// the canonical text form of RFC 5952: lowercase, no leading zeros, and the longest run
// of two or more zero groups (the first, on a tie) written as `::`
export function formatIpv6(bytes: Uint8Array): string {
  const groups: number[] = [];
  for (let i = 0; i < 16; i += 2) groups.push(readU16(bytes, i));

  let bestStart = -1;
  let bestLength = 0;
  for (let start = 0; start < 8;) {
    if (groups[start] !== 0) {
      start += 1;
      continue;
    }
    let end = start;
    while (end < 8 && groups[end] === 0) end += 1;
    if (end - start > bestLength) {
      bestStart = start;
      bestLength = end - start;
    }
    start = end;
  }

  const text = groups.map(group => group.toString(16));
  if (bestLength < 2) return text.join(':');
  const head = text.slice(0, bestStart).join(':');
  const tail = text.slice(bestStart + bestLength).join(':');
  return `${head}::${tail}`;
}

const HEX_PAIR = /^[0-9a-fA-F]{2}$/;

// hex text to bytes. Throws ParseError for anything that is not pairs of hex digits
export function fromHex(text: string): Uint8Array {
  if (text.length % 2 !== 0) throw new ParseError('Hex text has an odd number of digits');
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i++) {
    const pair = text.slice(i * 2, i * 2 + 2);
    if (!HEX_PAIR.test(pair)) throw new ParseError('Not hex text');
    out[i] = Number.parseInt(pair, 16);
  }
  return out;
}

// base64 text to bytes
export function fromBase64(text: string): Uint8Array {
  const binary = atob(text.replace(/\s+/g, ''));
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// byte order: the first difference decides, then the shorter sorts first
export function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const length = Math.min(a.length, b.length);
  for (let i = 0; i < length; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}
