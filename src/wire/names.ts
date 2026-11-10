import { ParseError } from '../errors';
import { concatBytes, latin1Decode } from './bytes';

// domain names: reading them off the wire, writing them back, and the presentation form
// in between. A name in this library is a string of labels joined by dots, with no
// trailing dot, in the case it was given; the root is '.'. Bytes that are not printable
// ASCII, and literal dots and backslashes inside a label, are written with the standard
// escapes (`\.` `\\` `\065`), so any name survives a round trip.

const MAX_LABEL_BYTES = 63;
const MAX_NAME_BYTES = 255;

export interface NameRead {
  // the labels, as views into the message
  labels: Uint8Array[];
  // the offset just past the name where it was written; following a compression pointer
  // does not move it
  end: number;
}

// read a name that starts at `offset`, following compression pointers
export function readName(message: Uint8Array, offset: number): NameRead {
  const labels: Uint8Array[] = [];
  let position = offset;
  let end = -1;
  let jumps = 0;
  let total = 1; // the root label

  for (;;) {
    if (position >= message.length) throw new ParseError('Name runs past the end of the message');
    const length = message[position];

    if (length === 0) {
      if (end < 0) end = position + 1;
      break;
    }

    // a compression pointer: the top two bits set, then a 14-bit offset
    if ((length & 0xc0) === 0xc0) {
      if (position + 1 >= message.length) throw new ParseError('Truncated compression pointer');
      const target = ((length & 0x3f) << 8) | message[position + 1];
      if (end < 0) end = position + 2;
      // a pointer may only point backwards, which also rules out loops; the jump count is
      // a second guard
      if (target >= position || ++jumps > 127) throw new ParseError('Invalid compression pointer');
      position = target;
      continue;
    }

    if ((length & 0xc0) !== 0) throw new ParseError('Unknown label type');
    if (position + 1 + length > message.length) {
      throw new ParseError('Label runs past the end of the message');
    }
    total += 1 + length;
    if (total > MAX_NAME_BYTES) throw new ParseError('Name is longer than 255 bytes');
    labels.push(message.subarray(position + 1, position + 1 + length));
    position += 1 + length;
  }

  return { labels, end };
}

function escapeLabel(label: Uint8Array): string {
  let out = '';
  for (const byte of label) {
    if (byte === 0x2e || byte === 0x5c) {
      // a literal dot or backslash
      out += '\\' + String.fromCharCode(byte);
    } else if (byte < 0x21 || byte > 0x7e) {
      out += '\\' + byte.toString().padStart(3, '0');
    } else {
      out += String.fromCharCode(byte);
    }
  }
  return out;
}

// labels to the presentation form
export function labelsToName(labels: readonly Uint8Array[]): string {
  if (labels.length === 0) return '.';
  return labels.map(escapeLabel).join('.');
}

// split a name on its unescaped dots. The root has no labels
export function splitName(name: string): string[] {
  const trimmed = name.endsWith('.') && !name.endsWith('\\.') ? name.slice(0, -1) : name;
  if (trimmed === '') return [];
  const out: string[] = [];
  let current = '';
  for (let i = 0; i < trimmed.length; i++) {
    const char = trimmed[i];
    if (char === '\\') {
      current += char + (trimmed[i + 1] ?? '');
      i += 1;
    } else if (char === '.') {
      out.push(current);
      current = '';
    } else {
      current += char;
    }
  }
  out.push(current);
  return out;
}

function unescapeLabel(label: string): Uint8Array {
  const bytes: number[] = [];
  for (let i = 0; i < label.length; i++) {
    if (label[i] !== '\\') {
      const code = label.charCodeAt(i);
      // a Unicode name has to be converted to its ASCII form before it can go on the wire;
      // a raw byte above 127 is written with an escape
      if (code > 0x7f) throw new ParseError(`Name contains a non-ASCII character: ${label}`);
      bytes.push(code);
      continue;
    }
    const digits = label.slice(i + 1, i + 4);
    if (/^\d{3}$/.test(digits)) {
      const value = Number(digits);
      if (value > 0xff) throw new ParseError(`Invalid escape in name: \\${digits}`);
      bytes.push(value);
      i += 3;
    } else if (i + 1 < label.length) {
      bytes.push(label.charCodeAt(i + 1) & 0xff);
      i += 1;
    } else {
      throw new ParseError('Name ends with a dangling backslash');
    }
  }
  return Uint8Array.from(bytes);
}

// a name's labels as bytes, checked against the DNS length limits
export function nameToLabels(name: string): Uint8Array[] {
  const labels = splitName(name).map(unescapeLabel);
  let total = 1;
  for (const label of labels) {
    if (label.length === 0) throw new ParseError(`Name has an empty label: ${name}`);
    if (label.length > MAX_LABEL_BYTES) {
      throw new ParseError(`Label is longer than 63 bytes: ${latin1Decode(label)}`);
    }
    total += 1 + label.length;
  }
  if (total > MAX_NAME_BYTES) throw new ParseError(`Name is longer than 255 bytes: ${name}`);
  return labels;
}

// a name in wire form, uncompressed, in the case it was given
export function encodeName(name: string): Uint8Array {
  const parts: Uint8Array[] = [];
  for (const label of nameToLabels(name)) {
    parts.push(Uint8Array.of(label.length), label);
  }
  parts.push(Uint8Array.of(0));
  return concatBytes(parts);
}

// a name for comparing: lowercase, no trailing dot, '.' for the root. DNS names are
// case-insensitive, and only ASCII letters fold
export function canonicalName(name: string): string {
  const trimmed = name.endsWith('.') && !name.endsWith('\\.') ? name.slice(0, -1) : name;
  if (trimmed === '') return '.';
  return trimmed.replace(/[A-Z]/g, char => char.toLowerCase());
}

// the number of labels, not counting the root (RFC 4034 §3.1.3)
export function countLabels(name: string): number {
  return splitName(name).length;
}

// the name one label up: 'a.b.example.com' -> 'b.example.com', 'com' -> '.'
export function parentName(name: string): string {
  const labels = splitName(name);
  return labels.length <= 1 ? '.' : labels.slice(1).join('.');
}

// whether `name` is `zone` itself or below it
export function isSubdomain(name: string, zone: string): boolean {
  const child = splitName(canonicalName(name));
  const parent = splitName(canonicalName(zone));
  if (parent.length > child.length) return false;
  const offset = child.length - parent.length;
  return parent.every((label, index) => label === child[offset + index]);
}
