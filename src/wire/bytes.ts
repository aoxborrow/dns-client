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
