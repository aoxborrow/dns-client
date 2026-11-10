// SHA-1, SHA-256 and SHA-384, synchronous and in plain JavaScript.
//
// DNSSEC hashes small things often: a DS digest per key, and for NSEC3 up to hundreds of
// rounds of SHA-1 per name. WebCrypto's digest is asynchronous, which would turn every
// function that touches a hash, and everything that calls it, into an async one. These
// are the three digests DNSSEC uses, kept synchronous. Signature verification, which
// needs real public-key arithmetic, does go through WebCrypto.
//
// the round constants are computed, not typed in: they are defined as the fractional
// parts of the square and cube roots of the first primes, and deriving them leaves no
// table to mistype. The tests check every digest against the runtime's own

const MASK64 = (1n << 64n) - 1n;

function firstPrimes(count: number): bigint[] {
  const primes: bigint[] = [];
  for (let candidate = 2n; primes.length < count; candidate++) {
    if (primes.every(prime => candidate % prime !== 0n)) primes.push(candidate);
  }
  return primes;
}

// the largest integer whose `degree`-th power is not above `value`
function integerRoot(value: bigint, degree: bigint): bigint {
  let low = 0n;
  let high = 1n << BigInt(Math.ceil(value.toString(2).length / Number(degree)) + 1);
  while (low < high) {
    const middle = (low + high + 1n) >> 1n;
    if (middle ** degree <= value) low = middle;
    else high = middle - 1n;
  }
  return low;
}

// the first 64 bits of the fractional part of a root of a prime
const fraction = (prime: bigint, degree: bigint): bigint =>
  integerRoot(prime << (64n * degree), degree) & MASK64;

interface Constants {
  // 64-bit: SHA-384's initial state and SHA-512's round constants
  iv384: bigint[];
  k512: bigint[];
  // 32-bit: SHA-256's initial state and round constants, the top halves of the same roots
  iv256: number[];
  k256: number[];
}

let constants: Constants | undefined;

function derive(): Constants {
  const primes = firstPrimes(80);
  const k512 = primes.map(prime => fraction(prime, 3n));
  return {
    // square roots of the ninth to sixteenth primes
    iv384: primes.slice(8, 16).map(prime => fraction(prime, 2n)),
    k512,
    iv256: primes.slice(0, 8).map(prime => Number(fraction(prime, 2n) >> 32n)),
    k256: k512.slice(0, 64).map(value => Number(value >> 32n)),
  };
}

// the message, padded: a 1 bit, zeros, then the length in bits in the last `lengthBytes`
function pad(message: Uint8Array, blockBytes: number, lengthBytes: number): Uint8Array {
  const total = Math.ceil((message.length + 1 + lengthBytes) / blockBytes) * blockBytes;
  const padded = new Uint8Array(total);
  padded.set(message);
  padded[message.length] = 0x80;
  const view = new DataView(padded.buffer);
  // messages here are far shorter than 2^53 bits, so the low 64 bits hold the length
  view.setBigUint64(total - 8, BigInt(message.length) * 8n);
  return padded;
}

const rotl32 = (value: number, bits: number) => (value << bits) | (value >>> (32 - bits));
const rotr32 = (value: number, bits: number) => (value >>> bits) | (value << (32 - bits));
const rotr64 = (value: bigint, bits: bigint) =>
  ((value >> bits) | (value << (64n - bits))) & MASK64;

export function sha1(message: Uint8Array): Uint8Array {
  const state = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
  const padded = pad(message, 64, 8);
  const view = new DataView(padded.buffer);
  const words = new Uint32Array(80);

  for (let block = 0; block < padded.length; block += 64) {
    for (let i = 0; i < 16; i++) words[i] = view.getUint32(block + i * 4);
    for (let i = 16; i < 80; i++) {
      words[i] = rotl32(words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16], 1);
    }
    let [a, b, c, d, e] = state;
    for (let i = 0; i < 80; i++) {
      let mix: number;
      let constant: number;
      if (i < 20) {
        mix = (b & c) | (~b & d);
        constant = 0x5a827999;
      } else if (i < 40) {
        mix = b ^ c ^ d;
        constant = 0x6ed9eba1;
      } else if (i < 60) {
        mix = (b & c) | (b & d) | (c & d);
        constant = 0x8f1bbcdc;
      } else {
        mix = b ^ c ^ d;
        constant = 0xca62c1d6;
      }
      const next = (rotl32(a, 5) + mix + e + constant + words[i]) | 0;
      e = d;
      d = c;
      c = rotl32(b, 30);
      b = a;
      a = next;
    }
    state[0] = (state[0] + a) | 0;
    state[1] = (state[1] + b) | 0;
    state[2] = (state[2] + c) | 0;
    state[3] = (state[3] + d) | 0;
    state[4] = (state[4] + e) | 0;
  }

  const out = new Uint8Array(20);
  const outView = new DataView(out.buffer);
  state.forEach((word, index) => outView.setUint32(index * 4, word >>> 0));
  return out;
}

export function sha256(message: Uint8Array): Uint8Array {
  const { iv256, k256 } = (constants ??= derive());
  const state = [...iv256];
  const padded = pad(message, 64, 8);
  const view = new DataView(padded.buffer);
  const words = new Uint32Array(64);

  for (let block = 0; block < padded.length; block += 64) {
    for (let i = 0; i < 16; i++) words[i] = view.getUint32(block + i * 4);
    for (let i = 16; i < 64; i++) {
      const w15 = words[i - 15];
      const w2 = words[i - 2];
      const s0 = rotr32(w15, 7) ^ rotr32(w15, 18) ^ (w15 >>> 3);
      const s1 = rotr32(w2, 17) ^ rotr32(w2, 19) ^ (w2 >>> 10);
      words[i] = (words[i - 16] + s0 + words[i - 7] + s1) | 0;
    }
    let [a, b, c, d, e, f, g, h] = state;
    for (let i = 0; i < 64; i++) {
      const s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
      const choose = (e & f) ^ (~e & g);
      const t1 = (h + s1 + choose + k256[i] + words[i]) | 0;
      const s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
      const majority = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (s0 + majority) | 0;
      h = g;
      g = f;
      f = e;
      e = (d + t1) | 0;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) | 0;
    }
    [a, b, c, d, e, f, g, h].forEach((value, index) => {
      state[index] = (state[index] + value) | 0;
    });
  }

  const out = new Uint8Array(32);
  const outView = new DataView(out.buffer);
  state.forEach((word, index) => outView.setUint32(index * 4, word >>> 0));
  return out;
}

// SHA-384 is SHA-512 with its own initial state, cut to 48 bytes
export function sha384(message: Uint8Array): Uint8Array {
  const { iv384, k512 } = (constants ??= derive());
  const state = [...iv384];
  const padded = pad(message, 128, 16);
  const view = new DataView(padded.buffer);
  const words = new Array<bigint>(80);

  for (let block = 0; block < padded.length; block += 128) {
    for (let i = 0; i < 16; i++) words[i] = view.getBigUint64(block + i * 8);
    for (let i = 16; i < 80; i++) {
      const w15 = words[i - 15];
      const w2 = words[i - 2];
      const s0 = rotr64(w15, 1n) ^ rotr64(w15, 8n) ^ (w15 >> 7n);
      const s1 = rotr64(w2, 19n) ^ rotr64(w2, 61n) ^ (w2 >> 6n);
      words[i] = (words[i - 16] + s0 + words[i - 7] + s1) & MASK64;
    }
    let [a, b, c, d, e, f, g, h] = state;
    for (let i = 0; i < 80; i++) {
      const s1 = rotr64(e, 14n) ^ rotr64(e, 18n) ^ rotr64(e, 41n);
      const choose = (e & f) ^ (~e & MASK64 & g);
      const t1 = (h + s1 + choose + k512[i] + words[i]) & MASK64;
      const s0 = rotr64(a, 28n) ^ rotr64(a, 34n) ^ rotr64(a, 39n);
      const majority = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (s0 + majority) & MASK64;
      h = g;
      g = f;
      f = e;
      e = (d + t1) & MASK64;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) & MASK64;
    }
    [a, b, c, d, e, f, g, h].forEach((value, index) => {
      state[index] = (state[index] + value) & MASK64;
    });
  }

  const out = new Uint8Array(48);
  const outView = new DataView(out.buffer);
  state.slice(0, 6).forEach((word, index) => outView.setBigUint64(index * 8, word));
  return out;
}
