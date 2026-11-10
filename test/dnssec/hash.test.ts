import { createHash } from 'node:crypto';
import { sha1, sha256, sha384 } from '../../src/dnssec/hash';
import { toHex } from '../../src/wire/bytes';
import { seededRandom } from '../support/corpus';

// the library's own digests against the runtime's, which is the reference

const text = (value: string) => new TextEncoder().encode(value);
const node = (algorithm: string, bytes: Uint8Array) =>
  createHash(algorithm).update(bytes).digest('hex');

describe('hashes', () => {
  it('match the published test vectors', () => {
    expect(toHex(sha1(text('abc')))).toBe('a9993e364706816aba3e25717850c26c9cd0d89d');
    expect(toHex(sha256(text('abc')))).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    );
    expect(toHex(sha384(text('abc')))).toBe(
      'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7'
    );
    expect(toHex(sha1(new Uint8Array(0)))).toBe('da39a3ee5e6b4b0d3255bfef95601890afd80709');
  });

  it('agree with the runtime for every length across the block boundaries', () => {
    const random = seededRandom(7);
    for (let length = 0; length <= 300; length++) {
      const bytes = Uint8Array.from({ length }, () => Math.floor(random() * 256));
      expect(toHex(sha1(bytes)), `sha1 of ${length} bytes`).toBe(node('sha1', bytes));
      expect(toHex(sha256(bytes)), `sha256 of ${length} bytes`).toBe(node('sha256', bytes));
      expect(toHex(sha384(bytes)), `sha384 of ${length} bytes`).toBe(node('sha384', bytes));
    }
  });

  it('agree with the runtime on a long message', () => {
    const random = seededRandom(11);
    const bytes = Uint8Array.from({ length: 70_000 }, () => Math.floor(random() * 256));
    expect(toHex(sha1(bytes))).toBe(node('sha1', bytes));
    expect(toHex(sha256(bytes))).toBe(node('sha256', bytes));
    expect(toHex(sha384(bytes))).toBe(node('sha384', bytes));
  });
});
