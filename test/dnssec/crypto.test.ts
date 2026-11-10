import { generateKeyPairSync, sign as cryptoSign, KeyObject } from 'crypto';
import {
  verifySignature,
  isAlgorithmVerifiable,
  algorithmName,
  keySizeBits,
} from '@/tools/dnssec/crypto';

// signature verification is checked against keys generated here rather than recorded packets:
// a generated pair exercises the same DNSKEY wire encoding and the same node crypto path, and
// it lets the corruption cases be exact rather than approximate.

function fromBase64Url(value: string): Buffer {
  return Buffer.from(value.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

// export a public key in the DNSKEY RDATA public-key encoding for its algorithm
function toDnskeyPublicKey(key: KeyObject, algorithm: number): Buffer {
  const jwk = key.export({ format: 'jwk' }) as Record<string, string>;

  switch (algorithm) {
    case 8:
    case 10: {
      // RFC 3110: exponent length, exponent, modulus
      const exponent = fromBase64Url(jwk.e);
      const modulus = fromBase64Url(jwk.n);
      return Buffer.concat([Buffer.from([exponent.length]), exponent, modulus]);
    }
    case 13:
    case 14:
      // RFC 6605: the raw uncompressed point, without the 0x04 prefix
      return Buffer.concat([fromBase64Url(jwk.x), fromBase64Url(jwk.y)]);
    case 15:
    case 16:
      // RFC 8080: the raw key
      return fromBase64Url(jwk.x);
    default:
      throw new Error(`no DNSKEY encoding for algorithm ${algorithm}`);
  }
}

interface Vector {
  algorithm: number;
  publicKey: Buffer;
  sign: (data: Buffer) => Buffer;
  expectedKeySize: number;
}

function rsaVector(algorithm: number, hash: string, modulusLength: number): Vector {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength });
  return {
    algorithm,
    publicKey: toDnskeyPublicKey(publicKey, algorithm),
    sign: data => cryptoSign(hash, data, privateKey),
    expectedKeySize: modulusLength,
  };
}

function ecdsaVector(algorithm: number, curve: string, hash: string, size: number): Vector {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: curve });
  return {
    algorithm,
    publicKey: toDnskeyPublicKey(publicKey, algorithm),
    // DNSSEC carries ECDSA signatures as raw r‖s, not DER
    sign: data => cryptoSign(hash, data, { key: privateKey, dsaEncoding: 'ieee-p1363' }),
    expectedKeySize: size,
  };
}

function eddsaVector(algorithm: 15 | 16, size: number): Vector {
  // the two calls are spelled out because node's overloads key off the literal curve name
  const { publicKey, privateKey } =
    algorithm === 15 ? generateKeyPairSync('ed25519') : generateKeyPairSync('ed448');
  return {
    algorithm,
    publicKey: toDnskeyPublicKey(publicKey, algorithm),
    sign: data => cryptoSign(null, data, privateKey),
    expectedKeySize: size,
  };
}

const VECTORS: Record<string, () => Vector> = {
  'RSASHA256 (8)': () => rsaVector(8, 'sha256', 2048),
  'RSASHA512 (10)': () => rsaVector(10, 'sha512', 2048),
  'ECDSAP256SHA256 (13)': () => ecdsaVector(13, 'prime256v1', 'sha256', 256),
  'ECDSAP384SHA384 (14)': () => ecdsaVector(14, 'secp384r1', 'sha384', 384),
  'ED25519 (15)': () => eddsaVector(15, 256),
  'ED448 (16)': () => eddsaVector(16, 456),
};

const SIGNED_DATA = Buffer.from('RRSIG RDATA || canonical RRset', 'utf8');

describe('verifySignature', () => {
  for (const [label, build] of Object.entries(VECTORS)) {
    describe(label, () => {
      const vector = build();
      const signature = vector.sign(SIGNED_DATA);

      it('verifies a good signature', () => {
        const outcome = verifySignature(vector.algorithm, vector.publicKey, SIGNED_DATA, signature);
        expect(outcome.verified).toBe(true);
        expect(outcome.reason).toBeUndefined();
      });

      it('fails when a signature byte is flipped', () => {
        const corrupted = Buffer.from(signature);
        corrupted[corrupted.length - 1] ^= 0xff;
        const outcome = verifySignature(vector.algorithm, vector.publicKey, SIGNED_DATA, corrupted);
        expect(outcome.verified).toBe(false);
      });

      it('fails when the signed data is altered', () => {
        const tampered = Buffer.concat([SIGNED_DATA, Buffer.from('!')]);
        const outcome = verifySignature(vector.algorithm, vector.publicKey, tampered, signature);
        expect(outcome.verified).toBe(false);
      });

      it('reports the key size', () => {
        expect(keySizeBits(vector.algorithm, vector.publicKey)).toBe(vector.expectedKeySize);
      });
    });
  }

  it('names a wrong-length signature as its own fault, not a generic failure', () => {
    const vector = VECTORS['ECDSAP256SHA256 (13)']();
    const outcome = verifySignature(13, vector.publicKey, SIGNED_DATA, Buffer.alloc(32));
    expect(outcome.verified).toBe(false);
    expect(outcome.expectedSignatureLength).toBe(64);
    expect(outcome.reason).toMatch(/signature length 32 bytes, expected 64/);
  });

  it('leaves an unverifiable algorithm unchecked rather than passing it', () => {
    // GOST (12) is one this tool must never green-check
    const outcome = verifySignature(12, Buffer.alloc(64), SIGNED_DATA, Buffer.alloc(64));
    expect(outcome.verified).toBeUndefined();
    expect(outcome.reason).toMatch(/cannot be verified/);
  });

  it('reports a malformed public key as failed, without throwing', () => {
    // a supported algorithm whose key will not import is a real failure, not an unsupported
    // algorithm: it must read as verified:false (bogus), not the undefined an unverifiable
    // algorithm returns, or an RRset signed only by an unusable key would pass as secure
    const outcome = verifySignature(13, Buffer.alloc(7), SIGNED_DATA, Buffer.alloc(64));
    expect(outcome.verified).toBe(false);
    expect(outcome.reason).toMatch(/expected 64/);
  });

  it('does not verify a signature made by a different key', () => {
    const a = VECTORS['ED25519 (15)']();
    const b = VECTORS['ED25519 (15)']();
    const outcome = verifySignature(15, a.publicKey, SIGNED_DATA, b.sign(SIGNED_DATA));
    expect(outcome.verified).toBe(false);
  });
});

describe('algorithm support', () => {
  it('marks the algorithms the tool can check', () => {
    for (const algorithm of [5, 7, 8, 10, 13, 14, 15, 16]) {
      expect(isAlgorithmVerifiable(algorithm)).toBe(true);
    }
  });

  it('marks the algorithms it cannot', () => {
    for (const algorithm of [1, 3, 6, 12, 23]) {
      expect(isAlgorithmVerifiable(algorithm)).toBe(false);
    }
  });

  it('names an unknown algorithm rather than pretending it is fine', () => {
    expect(isAlgorithmVerifiable(99)).toBe(false);
    expect(algorithmName(99)).toBe('UNKNOWN(99)');
  });
});
