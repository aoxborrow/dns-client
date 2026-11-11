import {
  verifySignature,
  isAlgorithmVerifiable,
  algorithmName,
  keySizeBits,
} from '../../src/dnssec/crypto';

// signature verification is checked against keys generated here rather than recorded packets:
// a generated pair exercises the same DNSKEY wire encoding and the same verification path, and
// it lets the corruption cases be exact rather than approximate. The keys are made with
// WebCrypto, which every runtime the library supports has

function fromBase64Url(value: string): Buffer {
  return Buffer.from(value.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

// a public key in the DNSKEY RDATA public-key encoding for its algorithm
function toDnskeyPublicKey(jwk: JsonWebKey, algorithm: number): Buffer {
  switch (algorithm) {
    case 8:
    case 10: {
      // RFC 3110: exponent length, exponent, modulus
      const exponent = fromBase64Url(jwk.e!);
      const modulus = fromBase64Url(jwk.n!);
      return Buffer.concat([Buffer.from([exponent.length]), exponent, modulus]);
    }
    case 13:
    case 14:
      // RFC 6605: the raw uncompressed point, without the 0x04 prefix
      return Buffer.concat([fromBase64Url(jwk.x!), fromBase64Url(jwk.y!)]);
    case 15:
    case 16:
      // RFC 8080: the raw key
      return fromBase64Url(jwk.x!);
    default:
      throw new Error(`no DNSKEY encoding for algorithm ${algorithm}`);
  }
}

interface Vector {
  algorithm: number;
  publicKey: Buffer;
  sign: (data: Buffer) => Promise<Buffer>;
  expectedKeySize: number;
}

type KeyParams = AlgorithmIdentifier | RsaHashedKeyGenParams | EcKeyGenParams;
type SignParams = AlgorithmIdentifier | EcdsaParams;

async function vector(
  algorithm: number,
  generate: KeyParams,
  signWith: SignParams,
  expectedKeySize: number
): Promise<Vector> {
  const pair = (await crypto.subtle.generateKey(generate, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
  const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
  return {
    algorithm,
    publicKey: toDnskeyPublicKey(jwk, algorithm),
    // WebCrypto signs ECDSA as raw r‖s, which is how DNSSEC carries it
    sign: async data =>
      Buffer.from(await crypto.subtle.sign(signWith, pair.privateKey, new Uint8Array(data))),
    expectedKeySize,
  };
}

const rsa = (algorithm: number, hash: string) =>
  vector(
    algorithm,
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash,
    },
    'RSASSA-PKCS1-v1_5',
    2048
  );

const ecdsa = (algorithm: number, namedCurve: string, hash: string, size: number) =>
  vector(algorithm, { name: 'ECDSA', namedCurve }, { name: 'ECDSA', hash }, size);

const VECTORS: Record<string, () => Promise<Vector>> = {
  'RSASHA256 (8)': () => rsa(8, 'SHA-256'),
  'RSASHA512 (10)': () => rsa(10, 'SHA-512'),
  'ECDSAP256SHA256 (13)': () => ecdsa(13, 'P-256', 'SHA-256', 256),
  'ECDSAP384SHA384 (14)': () => ecdsa(14, 'P-384', 'SHA-384', 384),
  'ED25519 (15)': () => vector(15, 'Ed25519', 'Ed25519', 256),
  'ED448 (16)': () => vector(16, 'Ed448', 'Ed448', 456),
};

// a runtime without an algorithm cannot make a key for it either: Ed448 on Cloudflare
// Workers. Such a signature is reported as not checked, which has its own test below
const available = new Map<string, boolean>();
for (const [label, build] of Object.entries(VECTORS)) {
  available.set(
    label,
    await build().then(
      () => true,
      () => false
    )
  );
}

const SIGNED_DATA = Buffer.from('RRSIG RDATA || canonical RRset', 'utf8');

describe('verifySignature', () => {
  for (const [label, build] of Object.entries(VECTORS)) {
    describe.skipIf(!available.get(label))(label, () => {
      let made: Vector;
      let signature: Buffer;

      beforeAll(async () => {
        made = await build();
        signature = await made.sign(SIGNED_DATA);
      });

      it('verifies a good signature', async () => {
        const outcome = await verifySignature(
          made.algorithm,
          made.publicKey,
          SIGNED_DATA,
          signature
        );
        expect(outcome.verified).toBe(true);
        expect(outcome.reason).toBeUndefined();
      });

      it('fails when a signature byte is flipped', async () => {
        const corrupted = Buffer.from(signature);
        corrupted[corrupted.length - 1] ^= 0xff;
        const outcome = await verifySignature(
          made.algorithm,
          made.publicKey,
          SIGNED_DATA,
          corrupted
        );
        expect(outcome.verified).toBe(false);
      });

      it('fails when the signed data is altered', async () => {
        const tampered = Buffer.concat([SIGNED_DATA, Buffer.from('!')]);
        const outcome = await verifySignature(made.algorithm, made.publicKey, tampered, signature);
        expect(outcome.verified).toBe(false);
      });

      it('reports the key size', () => {
        expect(keySizeBits(made.algorithm, made.publicKey)).toBe(made.expectedKeySize);
      });
    });
  }

  it('names a wrong-length signature as its own fault, not a generic failure', async () => {
    const made = await VECTORS['ECDSAP256SHA256 (13)']();
    const outcome = await verifySignature(13, made.publicKey, SIGNED_DATA, Buffer.alloc(32));
    expect(outcome.verified).toBe(false);
    expect(outcome.expectedSignatureLength).toBe(64);
    expect(outcome.reason).toMatch(/signature length 32 bytes, expected 64/);
  });

  it('leaves an unverifiable algorithm unchecked rather than passing it', async () => {
    // GOST (12) is one this tool must never green-check
    const outcome = await verifySignature(12, Buffer.alloc(64), SIGNED_DATA, Buffer.alloc(64));
    expect(outcome.verified).toBeUndefined();
    expect(outcome.reason).toMatch(/cannot be verified/);
  });

  it('reports a malformed public key as failed, without throwing', async () => {
    // a supported algorithm whose key will not import is a real failure, not an unsupported
    // algorithm: it must read as verified:false (bogus), not the undefined an unverifiable
    // algorithm returns, or an RRset signed only by an unusable key would pass as secure
    const outcome = await verifySignature(13, Buffer.alloc(7), SIGNED_DATA, Buffer.alloc(64));
    expect(outcome.verified).toBe(false);
    expect(outcome.reason).toMatch(/expected 64/);
  });

  it('does not verify a signature made by a different key', async () => {
    const a = await VECTORS['ED25519 (15)']();
    const b = await VECTORS['ED25519 (15)']();
    const outcome = await verifySignature(15, a.publicKey, SIGNED_DATA, await b.sign(SIGNED_DATA));
    expect(outcome.verified).toBe(false);
  });
});

describe('algorithm support', () => {
  it('marks the algorithms the tool can check', async () => {
    for (const algorithm of [5, 7, 8, 10, 13, 14, 15, 16]) {
      expect(isAlgorithmVerifiable(algorithm)).toBe(true);
    }
  });

  it('marks the algorithms it cannot', async () => {
    for (const algorithm of [1, 3, 6, 12, 23]) {
      expect(isAlgorithmVerifiable(algorithm)).toBe(false);
    }
  });

  it('names an unknown algorithm rather than pretending it is fine', async () => {
    expect(isAlgorithmVerifiable(99)).toBe(false);
    expect(algorithmName(99)).toBe('UNKNOWN(99)');
  });
});
