import { readU16, toBase64, toHex } from '../wire/bytes';
import { DNSSEC_ALGORITHMS, SIGNATURE_LENGTHS } from './constants';

// signature verification for the DNSSEC algorithms, through WebCrypto, so it runs
// wherever that does. An algorithm that is not verifiable here, or that this runtime's
// WebCrypto does not have, is reported as not attempted, which yields `indeterminate`
// for the object: never a pass

export interface VerifyOutcome {
  // undefined means "not attempted": unsupported algorithm or an unusable key
  verified?: boolean;
  reason?: string;
  publicKeyDescription?: string;
  expectedSignatureLength?: number;
}

export function isAlgorithmVerifiable(algorithm: number): boolean {
  const entry = DNSSEC_ALGORITHMS[algorithm as keyof typeof DNSSEC_ALGORITHMS];
  return Boolean(entry?.verify);
}

export function algorithmName(algorithm: number): string {
  const entry = DNSSEC_ALGORITHMS[algorithm as keyof typeof DNSSEC_ALGORITHMS];
  return entry?.name ?? `UNKNOWN(${algorithm})`;
}

// bit length of the key material, for the "key size and estimated strength" display
export function keySizeBits(algorithm: number, publicKey: Uint8Array): number | undefined {
  switch (algorithm) {
    case 5:
    case 7:
    case 8:
    case 10: {
      const rsa = parseRsaPublicKey(publicKey);
      return rsa ? rsa.modulus.length * 8 : undefined;
    }
    case 13:
      return 256;
    case 14:
      return 384;
    case 15:
      return 256;
    case 16:
      return 456;
    default:
      return undefined;
  }
}

// RFC 3110 §2: an exponent-length byte (or a zero byte followed by a 16-bit length),
// then the exponent, then the modulus
function parseRsaPublicKey(
  publicKey: Uint8Array
): { exponent: Uint8Array; modulus: Uint8Array } | null {
  if (publicKey.length < 3) return null;
  let offset = 1;
  let exponentLength = publicKey[0];
  if (exponentLength === 0) {
    if (publicKey.length < 4) return null;
    exponentLength = readU16(publicKey, 1);
    offset = 3;
  }
  if (exponentLength === 0 || offset + exponentLength >= publicKey.length) return null;
  return {
    exponent: publicKey.subarray(offset, offset + exponentLength),
    modulus: publicKey.subarray(offset + exponentLength),
  };
}

function base64url(bytes: Uint8Array): string {
  return toBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// the hash each RSA algorithm signs under
function rsaHash(algorithm: number): string {
  switch (algorithm) {
    case 5:
    case 7:
      return 'SHA-1';
    case 8:
      return 'SHA-256';
    case 10:
      return 'SHA-512';
    default:
      throw new Error(`no hash for algorithm ${algorithm}`);
  }
}

interface Imported {
  key: CryptoKey;
  // what to pass to `verify` alongside the key
  parameters: AlgorithmIdentifier | EcdsaParams;
  description: string;
}

// the runtime's WebCrypto has no such algorithm, as opposed to the key being bad
class UnsupportedAlgorithm extends Error {}

const unsupported = (error: unknown) =>
  error instanceof Error && error.name === 'NotSupportedError';

// turn DNSKEY public-key bytes into a key WebCrypto can verify with
async function importKey(algorithm: number, publicKey: Uint8Array): Promise<Imported> {
  const { subtle } = crypto;
  try {
    switch (algorithm) {
      case 5:
      case 7:
      case 8:
      case 10: {
        const rsa = parseRsaPublicKey(publicKey);
        if (!rsa) throw new Error('malformed RSA public key');
        // a leading zero byte would make the JWK integer negative-safe but not canonical;
        // strip it so the modulus length reports the true key size
        const modulus = rsa.modulus[0] === 0 ? rsa.modulus.subarray(1) : rsa.modulus;
        const parameters = { name: 'RSASSA-PKCS1-v1_5', hash: rsaHash(algorithm) };
        return {
          key: await subtle.importKey(
            'jwk',
            { kty: 'RSA', n: base64url(modulus), e: base64url(rsa.exponent), ext: true },
            parameters,
            false,
            ['verify']
          ),
          parameters,
          description: `RSA modulus ${modulus.length * 8} bits, exponent ${toHex(rsa.exponent)}`,
        };
      }
      case 13:
      case 14: {
        const size = algorithm === 13 ? 32 : 48;
        const curve = algorithm === 13 ? 'P-256' : 'P-384';
        if (publicKey.length !== size * 2) {
          throw new Error(
            `public key is ${publicKey.length} bytes, expected ${size * 2} for ${curve}`
          );
        }
        // an uncompressed point: 0x04, then x and y
        const point = new Uint8Array(publicKey.length + 1);
        point[0] = 0x04;
        point.set(publicKey, 1);
        return {
          key: await subtle.importKey(
            'raw',
            point as BufferSource,
            { name: 'ECDSA', namedCurve: curve },
            false,
            ['verify']
          ),
          // DNSSEC carries ECDSA signatures as raw r‖s, which is also WebCrypto's form
          parameters: { name: 'ECDSA', hash: algorithm === 13 ? 'SHA-256' : 'SHA-384' },
          description: `uncompressed ${curve} point, ${publicKey.length} bytes`,
        };
      }
      case 15:
      case 16: {
        const expected = algorithm === 15 ? 32 : 57;
        const name = algorithm === 15 ? 'Ed25519' : 'Ed448';
        if (publicKey.length !== expected) {
          throw new Error(
            `public key is ${publicKey.length} bytes, expected ${expected} for ${name}`
          );
        }
        return {
          key: await subtle.importKey('raw', publicKey as BufferSource, { name }, false, [
            'verify',
          ]),
          parameters: { name },
          description: `raw ${name} key, ${publicKey.length} bytes`,
        };
      }
      default:
        throw new Error(`algorithm ${algorithm} is not verifiable`);
    }
  } catch (error) {
    if (unsupported(error)) throw new UnsupportedAlgorithm();
    throw error;
  }
}

// verify `signature` over `data` with a DNSKEY's raw public key.
// an error thrown inside WebCrypto is a failed check, not a crashed analysis: every path
// here returns a VerifyOutcome
export async function verifySignature(
  algorithm: number,
  publicKey: Uint8Array,
  data: Uint8Array,
  signature: Uint8Array
): Promise<VerifyOutcome> {
  if (!isAlgorithmVerifiable(algorithm)) {
    return {
      reason: `${algorithmName(algorithm)} (algorithm ${algorithm}) cannot be verified by this tool`,
    };
  }

  // a wrong-length signature is a distinct, diagnosable fault: say so rather than
  // reporting a generic crypto failure
  const expected = SIGNATURE_LENGTHS[algorithm];
  if (expected !== undefined && signature.length !== expected) {
    return {
      verified: false,
      expectedSignatureLength: expected,
      reason: `signature length ${signature.length} bytes, expected ${expected} for algorithm ${algorithm} (${algorithmName(algorithm)})`,
    };
  }

  let imported: Imported;
  try {
    imported = await importKey(algorithm, publicKey);
  } catch (error) {
    // this runtime cannot do the algorithm at all (Ed448 on Cloudflare Workers): not
    // attempted, so the object reads as indeterminate and not as bogus
    if (error instanceof UnsupportedAlgorithm) {
      return {
        reason: `${algorithmName(algorithm)} (algorithm ${algorithm}) cannot be verified on this runtime`,
      };
    }
    // the algorithm is supported but the key itself will not import: a real, checkable
    // failure. It must read as FAILED (verified: false, so bogus), not as the UNCHECKED
    // an unsupported algorithm gets, or an RRset signed only by an unusable key would
    // pass as secure
    return {
      verified: false,
      reason: error instanceof Error ? error.message : 'could not import public key',
    };
  }

  try {
    const verified = await crypto.subtle.verify(
      imported.parameters,
      imported.key,
      signature as BufferSource,
      data as BufferSource
    );
    return {
      verified,
      publicKeyDescription: imported.description,
      expectedSignatureLength: expected,
      reason: verified ? undefined : 'the signature does not match the data it covers',
    };
  } catch (error) {
    return {
      verified: false,
      publicKeyDescription: imported.description,
      reason: error instanceof Error ? error.message : 'signature verification threw',
    };
  }
}
