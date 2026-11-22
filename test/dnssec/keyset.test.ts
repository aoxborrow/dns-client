import { describe, expect, it } from 'vitest';
import { checkKeySet, KEY_SET_CODES, readKeys, SIGNATURE_CODES } from '../../src/dnssec/checks';
import { buildSignedData, groupRrsets } from '../../src/dnssec/canonical';
import { decodeRrsig } from '../../src/records/decode';
import type { ResourceRecord } from '../../src/wire/message';
import { countLabels, encodeName } from '../../src/wire/names';
import { rsaKey } from '../support/signed-zones';
import type { TestKey } from '../support/signed-zones';

// a key set signed by an RSA key under 1024 bits: a good signature by one counts like any
// other, and a forged one naming it fails, under a tag collision as much as without one

const now = new Date('2026-11-01T00:00:00Z');
const DNSKEY = 48;
const RRSIG = 46;

function record(type: number, rdata: Uint8Array): ResourceRecord {
  return { name: 'example', type, class: 1, ttl: 3600, rdata, section: 'answer' };
}

const u16 = (value: number) => [(value >> 8) & 0xff, value & 0xff];
const u32 = (value: number) => [...u16(Math.floor(value / 0x10000)), ...u16(value & 0xffff)];

function sign(records: ResourceRecord[], key: TestKey): ResourceRecord {
  const seconds = Math.floor(now.getTime() / 1000);
  const unsigned = Uint8Array.from([
    ...u16(DNSKEY),
    key.algorithm,
    countLabels('example'),
    ...u32(3600),
    ...u32(seconds + 86400),
    ...u32(seconds - 86400),
    ...u16(key.keyTag),
    ...encodeName('example'),
  ]);
  const signed = buildSignedData(decodeRrsig(unsigned), groupRrsets(records)[0])!;
  return record(RRSIG, Uint8Array.from([...unsigned, ...key.sign(signed.data)]));
}

describe('a key set signed by an RSA key under 1024 bits', () => {
  // the first key is tried first under the second's tag, as a tag collision would have it
  async function check(first: TestKey, signer: TestKey, by: TestKey = signer) {
    const records = [record(DNSKEY, first.rdata), record(DNSKEY, signer.rdata)];
    const keys = readKeys(records).map(key =>
      key.record === records[0] ? { ...key, keyTag: signer.keyTag } : key
    );
    return checkKeySet(
      'example',
      { answers: [...records, sign(records, { ...by, keyTag: signer.keyTag })] },
      keys,
      keys,
      [8],
      now
    );
  }

  it('links through it when another key sharing its tag comes first', async () => {
    const signer = rsaKey(257, 768);
    const linked = await check(rsaKey(257, 768), signer);
    expect(linked.code).toBe(KEY_SET_CODES.VERIFIED);
    expect(linked.keyTag).toBe(signer.keyTag);
    expect(linked.signatures.map(signature => signature.code)).toEqual([SIGNATURE_CODES.VERIFIED]);
  });

  it('links through it when a sound key sharing its tag comes first', async () => {
    const signer = rsaKey(257, 768);
    const linked = await check(rsaKey(257, 2048), signer);
    expect(linked.code).toBe(KEY_SET_CODES.VERIFIED);
    expect(linked.keyTag).toBe(signer.keyTag);
  });

  it('does not link through a signature that names it but was made by another key', async () => {
    const forged = await check(rsaKey(257, 768), rsaKey(257, 768), rsaKey(257, 768));
    expect(forged.code).not.toBe(KEY_SET_CODES.VERIFIED);
    expect(forged.keyTag).toBeUndefined();
    expect(forged.signatures.map(signature => signature.code)).toEqual([SIGNATURE_CODES.INVALID]);
  });
});
