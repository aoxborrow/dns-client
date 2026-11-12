import { DnssecEngine } from '../../src/dnssec/engine';
import type { DnssecDelegation, DnssecDs, DnssecStatus, DnssecZone } from '../../src/dnssec/types';
import {
  TYPE_DNSKEY,
  TYPE_DS,
  TYPE_RRSIG,
  buildSignedData,
  computeDsDigest,
  computeKeyTag,
  decodeRrsig,
  encodeName,
  groupRrsets,
} from '../../src/dnssec/wire';
import type { WireRecord } from '../../src/dnssec/wire';

// a DS set that links no key in the zone. Whether that is bogus or indeterminate depends on
// the algorithms the DS set names, not on what else signed the key set: a selected DS naming
// an algorithm verifiable here that matches nothing is a break (RFC 6840 §5.2), and only a DS
// set naming nothing verifiable leaves the zone indeterminate (RFC 4035 §5.2).
//
// the zone is made here, an ECDSA P-256 key every runtime verifies beside a GOST key nothing
// does, and handed to the engine's zone assembly directly, as the walk would after asking
// the parent

const ZONE = 'signed.example';
const PARENT = 'example';
const ECDSA = 13;
const GOST = 12;
const now = new Date('2026-11-01T00:00:00Z');

interface Key {
  algorithm: number;
  rdata: Uint8Array;
  keyTag: number;
  sign: (data: Uint8Array) => Promise<Uint8Array>;
}

function dnskeyRdata(algorithm: number, publicKey: Uint8Array): Uint8Array {
  // flags 257 (zone key, secure entry point), protocol 3
  return Uint8Array.from([0x01, 0x01, 3, algorithm, ...publicKey]);
}

async function ecdsaKey(): Promise<Key> {
  const pair = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
  // RFC 6605: the uncompressed point without its 0x04 prefix
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey)).subarray(1);
  const rdata = dnskeyRdata(ECDSA, raw);
  return {
    algorithm: ECDSA,
    rdata,
    keyTag: computeKeyTag(rdata),
    sign: async data =>
      new Uint8Array(
        await crypto.subtle.sign(
          { name: 'ECDSA', hash: 'SHA-256' },
          pair.privateKey,
          data as BufferSource
        )
      ),
  };
}

function gostKey(fill = 7): Key {
  const rdata = dnskeyRdata(GOST, new Uint8Array(64).fill(fill));
  // nothing checks a GOST signature, so any bytes stand in for one
  return {
    algorithm: GOST,
    rdata,
    keyTag: computeKeyTag(rdata),
    sign: async () => new Uint8Array(64).fill(9),
  };
}

function record(type: number, typeName: string, rdata: Uint8Array): WireRecord {
  return { name: ZONE, type, typeName, class: 1, ttl: 3600, rdata, section: 'answer' };
}

function u16(value: number): number[] {
  return [(value >> 8) & 0xff, value & 0xff];
}

function u32(value: number): number[] {
  return [...u16(Math.floor(value / 0x10000)), ...u16(value & 0xffff)];
}

// an RRSIG over the zone's DNSKEY RRset, made by `key`
async function signKeySet(key: Key, keyRecords: WireRecord[]): Promise<WireRecord> {
  const seconds = Math.floor(now.getTime() / 1000);
  const fields = [
    ...u16(TYPE_DNSKEY),
    key.algorithm,
    2,
    ...u32(3600),
    ...u32(seconds + 30 * 86400),
    ...u32(seconds - 86400),
    ...u16(key.keyTag),
    ...encodeName(ZONE),
  ];
  const unsigned = Uint8Array.from(fields);
  const rrset = groupRrsets(keyRecords).find(set => set.type === TYPE_DNSKEY)!;
  const signedData = buildSignedData(decodeRrsig(unsigned)!, rrset)!;
  const signature = await key.sign(signedData.data);
  return record(TYPE_RRSIG, 'RRSIG', Uint8Array.from([...unsigned, ...signature]));
}

// a DS with SHA-256, or with a digest type nothing here computes, whose bytes then stand in
function dsRecord(key: Key, digestType = 2): WireRecord {
  const digest =
    digestType === 2 ? computeDsDigest(ZONE, key.rdata, 2)! : new Uint8Array(32).fill(5);
  return record(
    TYPE_DS,
    'DS',
    Uint8Array.from([...u16(key.keyTag), key.algorithm, digestType, ...digest])
  );
}

// the engine's zone assembly, reached past `private` for want of a zone signed this way
interface ZoneAssembly {
  describeDs(
    rr: WireRecord,
    child: string,
    fetched: unknown,
    keys: Map<number, WireRecord[]>
  ): DnssecDs;
  buildZone(
    build: unknown,
    delegation: DnssecDelegation,
    trustAnchor: undefined,
    parentStatus: DnssecStatus
  ): Promise<DnssecZone>;
}

// a DS is a key, with SHA-256, or a key with a digest type to use instead
type DsSpec = Key | { key: Key; digestType: number };

async function assemble(options: { ds: DsSpec[]; keys: Key[]; signers: Key[] }) {
  const engine = new DnssecEngine({ now, crossCheck: false }) as unknown as ZoneAssembly;
  const from = { server: '192.0.2.1', queryIndex: 0 };

  const keyRecords = options.keys.map(key => record(TYPE_DNSKEY, 'DNSKEY', key.rdata));
  const rrsigs = await Promise.all(options.signers.map(key => signKeySet(key, keyRecords)));
  const fetched = { ...from, message: {}, answers: keyRecords, authorities: [], rrsigs };

  const delegation: DnssecDelegation = {
    parent: PARENT,
    child: ZONE,
    dsRecords: options.ds.map(spec => {
      const rr = 'key' in spec ? dsRecord(spec.key, spec.digestType) : dsRecord(spec);
      return engine.describeDs(rr, ZONE, from, new Map());
    }),
    status: 'indeterminate',
    parentResponseVerified: true,
  };
  const build = {
    name: ZONE,
    parent: PARENT,
    nameservers: [],
    serverIps: [from.server],
    fetched: new Map([[`${ZONE}/DNSKEY`, fetched]]),
    dnskeyRecords: keyRecords,
    started: performance.now(),
  };
  return engine.buildZone(build, delegation, undefined, 'secure');
}

describe('a DS set that links no key in the zone', () => {
  it('is bogus when the DS names a verifiable algorithm, even beside an unverifiable RRSIG', async () => {
    // the DS commits to an ECDSA key the zone does not publish; a GOST signature that
    // cannot be checked must not turn the broken link into an unknown one
    const [vouched, published, gost] = [await ecdsaKey(), await ecdsaKey(), gostKey()];
    const zone = await assemble({
      ds: [vouched],
      keys: [published, gost],
      signers: [published, gost],
    });
    expect(zone.status).toBe('bogus');
    expect(zone.reason).toContain('authenticated by its parent');
    expect(zone.delegation?.status).toBe('bogus');
  });

  it('is bogus when nothing unverifiable is involved', async () => {
    const [vouched, published] = [await ecdsaKey(), await ecdsaKey()];
    const zone = await assemble({ ds: [vouched], keys: [published], signers: [published] });
    expect(zone.status).toBe('bogus');
  });

  it('is indeterminate when the DS set names only an algorithm nothing here verifies', async () => {
    const [vouched, published] = [gostKey(7), gostKey(8)];
    const zone = await assemble({ ds: [vouched], keys: [published], signers: [published] });
    expect(zone.status).toBe('indeterminate');
    expect(zone.reason).toContain('No supported algorithm links');
  });

  it('is indeterminate when no DS uses a digest type this tool can verify', async () => {
    // RFC 4035 §5.2 and RFC 4509 §3: a DS set with no usable digest is treated as absent, so
    // the zone cannot be linked, which is not the same as a link that failed
    const key = await ecdsaKey();
    const zone = await assemble({
      ds: [{ key, digestType: 3 }],
      keys: [key],
      signers: [key],
    });
    expect(zone.status).toBe('indeterminate');
    expect(zone.reason).toContain('digest type');
    expect(zone.delegation?.status).toBe('indeterminate');
    expect(zone.findings.map(finding => finding.slug)).toContain('ds-digest-unsupported');
  });

  it('is bogus when a usable digest beside the unusable one matches nothing', async () => {
    // the SHA-256 DS names a key the zone does not publish; the GOST-digest one cannot be
    // checked, and does not soften the failure of the one that could
    const [vouched, published] = [await ecdsaKey(), await ecdsaKey()];
    const zone = await assemble({
      ds: [vouched, { key: published, digestType: 3 }],
      keys: [published],
      signers: [published],
    });
    expect(zone.status).toBe('bogus');
    expect(zone.delegation?.status).toBe('bogus');
  });
});
