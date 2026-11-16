import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { buildSignedData, computeDsDigest, computeKeyTag } from '../../src/dnssec/canonical';
import type { Rrset, WireRecord } from '../../src/dnssec/canonical';
import type { TrustAnchor } from '../../src/dnssec/types';
import { typeCode, typeName } from '../../src/protocol/types';
import { parseIpv4 } from '../../src/records/addresses';
import { decodeRrsig } from '../../src/records/decode';
import type { NameserverHint } from '../../src/resolvers/root-hints';
import { concatBytes, fromHex, toBase32Hex, toHex, writeU16, writeU32 } from '../../src/wire/bytes';
import { decodeMessage, encodeMessage } from '../../src/wire/index';
import type { Message, ResourceRecord } from '../../src/wire/index';
import {
  canonicalName,
  compareNames,
  countLabels,
  encodeName,
  isSubdomain,
  parentName,
  splitName,
} from '../../src/wire/names';
import type { SimulatedServer } from './simulated-network';

// signed zones, built and served in memory, for testing validation. Keys are made with
// node:crypto and signatures with it too, so what the library verifies (with WebCrypto) was
// made by something else. Each zone is served by one simulated authoritative server that
// answers with its signatures and its NSEC or NSEC3 proofs when asked with DO set

// ---- keys

export interface TestKey {
  algorithm: number;
  flags: number;
  rdata: Uint8Array;
  keyTag: number;
  sign: (data: Uint8Array) => Uint8Array;
}

function dnskeyRdata(flags: number, algorithm: number, publicKey: Uint8Array): Uint8Array {
  const head = new Uint8Array(4);
  writeU16(head, 0, flags);
  head[2] = 3;
  head[3] = algorithm;
  return concatBytes([head, publicKey]);
}

function fromBase64Url(text: string): Uint8Array {
  return Uint8Array.from(Buffer.from(text, 'base64url'));
}

function testKey(
  flags: number,
  algorithm: number,
  publicKey: Uint8Array,
  signer: (data: Uint8Array) => Uint8Array
): TestKey {
  const rdata = dnskeyRdata(flags, algorithm, publicKey);
  return { algorithm, flags, rdata, keyTag: computeKeyTag(rdata), sign: signer };
}

// an ECDSA P-256 key (algorithm 13). Flags 257 is a key-signing key, 256 a zone-signing key
export function ecdsaKey(flags = 257): TestKey {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' });
  const raw = concatBytes([fromBase64Url(jwk.x!), fromBase64Url(jwk.y!)]);
  // the private key goes to sign() as PKCS #8 bytes, not a KeyObject: the Workers runtime's
  // node:crypto takes only the bytes, and the suite runs there too
  const pkcs8 = privateKey.export({ format: 'der', type: 'pkcs8' });
  return testKey(flags, 13, raw, data => ecdsaSign(pkcs8, data));
}

function ecdsaSign(pkcs8: Buffer, data: Uint8Array): Uint8Array {
  return Uint8Array.from(
    sign('sha256', data, { key: pkcs8, format: 'der', type: 'pkcs8', dsaEncoding: 'ieee-p1363' })
  );
}

// a key in an algorithm the library cannot verify (ECC-GOST, 12): any bytes stand in for
// its signatures
export function unverifiableKey(flags = 257, algorithm = 12): TestKey {
  return testKey(flags, algorithm, new Uint8Array(64).fill(7), () => new Uint8Array(64).fill(9));
}

// the same key published with the RFC 5011 revoke bit set, still signing
export function revokedKey(key: TestKey): TestKey {
  const publicKey = key.rdata.subarray(4);
  return testKey(key.flags | 0x0080, key.algorithm, publicKey, key.sign);
}

// a trust anchor for a key, as IANA publishes the root's: a SHA-256 DS digest
export function anchorFor(key: TestKey, zone = '.'): TrustAnchor {
  return {
    id: `test-${key.keyTag}`,
    zone,
    keyTag: key.keyTag,
    algorithm: key.algorithm,
    digestType: 2,
    digest: toHex(computeDsDigest(zone, key.rdata, 2)!),
  };
}

// ---- zones

// a record as [owner, type, value, ttl?]: A, AAAA, TXT, MX, NS, CNAME or DNAME
export type SignedRecord = [name: string, type: string, value: string, ttl?: number];

export interface SignedZone {
  zone: string;
  records?: SignedRecord[];
  // the keys the zone publishes. Default: one ECDSA key with flags 257
  keys?: TestKey[];
  // the keys that sign. Default: every published key that may (Zone flag, not revoked)
  signers?: TestKey[];
  // what the parent publishes as DS: the zone's SEP keys by default, 'none' for an
  // insecure delegation, or other keys
  ds?: 'none' | TestKey[];
  // the parent's DS digest does not match the key it names
  badDs?: boolean;
  // NSEC (default) or NSEC3 proofs of non-existence. `optOut: true` sets the flag on every
  // NSEC3 and leaves insecure delegations out of the chain; a function sets it on the
  // NSEC3 of each name it picks, and leaves the chain whole
  nsec3?: { iterations?: number; salt?: string; optOut?: boolean | ((name: string) => boolean) };
  // when the zone's signatures are valid. Default: from a day ago for thirty days
  inception?: Date;
  expiration?: Date;
  // the zone serves no DNSKEY and no signatures at all
  unsigned?: boolean;
  // the zone serves its data without signatures, keys and proofs still published
  stripSignatures?: boolean;
  // the zone leaves NSEC and NSEC3 proofs out of its answers: all of them, or only those
  // that come with a wildcard answer
  dropProofs?: boolean | 'wildcard';
  // the TTL of the DNSKEY and DS records, in seconds. Default 3600
  keyTtl?: number;
}

export interface SignedNetwork {
  // simulated servers by address: one per zone, and a recursive resolver at `recursive`
  servers: Record<string, SimulatedServer>;
  // the root's server, for `rootServers`
  rootServers: NameserverHint[];
  // the root's key as a trust anchor
  trustAnchors: TrustAnchor[];
  recursive: string;
  // each zone's published keys
  keys: Record<string, TestKey[]>;
}

const RECURSIVE = '10.53.255.1';

interface Set_ {
  name: string;
  type: number;
  ttl: number;
  rdatas: Uint8Array[];
}

function rdataOf(type: string, value: string): Uint8Array {
  switch (type) {
    case 'A':
      return parseIpv4(value)!;
    case 'AAAA': {
      const bytes = new Uint8Array(16);
      bytes[15] = Number(value.split(':').pop() || 0);
      return bytes;
    }
    case 'NS':
    case 'CNAME':
    case 'DNAME':
      return encodeName(canonicalName(value));
    case 'MX': {
      const [preference, exchange] = value.split(' ');
      const head = new Uint8Array(2);
      writeU16(head, 0, Number(preference));
      return concatBytes([head, encodeName(canonicalName(exchange))]);
    }
    case 'TXT': {
      const text = new TextEncoder().encode(value);
      return concatBytes([Uint8Array.of(text.length), text]);
    }
    default:
      throw new Error(`signed zones cannot hold ${type} records`);
  }
}

// an NSEC or NSEC3 type bitmap (RFC 4034 §4.1.2)
function typeBitmap(types: number[]): Uint8Array {
  const windows = new Map<number, number[]>();
  for (const type of [...new Set(types)].sort((a, b) => a - b)) {
    windows.set(type >> 8, [...(windows.get(type >> 8) ?? []), type & 0xff]);
  }
  const parts: Uint8Array[] = [];
  for (const [window, bits] of windows) {
    const length = (Math.max(...bits) >> 3) + 1;
    const block = new Uint8Array(2 + length);
    block[0] = window;
    block[1] = length;
    for (const bit of bits) block[2 + (bit >> 3)] |= 0x80 >> (bit & 7);
    parts.push(block);
  }
  return concatBytes(parts);
}

function nsec3Raw(name: string, salt: Uint8Array, iterations: number): Uint8Array {
  let digest = createHash('sha1')
    .update(concatBytes([encodeName(canonicalName(name)), salt]))
    .digest();
  for (let i = 0; i < iterations; i++) {
    digest = createHash('sha1')
      .update(concatBytes([digest, salt]))
      .digest();
  }
  return Uint8Array.from(digest);
}

const seconds = (date: Date) => Math.floor(date.getTime() / 1000);

// ---- one zone's server

class ZoneData {
  readonly zone: string;
  readonly sets = new Map<string, Set_>();
  readonly glue: Set_[] = [];
  // delegated children
  readonly children = new Set<string>();
  readonly keys: TestKey[];
  readonly signers: TestKey[];
  readonly spec: SignedZone;
  private readonly sigs = new Map<string, ResourceRecord[]>();
  private chain: { owner: string; set: Set_; hash?: string }[] = [];
  private readonly salt: Uint8Array;

  constructor(spec: SignedZone, children: SignedZone[], keysOf: Map<string, TestKey[]>, now: Date) {
    this.spec = spec;
    this.zone = canonicalName(spec.zone);
    this.keys = keysOf.get(this.zone)!;
    this.signers =
      spec.signers ?? this.keys.filter(key => key.flags & 0x0100 && !(key.flags & 0x0080));
    this.salt = spec.nsec3?.salt ? fromHex(spec.nsec3.salt) : new Uint8Array(0);
    const keyTtl = spec.keyTtl ?? 3600;
    const ns = `ns1.${this.zone === '.' ? 'root-servers.test' : this.zone}`;

    this.add(this.zone, 'SOA', 3600, soaRdata(this.zone));
    this.add(this.zone, 'NS', 3600, encodeName(ns));
    if (!spec.unsigned)
      for (const key of this.keys) this.add(this.zone, 'DNSKEY', keyTtl, key.rdata);
    if (isSubdomain(ns, this.zone)) this.add(ns, 'A', 3600, parseIpv4(addressOf(this.zone))!);
    for (const [name, type, value, ttl] of spec.records ?? []) {
      this.add(canonicalName(name), type, ttl ?? 300, rdataOf(type, value));
    }

    for (const child of children) {
      const name = canonicalName(child.zone);
      this.children.add(name);
      const childNs = `ns1.${name}`;
      this.add(name, 'NS', 3600, encodeName(childNs));
      this.glue.push({ name: childNs, type: 1, ttl: 3600, rdatas: [parseIpv4(addressOf(name))!] });
      const childKeys = keysOf.get(name)!;
      const dsKeys =
        child.ds === 'none' ? [] : (child.ds ?? childKeys.filter(key => key.flags & 1));
      for (const key of dsKeys) {
        const digest = computeDsDigest(name, key.rdata, 2)!;
        if (child.badDs) digest[0] ^= 0xff;
        const head = new Uint8Array(4);
        writeU16(head, 0, key.keyTag);
        head[2] = key.algorithm;
        head[3] = 2;
        this.add(name, 'DS', child.keyTtl ?? 3600, concatBytes([head, digest]));
      }
    }

    if (!spec.unsigned) this.buildChain();
    if (!spec.unsigned) for (const set of this.sets.values()) this.signSet(set, now);
  }

  private add(name: string, type: string, ttl: number, rdata: Uint8Array): void {
    const key = `${name}/${type}`;
    const set = this.sets.get(key) ?? { name, type: typeCode(type), ttl, rdatas: [] };
    set.rdatas.push(rdata);
    this.sets.set(key, set);
  }

  get(name: string, type: number): Set_ | undefined {
    return this.sets.get(`${canonicalName(name)}/${typeName(type)}`);
  }

  // owners in the zone itself: not below a cut, apart from the cut's own NS and DS
  private owners(): string[] {
    const names = new Set<string>();
    for (const set of this.sets.values()) {
      if (set.type === 50 || set.type === 47) continue;
      names.add(set.name);
    }
    return [...names];
  }

  private typesAt(name: string): number[] {
    return [...this.sets.values()].filter(set => set.name === name).map(set => set.type);
  }

  private isInsecureCut(name: string): boolean {
    return this.children.has(name) && !this.get(name, 43);
  }

  private buildChain(): void {
    const nsec3 = this.spec.nsec3;
    if (!nsec3) {
      const owners = this.owners().sort(compareNames);
      owners.forEach((owner, index) => {
        const next = owners[(index + 1) % owners.length];
        const types = [...this.typesAt(owner), 46, 47];
        const rdata = concatBytes([encodeName(next), typeBitmap(types)]);
        const set: Set_ = { name: owner, type: 47, ttl: 300, rdatas: [rdata] };
        this.sets.set(`${owner}/NSEC`, set);
        this.chain.push({ owner, set });
      });
      return;
    }
    // empty non-terminals have NSEC3 records too (RFC 5155 §7.1)
    const names = new Set<string>();
    for (const owner of this.owners()) {
      if (nsec3.optOut === true && this.isInsecureCut(owner)) continue;
      let current = owner;
      while (current !== this.zone && isSubdomain(current, this.zone)) {
        names.add(current);
        current = parentName(current);
      }
      names.add(this.zone);
    }
    const iterations = nsec3.iterations ?? 0;
    const hashed = [...names]
      .map(name => ({ name, raw: nsec3Raw(name, this.salt, iterations) }))
      .sort((a, b) => (toBase32Hex(a.raw) < toBase32Hex(b.raw) ? -1 : 1));
    hashed.forEach((entry, index) => {
      const next = hashed[(index + 1) % hashed.length];
      const types = this.typesAt(entry.name);
      const signedTypes = types.length ? [...types, 46] : [];
      const head = new Uint8Array(5);
      head[0] = 1;
      const optOut =
        typeof nsec3.optOut === 'function' ? nsec3.optOut(entry.name) : Boolean(nsec3.optOut);
      head[1] = optOut ? 1 : 0;
      writeU16(head, 2, iterations);
      head[4] = this.salt.length;
      const rdata = concatBytes([
        head,
        this.salt,
        Uint8Array.of(next.raw.length),
        next.raw,
        typeBitmap(signedTypes),
      ]);
      const hash = toBase32Hex(entry.raw).toLowerCase();
      const owner = this.zone === '.' ? hash : `${hash}.${this.zone}`;
      const set: Set_ = { name: owner, type: 50, ttl: 300, rdatas: [rdata] };
      this.sets.set(`${owner}/NSEC3`, set);
      this.chain.push({ owner: entry.name, set, hash });
    });
  }

  private signSet(set: Set_, now: Date): void {
    // the parent does not sign a delegation's NS RRset, nor glue
    if (set.type === 2 && this.children.has(set.name)) return;
    const inception = seconds(this.spec.inception ?? new Date(now.getTime() - 86_400_000));
    const expiration = seconds(this.spec.expiration ?? new Date(now.getTime() + 30 * 86_400_000));
    const wildcard = splitName(set.name)[0] === '*';
    const labels = countLabels(set.name) - (wildcard ? 1 : 0);
    const records: ResourceRecord[] = [];
    for (const key of this.signers) {
      const fixed = new Uint8Array(18);
      writeU16(fixed, 0, set.type);
      fixed[2] = key.algorithm;
      fixed[3] = labels;
      writeU32(fixed, 4, set.ttl);
      writeU32(fixed, 8, expiration);
      writeU32(fixed, 12, inception);
      writeU16(fixed, 16, key.keyTag);
      const prefix = concatBytes([fixed, encodeName(this.zone)]);
      const rrset: Rrset = {
        name: set.name,
        type: set.type,
        typeName: typeName(set.type),
        class: 1,
        ttl: set.ttl,
        records: set.rdatas.map(rdata => wire(set.name, set.type, set.ttl, rdata)),
      };
      const signed = buildSignedData(decodeRrsig(prefix), rrset)!;
      const signature = key.sign(signed.data);
      records.push({
        name: set.name,
        type: 46,
        class: 1,
        ttl: set.ttl,
        rdata: concatBytes([prefix, signature]),
        section: 'answer',
      });
    }
    this.sigs.set(`${set.name}/${set.type}`, records);
  }

  // an RRset with its signatures, as records for a section, under `owner` if given
  records(
    set: Set_,
    section: ResourceRecord['section'],
    dnssec: boolean,
    owner = set.name
  ): ResourceRecord[] {
    const out = set.rdatas.map(rdata => ({ ...wire(owner, set.type, set.ttl, rdata), section }));
    if (!dnssec || this.spec.stripSignatures) return out;
    const sigs = this.sigs.get(`${set.name}/${set.type}`) ?? [];
    return [...out, ...sigs.map(sig => ({ ...sig, name: owner, section }))];
  }

  // ---- denial

  exists(name: string): boolean {
    return [...this.sets.values()].some(
      set => set.type !== 47 && set.type !== 50 && isSubdomain(set.name, name)
    );
  }

  closestEncloser(name: string): string {
    let current = canonicalName(name);
    while (current !== this.zone && !this.exists(current)) current = parentName(current);
    return current;
  }

  // the chain entry at a name, or the one whose range covers it
  private match(name: string): { set: Set_ } | undefined {
    if (this.spec.nsec3) {
      const hash = toBase32Hex(
        nsec3Raw(name, this.salt, this.spec.nsec3.iterations ?? 0)
      ).toLowerCase();
      return this.chain.find(entry => entry.hash === hash);
    }
    return this.chain.find(entry => entry.owner === canonicalName(name));
  }

  private cover(name: string): { set: Set_ } | undefined {
    if (this.spec.nsec3) {
      const hash = toBase32Hex(
        nsec3Raw(name, this.salt, this.spec.nsec3.iterations ?? 0)
      ).toLowerCase();
      const sorted = [...this.chain].sort((a, b) => (a.hash! < b.hash! ? -1 : 1));
      const before = sorted.filter(entry => entry.hash! < hash);
      return before.at(-1) ?? sorted.at(-1);
    }
    const sorted = [...this.chain].sort((a, b) => compareNames(a.owner, b.owner));
    const before = sorted.filter(entry => compareNames(entry.owner, name) < 0);
    return before.at(-1) ?? sorted.at(-1);
  }

  private proofSets(entries: ({ set: Set_ } | undefined)[]): Set_[] {
    const seen = new Set<Set_>();
    for (const entry of entries) if (entry) seen.add(entry.set);
    return [...seen];
  }

  // the NSEC or NSEC3 at the name. An empty non-terminal has no NSEC: the one whose range
  // covers it, and ends below it, shows it is there
  nodataProof(name: string): Set_[] {
    return this.proofSets([this.match(name) ?? (this.spec.nsec3 ? undefined : this.cover(name))]);
  }

  // a name that a wildcard without the type answers for (RFC 4035 §3.1.3.4, RFC 5155 §7.2.5)
  wildcardNodataProof(name: string, encloser: string, wildcard: string): Set_[] {
    if (!this.spec.nsec3) return this.proofSets([this.cover(name), this.match(wildcard)]);
    return this.proofSets([
      this.match(encloser),
      this.cover(nextCloser(name, encloser)),
      this.match(wildcard),
    ]);
  }

  nxdomainProof(name: string): Set_[] {
    const encloser = this.closestEncloser(name);
    const wildcard = encloser === '.' ? '*' : `*.${encloser}`;
    if (!this.spec.nsec3) return this.proofSets([this.cover(name), this.cover(wildcard)]);
    return this.proofSets([
      this.match(encloser),
      this.cover(nextCloser(name, encloser)),
      this.cover(wildcard),
    ]);
  }

  wildcardProof(name: string, encloser: string): Set_[] {
    if (!this.spec.nsec3) return this.proofSets([this.cover(name)]);
    return this.proofSets([this.cover(nextCloser(name, encloser))]);
  }

  noDsProof(child: string): Set_[] {
    if (!this.spec.nsec3 || this.match(child)) return this.proofSets([this.match(child)]);
    // opt-out: the closest encloser in the chain, and the opt-out range over the child
    const encloser = parentName(child);
    return this.proofSets([this.match(encloser), this.cover(child)]);
  }
}

function nextCloser(name: string, encloser: string): string {
  const labels = splitName(canonicalName(name));
  return labels.slice(labels.length - countLabels(encloser) - 1).join('.');
}

function wire(name: string, type: number, ttl: number, rdata: Uint8Array): WireRecord {
  return { name, type, typeName: typeName(type), class: 1, ttl, rdata, section: 'answer' };
}

function soaRdata(zone: string): Uint8Array {
  const suffix = zone === '.' ? '' : `.${zone}`;
  const numbers = new Uint8Array(20);
  [1, 7200, 3600, 1_209_600, 300].forEach((value, index) => writeU32(numbers, index * 4, value));
  return concatBytes([encodeName(`ns1${suffix}`), encodeName(`hostmaster${suffix}`), numbers]);
}

const zoneAddresses = new Map<string, string>();
function addressOf(zone: string): string {
  return zoneAddresses.get(canonicalName(zone))!;
}

function serve(data: ZoneData): SimulatedServer {
  const zone = data.zone;
  return (query: Message) => {
    const [question] = query.questions;
    const name = canonicalName(question.name);
    const type = question.type;
    const dnssec = query.edns?.dnssecOk ?? false;
    const reply = (parts: Partial<Message> & { aa?: boolean }) =>
      encodeMessage({
        id: query.id,
        flags: { qr: true, aa: parts.aa ?? false },
        questions: query.questions,
        edns: { udpPayloadSize: 4096, version: 0, dnssecOk: dnssec, options: [] },
        ...parts,
      });
    const soa = () => data.records(data.get(zone, 6)!, 'authority', dnssec);
    const proof = (sets: Set_[]) =>
      dnssec && data.spec.dropProofs !== true
        ? sets.flatMap(set => data.records(set, 'authority', true))
        : [];

    if (!isSubdomain(name, zone)) return reply({ rcode: 5 });

    // a delegated name: the parent answers a DS question at the cut itself, and refers
    // anything else
    const child = [...data.children]
      .filter(delegated => isSubdomain(name, delegated))
      .sort((a, b) => b.length - a.length)[0];
    if (child !== undefined) {
      const ds = data.get(child, 43);
      if (name === child && type === 43) {
        if (ds) return reply({ aa: true, answers: data.records(ds, 'answer', dnssec) });
        return reply({ aa: true, authorities: [...soa(), ...proof(data.noDsProof(child))] });
      }
      const ns = data.get(child, 2)!;
      return reply({
        authorities: [
          ...data.records(ns, 'authority', false),
          ...(ds
            ? dnssec
              ? data.records(ds, 'authority', true)
              : []
            : proof(data.noDsProof(child))),
        ],
        additionals: data.glue
          .filter(set => isSubdomain(set.name, child))
          .flatMap(set => data.records(set, 'additional', false)),
      });
    }

    const exact = data.get(name, type);
    if (exact) return reply({ aa: true, answers: data.records(exact, 'answer', dnssec) });

    const cname = data.get(name, 5);
    if (cname) {
      const answers = data.records(cname, 'answer', dnssec);
      const target = data.get(decodeTarget(cname.rdatas[0]), type);
      if (target) answers.push(...data.records(target, 'answer', dnssec));
      return reply({ aa: true, answers });
    }

    // a DNAME above the name: the DNAME, and the CNAME it makes, unsigned (RFC 6672 §3.4)
    for (let above = parentName(name); isSubdomain(above, zone); above = parentName(above)) {
      const dname = data.get(above, 39);
      if (dname) {
        const labels = splitName(name);
        const prefix = labels.slice(0, labels.length - countLabels(above));
        const target = canonicalName(
          [...prefix, ...splitName(decodeTarget(dname.rdatas[0]))].join('.')
        );
        return reply({
          aa: true,
          answers: [
            ...data.records(dname, 'answer', dnssec),
            { ...wire(name, 5, dname.ttl, encodeName(target)), section: 'answer' },
          ],
        });
      }
      if (above === zone) break;
    }

    if (data.exists(name)) {
      return reply({ aa: true, authorities: [...soa(), ...proof(data.nodataProof(name))] });
    }

    // a wildcard at the closest encloser
    const encloser = data.closestEncloser(name);
    const wildcardName = encloser === '.' ? '*' : `*.${encloser}`;
    const wildcard = data.get(wildcardName, type) ?? data.get(wildcardName, 5);
    if (wildcard) {
      return reply({
        aa: true,
        answers: data.records(wildcard, 'answer', dnssec, name),
        authorities:
          data.spec.dropProofs === 'wildcard' ? [] : proof(data.wildcardProof(name, encloser)),
      });
    }
    if (data.exists(wildcardName)) {
      return reply({
        aa: true,
        authorities: [...soa(), ...proof(data.wildcardNodataProof(name, encloser, wildcardName))],
      });
    }

    return reply({
      aa: true,
      rcode: 3,
      authorities: [...soa(), ...proof(data.nxdomainProof(name))],
    });
  };
}

function decodeTarget(rdata: Uint8Array): string {
  const labels: string[] = [];
  let pos = 0;
  while (rdata[pos]) {
    labels.push(new TextDecoder().decode(rdata.subarray(pos + 1, pos + 1 + rdata[pos])));
    pos += 1 + rdata[pos];
  }
  return canonicalName(labels.join('.') || '.');
}

// ---- a tree of zones

// build and serve a tree of signed zones. The first zone is the root of the tree, and
// should be '.'. Every other zone is delegated from the deepest zone above it
export function signedNetwork(zones: SignedZone[], now = new Date()): SignedNetwork {
  const keysOf = new Map<string, TestKey[]>();
  zones.forEach((spec, index) => {
    const zone = canonicalName(spec.zone);
    zoneAddresses.set(zone, `10.53.${Math.floor(index / 250)}.${(index % 250) + 1}`);
    keysOf.set(zone, spec.unsigned ? [] : (spec.keys ?? [ecdsaKey()]));
  });
  const parentOf = (spec: SignedZone) =>
    zones
      .filter(other => other !== spec && canonicalName(spec.zone) !== canonicalName(other.zone))
      .filter(other => isSubdomain(spec.zone, other.zone))
      .sort((a, b) => countLabels(b.zone) - countLabels(a.zone))[0];

  const servers: Record<string, SimulatedServer> = {};
  const data = new Map<string, ZoneData>();
  for (const spec of zones) {
    const children = zones.filter(other => parentOf(other) === spec);
    const zoneData = new ZoneData(spec, children, keysOf, now);
    data.set(zoneData.zone, zoneData);
    servers[addressOf(zoneData.zone)] = serve(zoneData);
  }
  servers[RECURSIVE] = recursiveOver(
    zones.map(spec => canonicalName(spec.zone)),
    servers
  );

  const root = keysOf.get('.') ?? [];
  return {
    servers,
    rootServers: [{ name: 'ns1.root-servers.test', ipv4: addressOf('.') }],
    trustAnchors: root.filter(key => key.flags & 1).map(key => anchorFor(key)),
    recursive: RECURSIVE,
    keys: Object.fromEntries(keysOf),
  };
}

// a recursive resolver over the zones: it asks the zone that holds a name (the parent, for
// a DS at a cut), and follows aliases into other zones, as a resolver does
function recursiveOver(zones: string[], servers: Record<string, SimulatedServer>): SimulatedServer {
  const holder = (name: string, type: number) => {
    const holding = zones
      .filter(zone => isSubdomain(name, zone))
      .sort((a, b) => countLabels(b) - countLabels(a));
    if (type === 43 && holding[0] === name && holding.length > 1) return holding[1];
    return holding[0];
  };
  return async query => {
    const [question] = query.questions;
    let name = canonicalName(question.name);
    const answers: ResourceRecord[] = [];
    // the proofs of every zone on the way: a wildcard's in one, a denial in the next
    const authorities: ResourceRecord[] = [];
    let last: Message | undefined;
    for (let step = 0; step < 8; step++) {
      const zone = holder(name, question.type);
      const asked: Message = { ...query, questions: [{ ...question, name }] };
      const bytes = await servers[addressOf(zone)](asked);
      if (!(bytes instanceof Uint8Array)) return bytes;
      last = decodeMessage(bytes);
      answers.push(...last.answers);
      authorities.push(...last.authorities);
      const alias = last.answers.find(
        record => record.type === 5 && canonicalName(record.name) === name
      );
      if (!alias || question.type === 5) break;
      const target = decodeTarget(alias.rdata);
      const answered = last.answers.some(
        record => record.type === question.type && canonicalName(record.name) === target
      );
      if (answered) break;
      name = target;
    }
    return encodeMessage({
      id: query.id,
      flags: { qr: true, ra: true, rd: query.flags.rd, cd: query.flags.cd },
      rcode: last!.rcode,
      questions: query.questions,
      answers,
      authorities,
      additionals: last!.additionals,
      edns: last!.edns,
    });
  };
}
