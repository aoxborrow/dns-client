import {
  verifyNoDsProof,
  verifyNodataProof,
  verifyNxdomainProof,
  verifyWildcardProof,
  nextCloserOptOut,
  assessNsec3Params,
} from '../../src/dnssec/nsec';
import { nsec3Hash } from '../../src/dnssec/canonical';
import type { ResourceRecord } from '../../src/wire/message';
import { RECORD_TYPES } from '../../src/protocol/types';
import { encodeName } from '../../src/wire/names';
import { PROOF_STATUSES, VERIFICATION_RESULTS } from '../../src/dnssec/constants';

const { VERIFIED, FAILED, UNCHECKED } = VERIFICATION_RESULTS;
const { A: TYPE_A, NSEC: TYPE_NSEC, NSEC3: TYPE_NSEC3 } = RECORD_TYPES;

// ---------------------------------------------------------------------------
// builders
// ---------------------------------------------------------------------------

// encode an RFC 4034 §4.1.2 type bitmap for the given type codes (window 0 only, which
// covers every type these tests use)
function typeBitmap(types: number[]): Buffer {
  if (types.length === 0) return Buffer.alloc(0);
  const maxByte = Math.floor(Math.max(...types) / 8);
  const bytes = Buffer.alloc(maxByte + 1);
  for (const type of types) {
    bytes[Math.floor(type / 8)] |= 0x80 >> (type % 8);
  }
  return Buffer.concat([Buffer.from([0, bytes.length]), bytes]);
}

function nsecRecord(owner: string, next: string, types: number[]): ResourceRecord {
  return {
    name: owner,
    type: TYPE_NSEC,
    class: 1,
    ttl: 3600,
    rdata: Buffer.concat([encodeName(next), typeBitmap(types)]),
    section: 'authority',
  };
}

// base32hex alphabet, for turning a hash label back into raw bytes
const BASE32HEX = '0123456789abcdefghijklmnopqrstuv';

function fromBase32Hex(value: string): Buffer {
  let bits = 0;
  let acc = 0;
  const out: number[] = [];
  for (const char of value.toLowerCase()) {
    acc = (acc << 5) | BASE32HEX.indexOf(char);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((acc >> bits) & 0xff);
    }
  }
  return Buffer.from(out);
}

function nsec3Record(
  ownerHash: string,
  zone: string,
  nextHash: string,
  types: number[],
  options: { salt?: Buffer; iterations?: number; optOut?: boolean } = {}
): ResourceRecord {
  const salt = options.salt ?? Buffer.alloc(0);
  const next = fromBase32Hex(nextHash);
  const head = Buffer.alloc(5);
  head.writeUInt8(1, 0); // SHA-1
  head.writeUInt8(options.optOut ? 0x01 : 0, 1);
  head.writeUInt16BE(options.iterations ?? 0, 2);
  head.writeUInt8(salt.length, 4);

  return {
    name: `${ownerHash}.${zone}`,
    type: TYPE_NSEC3,
    class: 1,
    ttl: 3600,
    rdata: Buffer.concat([head, salt, Buffer.from([next.length]), next, typeBitmap(types)]),
    section: 'authority',
  };
}

const TYPE_NS = 2;
const TYPE_CNAME = 5;
const TYPE_SOA = 6;
const TYPE_MX = 15;
const TYPE_DNAME = 39;
const TYPE_DS = 43;
const TYPE_RRSIG = 46;

// ---------------------------------------------------------------------------

describe('verifyNoDsProof — NSEC', () => {
  it('accepts a delegation NSEC whose bitmap has NS and no DS', () => {
    const proof = verifyNoDsProof('unsigned.example', [
      nsecRecord('unsigned.example', 'zzz.example', [TYPE_NS, TYPE_RRSIG]),
    ]);
    expect(proof.result).toBe(VERIFIED);
    expect(proof.status).toBe(PROOF_STATUSES.VERIFIED);
    expect(proof.optOut).toBe(false);
  });

  it('rejects an NSEC whose bitmap lists DS, which contradicts the empty answer', () => {
    const proof = verifyNoDsProof('signed.example', [
      nsecRecord('signed.example', 'zzz.example', [TYPE_NS, TYPE_DS, TYPE_RRSIG]),
    ]);
    expect(proof.result).toBe(FAILED);
    expect(proof.reason).toMatch(/lists DS/);
  });

  it('rejects an apex NSEC, which says nothing about a child', () => {
    // SOA without NS is the zone apex — RFC 6840 §4.4
    const proof = verifyNoDsProof('example', [
      nsecRecord('example', 'a.example', [TYPE_SOA, TYPE_RRSIG]),
    ]);
    expect(proof.result).toBe(FAILED);
    expect(proof.status).toBe(PROOF_STATUSES.INCOMPLETE);
  });

  it('accepts a covering NSEC, which proves the name does not exist at all', () => {
    const proof = verifyNoDsProof('m.example', [nsecRecord('a.example', 'z.example', [TYPE_A])]);
    expect(proof.result).toBe(VERIFIED);
  });

  it('handles the wrap-around NSEC at the end of a zone', () => {
    // the last NSEC points back at the apex, so its range runs past the end of the zone
    const proof = verifyNoDsProof('zz.example', [nsecRecord('z.example', 'example', [TYPE_A])]);
    expect(proof.result).toBe(VERIFIED);
  });

  it('rejects an NSEC set that neither matches nor covers the name', () => {
    const proof = verifyNoDsProof('q.example', [nsecRecord('a.example', 'b.example', [TYPE_A])]);
    expect(proof.result).toBe(FAILED);
    expect(proof.status).toBe(PROOF_STATUSES.INCOMPLETE);
  });

  it('does not let an escaped dot in the next name stretch the range', () => {
    // the range a.example .. "b.z".example ends before y.example in canonical order. Read as
    // a split string the next name ends in "z" and the range would swallow y.example, proving
    // a delegation that exists has no DS
    const proof = verifyNoDsProof('y.example', [
      nsecRecord('a.example', 'b\\.z.example', [TYPE_A]),
    ]);
    expect(proof.result).toBe(FAILED);
    expect(proof.status).toBe(PROOF_STATUSES.INCOMPLETE);
  });

  it('accepts a range whose owner has an escaped dot when it really covers the name', () => {
    const proof = verifyNoDsProof('b.example', [
      nsecRecord('a\\.z.example', 'c.example', [TYPE_A]),
    ]);
    expect(proof.result).toBe(VERIFIED);
  });

  it('fails when no denial records are returned at all', () => {
    // absence of records is not a proof of absence — this is the spoofable case the old
    // engine treated as "insecure"
    const proof = verifyNoDsProof('anything.example', []);
    expect(proof.result).toBe(FAILED);
    expect(proof.status).toBe(PROOF_STATUSES.MISSING);
    expect(proof.reason).toMatch(/unproven/);
  });
});

describe('verifyNoDsProof — NSEC3', () => {
  const zone = 'example';
  const salt = Buffer.alloc(0);

  it('accepts a matching NSEC3 whose bitmap has NS and no DS', () => {
    const hash = nsec3Hash('unsigned.example', salt, 0)!;
    const proof = verifyNoDsProof('unsigned.example', [
      nsec3Record(hash, zone, 'vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv', [TYPE_NS, TYPE_RRSIG]),
    ]);
    expect(proof.result).toBe(VERIFIED);
    expect(proof.nsec3Params?.conforms).toBe(true);
  });

  it('rejects a matching NSEC3 whose bitmap lists DS', () => {
    const hash = nsec3Hash('signed.example', salt, 0)!;
    const proof = verifyNoDsProof('signed.example', [
      nsec3Record(hash, zone, 'vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv', [TYPE_NS, TYPE_DS]),
    ]);
    expect(proof.result).toBe(FAILED);
  });

  it('reports opt-out as unchecked rather than verified', () => {
    // the covering NSEC3 asserts the absence but does not authenticate it (RFC 5155 §6)
    const encloserHash = nsec3Hash('example', salt, 0)!;
    const nextCloserHash = nsec3Hash('child.example', salt, 0)!;

    const proof = verifyNoDsProof('child.example', [
      // a real NSEC3 chain partitions the hash space, so the apex record's range stops
      // immediately and only the second record can cover the next closer name
      nsec3Record(encloserHash, zone, incrementHash(encloserHash), [TYPE_NS, TYPE_SOA]),
      nsec3Record(decrementHash(nextCloserHash), zone, incrementHash(nextCloserHash), [TYPE_NS], {
        optOut: true,
      }),
    ]);
    expect(proof.status).toBe(PROOF_STATUSES.OPT_OUT);
    expect(proof.result).toBe(UNCHECKED);
    expect(proof.optOut).toBe(true);
  });

  it('accepts a non-opt-out covering proof as authenticated', () => {
    const encloserHash = nsec3Hash('example', salt, 0)!;
    const nextCloserHash = nsec3Hash('child.example', salt, 0)!;

    const proof = verifyNoDsProof('child.example', [
      nsec3Record(encloserHash, zone, incrementHash(encloserHash), [TYPE_NS, TYPE_SOA]),
      nsec3Record(decrementHash(nextCloserHash), zone, incrementHash(nextCloserHash), [TYPE_NS]),
    ]);
    expect(proof.status).toBe(PROOF_STATUSES.VERIFIED);
    expect(proof.result).toBe(VERIFIED);
  });

  it('leaves an unsupported NSEC3 hash algorithm unchecked', () => {
    const record = nsec3Record('aaaa', zone, 'vvvv', [TYPE_NS]);
    record.rdata[0] = 2; // an algorithm RFC 5155 does not define
    const proof = verifyNoDsProof('child.example', [record]);
    expect(proof.status).toBe(PROOF_STATUSES.UNSUPPORTED_ALGORITHM);
    expect(proof.result).toBe(UNCHECKED);
  });

  it('honours the iteration count and salt when hashing', () => {
    const salted = Buffer.from('aabbccdd', 'hex');
    const hash = nsec3Hash('unsigned.example', salted, 12)!;
    const proof = verifyNoDsProof('unsigned.example', [
      nsec3Record(hash, zone, 'vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv', [TYPE_NS], {
        salt: salted,
        iterations: 12,
      }),
    ]);
    expect(proof.result).toBe(VERIFIED);
    expect(proof.nsec3Params?.iterations).toBe(12);
    expect(proof.nsec3Params?.conforms).toBe(false);
  });
});

describe('verifyNodataProof', () => {
  it('accepts an NSEC that matches the name without the type in its bitmap', () => {
    const proof = verifyNodataProof('example', TYPE_A, [
      nsecRecord('example', 'a.example', [TYPE_SOA, TYPE_NS]),
    ]);
    expect(proof.result).toBe(VERIFIED);
  });

  it('rejects an NSEC that lists the type it claims is absent', () => {
    const proof = verifyNodataProof('example', TYPE_A, [
      nsecRecord('example', 'a.example', [TYPE_A, TYPE_SOA]),
    ]);
    expect(proof.result).toBe(FAILED);
  });

  it('rejects an NSEC3 whose bitmap lists CNAME, an alias with its CNAME stripped', () => {
    // RFC 5155 §8.5: neither the type asked for nor CNAME may be set
    const hash = nsec3Hash('alias.example', Buffer.alloc(0), 0)!;
    const proof = verifyNodataProof('alias.example', TYPE_A, [
      nsec3Record(hash, 'example', incrementHash(hash), [TYPE_CNAME, TYPE_RRSIG]),
    ]);
    expect(proof.result).toBe(FAILED);
    expect(proof.steps.find(step => step.label === 'Type bitmap')?.detail).toContain('CNAME');
  });

  it('accepts an NSEC3 that matches the name without the type or CNAME', () => {
    const hash = nsec3Hash('mail.example', Buffer.alloc(0), 0)!;
    const proof = verifyNodataProof('mail.example', TYPE_A, [
      nsec3Record(hash, 'example', incrementHash(hash), [TYPE_MX, TYPE_RRSIG]),
    ]);
    expect(proof.result).toBe(VERIFIED);
  });

  it('rejects an NSEC whose bitmap lists CNAME, and says why', () => {
    const proof = verifyNodataProof('alias.example', TYPE_A, [
      nsecRecord('alias.example', 'b.example', [TYPE_CNAME, TYPE_RRSIG]),
    ]);
    expect(proof.result).toBe(FAILED);
    expect(proof.steps.find(step => step.label === 'Type bitmap')?.result).toBe(FAILED);
  });
});

describe('verifyNxdomainProof', () => {
  it('checks the wildcard at the real closest encloser when a label holds a dot', () => {
    // the covering NSEC's owner is "a.b".example, so the closest encloser of x.b.example is
    // example and *.example must be proven absent. Splitting on every dot reads the shared
    // suffix as b.example and checks *.b.example instead, which this same range covers
    const proof = verifyNxdomainProof('x.b.example', [
      nsecRecord('example', '*.example', [TYPE_SOA, TYPE_NS]),
      nsecRecord('*.example', 'a\\.b.example', [TYPE_A]),
      nsecRecord('a\\.b.example', 'c.example', [TYPE_A]),
    ]);
    expect(proof.result).toBe(FAILED);
    expect(proof.steps[1].detail).toContain('*.example');
    expect(proof.steps[1].result).toBe(FAILED);
  });

  it('checks the wildcard at an empty non-terminal only the next name reveals', () => {
    // example.com holds example.com, a.example.com and c.b.example.com, so b.example.com is an
    // empty non-terminal. For a.b.example.com the one NSEC a.example.com -> c.b.example.com
    // covers the name and *.b.example.com, the wildcard at the real closest encloser, which is
    // all RFC 4035 §3.1.3.2 asks a server to send
    const proof = verifyNxdomainProof('a.b.example.com', [
      nsecRecord('a.example.com', 'c.b.example.com', [TYPE_A]),
    ]);
    expect(proof.result).toBe(VERIFIED);
    expect(proof.steps[1].detail).toContain('*.b.example.com');
  });

  it('rejects an NSEC whose next name lies below the name: the name is an empty non-terminal', () => {
    // a.example.com -> x.b.example.com proves b.example.com exists, with nothing of its own;
    // a NODATA for it turned into NXDOMAIN must not pass
    const proof = verifyNxdomainProof('b.example.com', [
      nsecRecord('a.example.com', 'x.b.example.com', [TYPE_A]),
      nsecRecord('example.com', 'a.example.com', [TYPE_SOA, TYPE_NS]),
    ]);
    expect(proof.result).toBe(FAILED);
    expect(proof.steps[0].result).toBe(FAILED);
  });

  it('rejects an NSEC3 proof when an NSEC3 matches the name itself', () => {
    // an empty non-terminal has an NSEC3 of its own: it exists, so NXDOMAIN is wrong
    const salt = Buffer.alloc(0);
    const apex = nsec3Hash('example', salt, 0)!;
    const self = nsec3Hash('ent.example', salt, 0)!;
    const wildcard = nsec3Hash('*.example', salt, 0)!;
    const proof = verifyNxdomainProof('ent.example', [
      nsec3Record(apex, 'example', incrementHash(apex), [TYPE_SOA]),
      nsec3Record(self, 'example', incrementHash(self), []),
      // a range over the next closer name (the name itself) and the wildcard, from a chain
      // that no longer matches the zone
      nsec3Record(decrementHash(self), 'example', incrementHash(self), []),
      nsec3Record(decrementHash(wildcard), 'example', incrementHash(wildcard), []),
    ]);
    expect(proof.result).toBe(FAILED);
  });

  it('accepts the proof once *.example is shown absent', () => {
    const proof = verifyNxdomainProof('x.b.example', [
      nsecRecord('example', 'a\\.b.example', [TYPE_SOA, TYPE_NS]),
      nsecRecord('a\\.b.example', 'c.example', [TYPE_A]),
    ]);
    expect(proof.result).toBe(VERIFIED);
  });
});

describe('assessNsec3Params', () => {
  it('passes the RFC 9276 recommendation of no iterations and no salt', () => {
    const params = assessNsec3Params(1, 0, Buffer.alloc(0), false);
    expect(params.conforms).toBe(true);
    expect(params.notes).toEqual([]);
  });

  it('flags a non-zero iteration count and names the validator thresholds', () => {
    expect(assessNsec3Params(1, 51, Buffer.alloc(0), false).notes[0]).toMatch(
      /counts above 50 as insecure/
    );
    expect(assessNsec3Params(1, 600, Buffer.alloc(0), false).notes[0]).toMatch(
      /SERVFAIL above 500/
    );
  });

  it('flags a salt', () => {
    const params = assessNsec3Params(1, 0, Buffer.from('a3b1f9', 'hex'), false);
    expect(params.conforms).toBe(false);
    expect(params.salt).toBe('a3b1f9');
    expect(params.notes.join(' ')).toMatch(/no salt/);
  });

  it('flags opt-out as unauthenticated absence', () => {
    expect(assessNsec3Params(1, 0, Buffer.alloc(0), true).notes.join(' ')).toMatch(
      /not authenticated/
    );
  });

  it('flags a hash algorithm it cannot compute', () => {
    const params = assessNsec3Params(2, 0, Buffer.alloc(0), false);
    expect(params.conforms).toBe(false);
    expect(params.notes.join(' ')).toMatch(/cannot be verified/);
  });
});

// nudge a base32hex hash one step down or up, to build a range that brackets it
function decrementHash(hash: string): string {
  const chars = [...hash];
  for (let i = chars.length - 1; i >= 0; i--) {
    const index = BASE32HEX.indexOf(chars[i]);
    if (index > 0) {
      chars[i] = BASE32HEX[index - 1];
      return chars.join('');
    }
    chars[i] = BASE32HEX[BASE32HEX.length - 1];
  }
  return chars.join('');
}

function incrementHash(hash: string): string {
  const chars = [...hash];
  for (let i = chars.length - 1; i >= 0; i--) {
    const index = BASE32HEX.indexOf(chars[i]);
    if (index < BASE32HEX.length - 1) {
      chars[i] = BASE32HEX[index + 1];
      return chars.join('');
    }
    chars[i] = BASE32HEX[0];
  }
  return chars.join('');
}

// ---------------------------------------------------------------------------
// wildcard-expansion proof (RFC 4035 §5.3.4)
// ---------------------------------------------------------------------------

describe('verifyWildcardProof', () => {
  it('accepts an NSEC that covers the queried name (no exact match exists)', () => {
    // foo.example was synthesised from *.example; an NSEC covering foo.example proves it has no
    // records of its own, so the wildcard legitimately answered
    const proof = verifyWildcardProof(
      'foo.example',
      [nsecRecord('example', 'www.example', [TYPE_A])],
      '*.example'
    );
    expect(proof.result).toBe(VERIFIED);
    expect(proof.status).toBe(PROOF_STATUSES.VERIFIED);
  });

  it('rejects an NSEC that does not cover the queried name', () => {
    const proof = verifyWildcardProof(
      'foo.example',
      [nsecRecord('aaa.example', 'bbb.example', [TYPE_A])],
      '*.example'
    );
    expect(proof.result).toBe(FAILED);
  });

  it('rejects a wildcard answer that carries no proof at all', () => {
    const proof = verifyWildcardProof('foo.example', [], '*.example');
    expect(proof.result).toBe(FAILED);
  });

  it('accepts an NSEC3 closest-encloser + next-closer cover', () => {
    const encloser = nsec3Hash('example', Buffer.alloc(0), 0)!;
    const nextCloser = nsec3Hash('foo.example', Buffer.alloc(0), 0)!;
    const proof = verifyWildcardProof(
      'foo.example',
      [
        // the closest encloser (example) exists — a matching NSEC3
        nsec3Record(encloser, 'example', incrementHash(encloser), [TYPE_SOA]),
        // the next-closer name (foo.example) is covered, so it has no exact match
        nsec3Record(decrementHash(nextCloser), 'example', incrementHash(nextCloser), []),
      ],
      '*.example'
    );
    expect(proof.result).toBe(VERIFIED);
    expect(proof.status).toBe(PROOF_STATUSES.VERIFIED);
  });

  it('takes the next closer name label by label when a label holds a dot', () => {
    // a.b\.c.example is three labels, so the next closer under example is "b.c".example,
    // not c.example. A range over c.example alone proves nothing about it
    const encloser = nsec3Hash('example', Buffer.alloc(0), 0)!;
    const wrong = nsec3Hash('c.example', Buffer.alloc(0), 0)!;
    const right = nsec3Hash('b\\.c.example', Buffer.alloc(0), 0)!;
    const apex = nsec3Record(encloser, 'example', incrementHash(encloser), [TYPE_SOA]);

    const rejected = verifyWildcardProof(
      'a.b\\.c.example',
      [apex, nsec3Record(decrementHash(wrong), 'example', incrementHash(wrong), [])],
      '*.example'
    );
    expect(rejected.result).toBe(FAILED);

    const accepted = verifyWildcardProof(
      'a.b\\.c.example',
      [apex, nsec3Record(decrementHash(right), 'example', incrementHash(right), [])],
      '*.example'
    );
    expect(accepted.result).toBe(VERIFIED);
  });

  it('rejects a higher wildcard replayed under a nearer closest encloser (NSEC)', () => {
    // *.example.com's signed A replayed for a.b.example.com. The NSEC from b.example.com to
    // c.example.com covers a.b.example.com, but b.example.com exists, so the closest encloser
    // is b.example.com and only *.b.example.com could have answered
    const nsec = [nsecRecord('b.example.com', 'c.example.com', [TYPE_A])];
    const replayed = verifyWildcardProof('a.b.example.com', nsec, '*.example.com');
    expect(replayed.result).toBe(FAILED);
    expect(replayed.steps.find(step => step.label === 'Wildcard')?.result).toBe(FAILED);

    const nearer = verifyWildcardProof('a.b.example.com', nsec, '*.b.example.com');
    expect(nearer.result).toBe(VERIFIED);
  });

  it('takes the closest encloser from the next name when it is the deeper one (NSEC)', () => {
    // z.b.example exists, so b.example does too: the closest encloser of x.b.example is
    // b.example even though the NSEC's owner shares only example with it
    const nsec = [nsecRecord('a.example', 'z.b.example', [TYPE_A])];
    expect(verifyWildcardProof('x.b.example', nsec, '*.example').result).toBe(FAILED);
    expect(verifyWildcardProof('x.b.example', nsec, '*.b.example').result).toBe(VERIFIED);
  });

  it('rejects a higher wildcard replayed under a nearer closest encloser (NSEC3)', () => {
    // b.example exists (an NSEC3 matches it), so the next closer under *.example is b.example,
    // which no range covers. The cover of a.b.example only fits *.b.example
    const salt = Buffer.alloc(0);
    const encloser = nsec3Hash('b.example', salt, 0)!;
    const qnameHash = nsec3Hash('a.b.example', salt, 0)!;
    const records = [
      nsec3Record(encloser, 'example', incrementHash(encloser), [TYPE_A]),
      nsec3Record(decrementHash(qnameHash), 'example', incrementHash(qnameHash), []),
    ];
    expect(verifyWildcardProof('a.b.example', records, '*.example').result).toBe(FAILED);
    expect(verifyWildcardProof('a.b.example', records, '*.b.example').result).toBe(VERIFIED);
  });

  it('needs no NSEC3 matching the closest encloser, which the RRSIG labels already give', () => {
    // RFC 5155 §7.2.5: a wildcard answer carries only the NSEC3 covering the next closer name
    const nextCloser = nsec3Hash('foo.example', Buffer.alloc(0), 0)!;
    const proof = verifyWildcardProof(
      'foo.example',
      [nsec3Record(decrementHash(nextCloser), 'example', incrementHash(nextCloser), [])],
      '*.example'
    );
    expect(proof.result).toBe(VERIFIED);
  });

  it('rejects a wildcard that is not above the queried name', () => {
    const nsec = [nsecRecord('example', 'www.example', [TYPE_A])];
    expect(verifyWildcardProof('foo.example', nsec, '*.other').result).toBe(FAILED);
    expect(verifyWildcardProof('foo.example', nsec, '*.foo.example').result).toBe(FAILED);
  });
});

describe('verifyNodataProof — names without an NSEC of their own', () => {
  it('accepts an empty non-terminal: a range that covers it and ends below it', () => {
    // b.example exists only because a.b.example does
    const proof = verifyNodataProof('b.example', TYPE_A, [
      nsecRecord('a.example', 'a.b.example', [TYPE_A]),
    ]);
    expect(proof.result).toBe(VERIFIED);
    expect(proof.steps[0].label).toBe('Empty non-terminal');
  });

  it('accepts a wildcard without the type, at the closest encloser', () => {
    const proof = verifyNodataProof('foo.example', TYPE_A, [
      nsecRecord('example', '*.example', [TYPE_SOA, TYPE_NS]),
      nsecRecord('*.example', 'www.example', [TYPE_MX]),
    ]);
    expect(proof.result).toBe(VERIFIED);
    expect(proof.steps.map(step => step.label)).toEqual([
      'Covering NSEC',
      'Wildcard',
      'Type bitmap',
    ]);
  });

  it('rejects a wildcard that holds the type, or CNAME', () => {
    for (const types of [[TYPE_A], [TYPE_CNAME]]) {
      const proof = verifyNodataProof('foo.example', TYPE_A, [
        nsecRecord('*.example', 'www.example', types),
      ]);
      expect(proof.result).toBe(FAILED);
    }
  });

  it('rejects a wildcard that is not at the closest encloser', () => {
    // sub.example exists, so foo.sub.example could only come from *.sub.example
    const proof = verifyNodataProof('foo.sub.example', TYPE_A, [
      nsecRecord('*.example', 'sub.example', [TYPE_MX]),
      nsecRecord('sub.example', 'www.example', [TYPE_A]),
    ]);
    expect(proof.result).toBe(FAILED);
  });

  it('accepts an NSEC3 wildcard NODATA proof (RFC 5155 §8.7)', () => {
    const encloser = nsec3Hash('example', Buffer.alloc(0), 0)!;
    const nextCloser = nsec3Hash('foo.example', Buffer.alloc(0), 0)!;
    const wildcard = nsec3Hash('*.example', Buffer.alloc(0), 0)!;
    const records = [
      nsec3Record(encloser, 'example', incrementHash(encloser), [TYPE_SOA, TYPE_NS]),
      nsec3Record(decrementHash(nextCloser), 'example', incrementHash(nextCloser), []),
      nsec3Record(wildcard, 'example', incrementHash(wildcard), [TYPE_MX]),
    ];
    expect(verifyNodataProof('foo.example', TYPE_A, records).result).toBe(VERIFIED);
    expect(verifyNodataProof('foo.example', TYPE_MX, records).result).toBe(FAILED);
  });

  it('calls a next closer name in an opt-out range opt-out, not proven (RFC 5155 §8.6)', () => {
    const encloser = nsec3Hash('example', Buffer.alloc(0), 0)!;
    const nextCloser = nsec3Hash('foo.example', Buffer.alloc(0), 0)!;
    const range = (optOut: boolean) => [
      nsec3Record(encloser, 'example', incrementHash(encloser), [TYPE_SOA, TYPE_NS]),
      nsec3Record(decrementHash(nextCloser), 'example', incrementHash(nextCloser), [], {
        optOut,
      }),
    ];
    expect(verifyNodataProof('foo.example', TYPE_A, range(true)).status).toBe(
      PROOF_STATUSES.OPT_OUT
    );
    expect(verifyNodataProof('foo.example', TYPE_A, range(false)).result).toBe(FAILED);
  });
});

describe('records at a delegation or a DNAME (RFC 6840 §4.1)', () => {
  const delegation = nsecRecord('child.example', 'zzz.example', [TYPE_NS, TYPE_RRSIG]);

  it('does not let the parent deny names below a delegation', () => {
    const proof = verifyNxdomainProof('www.child.example', [
      delegation,
      nsecRecord('example', 'child.example', [TYPE_SOA, TYPE_NS]),
    ]);
    expect(proof.result).toBe(FAILED);
  });

  it('does not let a DNAME deny names below it', () => {
    const proof = verifyNxdomainProof('www.moved.example', [
      nsecRecord('moved.example', 'zzz.example', [TYPE_DNAME, TYPE_RRSIG]),
      nsecRecord('example', 'moved.example', [TYPE_SOA, TYPE_NS]),
    ]);
    expect(proof.result).toBe(FAILED);
  });

  it('lets the parent deny a DS at the delegation, and nothing else there', () => {
    expect(verifyNodataProof('child.example', TYPE_DS, [delegation]).result).toBe(VERIFIED);
    const proof = verifyNodataProof('child.example', TYPE_A, [delegation]);
    expect(proof.result).toBe(FAILED);
    expect(proof.steps.at(-1)?.label).toBe('Delegation');
  });

  it('does not take an NSEC3 delegation as the closest encloser', () => {
    const cut = nsec3Hash('child.example', Buffer.alloc(0), 0)!;
    const nextCloser = nsec3Hash('www.child.example', Buffer.alloc(0), 0)!;
    const wildcard = nsec3Hash('*.child.example', Buffer.alloc(0), 0)!;
    const proof = verifyNxdomainProof('www.child.example', [
      nsec3Record(cut, 'example', incrementHash(cut), [TYPE_NS]),
      nsec3Record(decrementHash(nextCloser), 'example', incrementHash(nextCloser), []),
      nsec3Record(decrementHash(wildcard), 'example', incrementHash(wildcard), []),
    ]);
    expect(proof.result).toBe(FAILED);
  });
});

describe('nextCloserOptOut', () => {
  const encloser = nsec3Hash('example', Buffer.alloc(0), 0)!;
  const nextCloser = nsec3Hash('foo.example', Buffer.alloc(0), 0)!;
  const records = (closest: boolean, covering: boolean) => [
    nsec3Record(encloser, 'example', incrementHash(encloser), [TYPE_SOA, TYPE_NS], {
      optOut: closest,
    }),
    nsec3Record(decrementHash(nextCloser), 'example', incrementHash(nextCloser), [], {
      optOut: covering,
    }),
  ];

  it('looks only at the NSEC3 covering the next closer name', () => {
    expect(nextCloserOptOut('foo.example', records(true, false))).toBe(false);
    expect(nextCloserOptOut('foo.example', records(false, true))).toBe(true);
    expect(nextCloserOptOut('a.foo.example', records(false, true), 'example')).toBe(true);
  });

  it('is false for NSEC', () => {
    expect(nextCloserOptOut('foo.example', [nsecRecord('example', 'www.example', [])])).toBe(false);
  });
});
