import {
  responseFingerprint,
  computeKeyTag,
  computeDsDigest,
  encodeName,
  canonicalName,
  countLabels,
  parentName,
  isInZone,
  groupRrsets,
  buildSignedData,
  canonicalRdata,
  decodeRrsig,
  decodeDnskey,
  decodeTypeBitmap,
  nsec3Hash,
  presentRecord,
  recordTypeName,
  TYPE_A,
  TYPE_NS,
  TYPE_DNSKEY,
  WireRecord,
} from '../../src/dnssec/wire';
import { ROOT_TRUST_ANCHORS } from '../../src/dnssec/anchors';
import { toWireMessage } from '../../src/dnssec/wire';
import { decodeMessage } from '../../src/wire/index';

// a response as the DNSSEC code reads it: decoded by the library, then put in canonical form
const parseMessage = (bytes: Uint8Array) => toWireMessage(decodeMessage(bytes));

const hex = (bytes: Uint8Array | null | undefined) =>
  bytes ? Buffer.from(bytes).toString('hex') : undefined;

// the two IANA root KSKs, taken verbatim from root-anchors.xml. these are the reference
// vectors for key tag and DS digest: if either drifts, every downstream check that joins on
// key tag starts manufacturing false orphans
const KSK_2017_KEY =
  'AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=';

const KSK_2024_KEY =
  'AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc=';

// build canonical DNSKEY RDATA from the presentation-format fields
function dnskeyRdata(flags: number, protocol: number, algorithm: number, key: string): Buffer {
  const head = Buffer.alloc(4);
  head.writeUInt16BE(flags, 0);
  head.writeUInt8(protocol, 2);
  head.writeUInt8(algorithm, 3);
  return Buffer.concat([head, Buffer.from(key, 'base64')]);
}

describe('computeKeyTag', () => {
  it('matches the published tag for the root KSK-2017 anchor', () => {
    expect(computeKeyTag(dnskeyRdata(257, 3, 8, KSK_2017_KEY))).toBe(20326);
  });

  it('matches the published tag for the root KSK-2024 anchor', () => {
    expect(computeKeyTag(dnskeyRdata(257, 3, 8, KSK_2024_KEY))).toBe(38696);
  });

  it('uses the next-to-last modulus bytes for the RSAMD5 special case', () => {
    // RFC 4034 Appendix B.1: algorithm 1 does not use the checksum at all
    const rdata = Buffer.concat([
      Buffer.from([0x01, 0x01, 0x03, 0x01]),
      Buffer.from([0xaa, 0xbb, 0xcc, 0xdd, 0xee]),
    ]);
    expect(computeKeyTag(rdata)).toBe(0xccdd);
  });
});

describe('computeDsDigest', () => {
  it('reproduces the published SHA-256 digest for KSK-2017', () => {
    const anchor = ROOT_TRUST_ANCHORS.find(a => a.keyTag === 20326)!;
    const digest = computeDsDigest('.', dnskeyRdata(257, 3, 8, KSK_2017_KEY), 2);
    expect(hex(digest)).toBe(anchor.digest);
  });

  it('reproduces the published SHA-256 digest for KSK-2024', () => {
    const anchor = ROOT_TRUST_ANCHORS.find(a => a.keyTag === 38696)!;
    const digest = computeDsDigest('.', dnskeyRdata(257, 3, 8, KSK_2024_KEY), 2);
    expect(hex(digest)).toBe(anchor.digest);
  });

  it('returns null for a digest type it cannot compute rather than guessing', () => {
    // GOST (3) and SM3 (6) must be reported unsupported, never silently passed
    expect(computeDsDigest('.', dnskeyRdata(257, 3, 8, KSK_2017_KEY), 3)).toBeNull();
    expect(computeDsDigest('.', dnskeyRdata(257, 3, 8, KSK_2017_KEY), 6)).toBeNull();
  });

  it('binds the digest to the owner name', () => {
    const rdata = dnskeyRdata(257, 3, 8, KSK_2017_KEY);
    expect(hex(computeDsDigest('example.com', rdata, 2))).not.toBe(
      hex(computeDsDigest('.', rdata, 2))
    );
  });
});

describe('encodeName', () => {
  it('encodes the root as a single zero octet', () => {
    expect(Buffer.from(encodeName('.'))).toEqual(Buffer.from([0]));
    expect(Buffer.from(encodeName(''))).toEqual(Buffer.from([0]));
  });

  it('downcases for canonical form', () => {
    expect(encodeName('EXAMPLE.com')).toEqual(encodeName('example.COM'));
  });

  it('is length-prefixed per label and root-terminated', () => {
    expect(Buffer.from(encodeName('a.bc'))).toEqual(Buffer.from([1, 0x61, 2, 0x62, 0x63, 0]));
  });

  it('tolerates a trailing dot', () => {
    expect(encodeName('example.com.')).toEqual(encodeName('example.com'));
  });
});

describe('name helpers', () => {
  it('normalises the root and strips trailing dots', () => {
    expect(canonicalName('EXAMPLE.COM.')).toBe('example.com');
    expect(canonicalName('.')).toBe('.');
    expect(canonicalName('')).toBe('.');
  });

  it('counts labels excluding the root', () => {
    expect(countLabels('.')).toBe(0);
    expect(countLabels('com')).toBe(1);
    expect(countLabels('www.example.com')).toBe(3);
  });

  it('walks up one label at a time and stops at the root', () => {
    expect(parentName('www.example.com')).toBe('example.com');
    expect(parentName('com')).toBe('.');
    expect(parentName('.')).toBe('.');
  });

  it('places a name in a zone label by label', () => {
    expect(isInZone('www.example.com', 'example.com')).toBe(true);
    expect(isInZone('EXAMPLE.com', 'example.COM.')).toBe(true);
    expect(isInZone('anything', '.')).toBe(true);
    expect(isInZone('badexample.com', 'example.com')).toBe(false);
    // `a.example` is one label, so this name sits directly under com
    expect(isInZone('a\\.example.com', 'example.com')).toBe(false);
    expect(isInZone('a\\.example.com', 'com')).toBe(true);
  });
});

describe('parseMessage', () => {
  // a hand-built response with a compression pointer in the NS RDATA, which is exactly the
  // case a naive "copy the rdata bytes" canonicalisation gets wrong
  function buildResponse(): Buffer {
    const header = Buffer.alloc(12);
    header.writeUInt16BE(0x1234, 0);
    header.writeUInt16BE(0x8400, 2); // QR + AA
    header.writeUInt16BE(1, 4); // qdcount
    header.writeUInt16BE(1, 6); // ancount

    const qname = encodeName('example.com');
    const question = Buffer.alloc(4);
    question.writeUInt16BE(TYPE_NS, 0);
    question.writeUInt16BE(1, 2);

    // answer: example.com NS ns1.<pointer to example.com>
    const owner = Buffer.from([0xc0, 0x0c]); // pointer to offset 12
    const rrHead = Buffer.alloc(8);
    rrHead.writeUInt16BE(TYPE_NS, 0);
    rrHead.writeUInt16BE(1, 2);
    rrHead.writeUInt32BE(3600, 4);
    const rdata = Buffer.concat([Buffer.from([3, 0x6e, 0x73, 0x31]), Buffer.from([0xc0, 0x0c])]);
    const rdlength = Buffer.alloc(2);
    rdlength.writeUInt16BE(rdata.length, 0);

    return Buffer.concat([header, qname, question, owner, rrHead, rdlength, rdata]);
  }

  it('reads the header flags and question', () => {
    const message = parseMessage(buildResponse());
    expect(message.aa).toBe(true);
    expect(message.rcode).toBe(0);
    expect(message.question).toEqual({ name: 'example.com', type: TYPE_NS, class: 1 });
  });

  it('expands compression pointers in the owner name', () => {
    const message = parseMessage(buildResponse());
    expect(message.answers[0].name).toBe('example.com');
  });

  it('expands compression pointers inside RDATA so the canonical bytes are signable', () => {
    const message = parseMessage(buildResponse());
    // the compressed form is 6 bytes; the canonical form spells the name out in full
    expect(message.answers[0].rdata).toEqual(encodeName('ns1.example.com'));
    expect(presentRecord(message.answers[0])).toContain('ns1.example.com.');
  });

  it('rejects a message shorter than a DNS header', () => {
    expect(() => parseMessage(Buffer.alloc(4))).toThrow(/DNS header/);
  });

  it('rejects a forward compression pointer', () => {
    const message = buildResponse();
    // point the owner name at itself, which would loop forever if followed
    message.writeUInt16BE(0xc000 | (message.length - 1), message.length - 8);
    expect(() => parseMessage(message)).toThrow();
  });
});

describe('canonicalRdata', () => {
  // a name in wire form, keeping the case it was written in
  const wire = (name: string) => [
    ...name.split('.').flatMap(label => [label.length, ...Buffer.from(label)]),
    0,
  ];
  const string = (text: string) => [text.length, ...Buffer.from(text)];
  const canonical = (type: number, rdata: number[]) => [
    ...canonicalRdata(type, Uint8Array.from(rdata)),
  ];

  it('downcases the NAPTR replacement and leaves its character strings alone', () => {
    // RFC 4034 §6.2 lists NAPTR, and RFC 6840 §5.1 keeps it
    const strings = [...string('U'), ...string('E2U+SIP'), ...string('!^.*$!SIP:A@B!')];
    const rdata = [0, 100, 0, 10, ...strings, ...wire('SIP.Example')];
    expect(canonical(35, rdata)).toEqual([0, 100, 0, 10, ...strings, ...wire('sip.example')]);
  });

  it('downcases the NXT next name and leaves its bitmap alone', () => {
    const bitmap = [0x40, 0x01, 0x00, 0x00, 0x00, 0x03];
    expect(canonical(30, [...wire('Next.Example'), ...bitmap])).toEqual([
      ...wire('next.example'),
      ...bitmap,
    ]);
  });

  it('downcases both PX names, after the preference', () => {
    expect(canonical(26, [0, 10, ...wire('Map822.Example'), ...wire('MapX400.Example')])).toEqual([
      0,
      10,
      ...wire('map822.example'),
      ...wire('mapx400.example'),
    ]);
  });

  it('downcases the SIG signer name, after the fixed fields', () => {
    const fixed = Array.from({ length: 18 }, (_, i) => 0x41 + i);
    expect(canonical(24, [...fixed, ...wire('Signer.Example'), 0x41, 0x42])).toEqual([
      ...fixed,
      ...wire('signer.example'),
      0x41,
      0x42,
    ]);
  });

  it('downcases the A6 prefix name, after the address suffix', () => {
    // prefix length 64 leaves an 8-byte suffix; 0x41 is an uppercase letter in the address
    const suffix = [0x41, 0x41, 0, 0, 0, 0, 0, 1];
    expect(canonical(38, [64, ...suffix, ...wire('Prefix.Example')])).toEqual([
      64,
      ...suffix,
      ...wire('prefix.example'),
    ]);
    // a prefix length of 0 carries the whole address and no name
    const whole = Array.from({ length: 16 }, () => 0x41);
    expect(canonical(38, [0, ...whole])).toEqual([0, ...whole]);
  });

  it('leaves the NSEC next name as published (RFC 6840 §5.1)', () => {
    const bitmap = [0, 1, 0x40];
    expect(canonical(47, [...wire('Next.Example'), ...bitmap])).toEqual([
      ...wire('Next.Example'),
      ...bitmap,
    ]);
  });
});

describe('groupRrsets', () => {
  it('groups by owner, class and type and keeps the lowest TTL', () => {
    const base = { class: 1, section: 'answer' as const, typeName: 'A' };
    const rrsets = groupRrsets([
      { ...base, name: 'example.com', type: TYPE_A, ttl: 300, rdata: Buffer.from([1, 1, 1, 1]) },
      { ...base, name: 'example.com', type: TYPE_A, ttl: 60, rdata: Buffer.from([2, 2, 2, 2]) },
      { ...base, name: 'other.com', type: TYPE_A, ttl: 300, rdata: Buffer.from([3, 3, 3, 3]) },
    ]);
    expect(rrsets).toHaveLength(2);
    expect(rrsets[0].records).toHaveLength(2);
    expect(rrsets[0].ttl).toBe(60);
  });
});

describe('buildSignedData', () => {
  // a minimal RRSIG RDATA covering A, signed by example.com
  function rrsigRdata(labels: number, originalTtl = 300): Buffer {
    const head = Buffer.alloc(18);
    head.writeUInt16BE(TYPE_A, 0);
    head.writeUInt8(13, 2); // algorithm
    head.writeUInt8(labels, 3);
    head.writeUInt32BE(originalTtl, 4);
    head.writeUInt32BE(2000000000, 8); // expiration
    head.writeUInt32BE(1000000000, 12); // inception
    head.writeUInt16BE(1234, 16); // key tag
    return Buffer.concat([head, encodeName('example.com'), Buffer.alloc(64, 0xaa)]);
  }

  const rrset = {
    name: 'example.com',
    type: TYPE_A,
    typeName: 'A',
    class: 1,
    ttl: 300,
    records: [
      {
        name: 'example.com',
        type: TYPE_A,
        typeName: 'A',
        class: 1,
        ttl: 300,
        rdata: Buffer.from([9, 9, 9, 9]),
        section: 'answer' as const,
      },
      {
        name: 'example.com',
        type: TYPE_A,
        typeName: 'A',
        class: 1,
        ttl: 300,
        rdata: Buffer.from([1, 1, 1, 1]),
        section: 'answer' as const,
      },
    ],
  };

  it('orders RRs canonically by RDATA regardless of wire order', () => {
    const sig = decodeRrsig(rrsigRdata(2))!;
    const built = buildSignedData(sig, rrset)!;
    // the 1.1.1.1 record sorts before 9.9.9.9, so its RDATA appears first
    const first = Buffer.from(built.data).indexOf(Buffer.from([1, 1, 1, 1]));
    const second = Buffer.from(built.data).indexOf(Buffer.from([9, 9, 9, 9]));
    expect(first).toBeGreaterThan(0);
    expect(first).toBeLessThan(second);
  });

  it("uses the signature's original TTL, not the TTL the record arrived with", () => {
    const sig = decodeRrsig(rrsigRdata(2, 77))!;
    const built = buildSignedData(sig, { ...rrset, ttl: 5 })!;
    // 77 appears as a 32-bit TTL in each RR header of the canonical form
    const ttlBytes = Buffer.alloc(4);
    ttlBytes.writeUInt32BE(77, 0);
    expect(Buffer.from(built.data).includes(ttlBytes)).toBe(true);
  });

  it('reconstructs the wildcard owner name when the label count is short', () => {
    // one label fewer than the owner name means the answer came from *.com
    const sig = decodeRrsig(rrsigRdata(1))!;
    const built = buildSignedData(sig, rrset)!;
    expect(built.wildcard).toBe(true);
    expect(built.ownerName).toBe('*.com');
  });

  it('refuses to build when the label count exceeds the owner name', () => {
    const sig = decodeRrsig(rrsigRdata(5))!;
    expect(buildSignedData(sig, rrset)).toBeNull();
  });

  it('drops duplicate RRs, which are not part of the RRset', () => {
    const sig = decodeRrsig(rrsigRdata(2))!;
    const withDuplicate = { ...rrset, records: [...rrset.records, rrset.records[0]] };
    expect(buildSignedData(sig, withDuplicate)!.data).toEqual(buildSignedData(sig, rrset)!.data);
  });
});

describe('decodeDnskey', () => {
  it('splits the flag, protocol and algorithm fields', () => {
    const decoded = decodeDnskey(dnskeyRdata(257, 3, 8, KSK_2017_KEY))!;
    expect(decoded.flags).toBe(257);
    expect(decoded.protocol).toBe(3);
    expect(decoded.algorithm).toBe(8);
    expect(Buffer.from(decoded.publicKey).toString('base64')).toBe(KSK_2017_KEY);
  });
});

describe('decodeTypeBitmap', () => {
  it('decodes an RFC 4034 §4.1.2 window', () => {
    // window 0, length 1, bit 1 (NS) and bit 6 (SOA) set
    const bitmap = Buffer.from([0x00, 0x01, 0b01000010]);
    expect(decodeTypeBitmap(bitmap)).toEqual([1, 6]);
    expect(decodeTypeBitmap(bitmap).map(recordTypeName)).toEqual(['A', 'SOA']);
  });

  it('handles multiple windows', () => {
    const bitmap = Buffer.from([0x00, 0x01, 0b01000000, 0x01, 0x01, 0b10000000]);
    expect(decodeTypeBitmap(bitmap)).toEqual([1, 256]);
  });
});

describe('nsec3Hash', () => {
  // RFC 5155 Appendix A publishes the hashed owner names for the example zone with
  // salt aabbccdd and 12 iterations
  const salt = Buffer.from('aabbccdd', 'hex');

  it('reproduces the RFC 5155 Appendix A hash for the zone apex', () => {
    expect(nsec3Hash('example', salt, 12)).toBe('0p9mhaveqvm6t7vbl5lop2u3t2rp3tom');
  });

  it('reproduces the RFC 5155 Appendix A hash for a.example', () => {
    expect(nsec3Hash('a.example', salt, 12)).toBe('35mthgpgcu1qg68fab165klnsnk3dpvl');
  });

  it('is case-insensitive, because the name is canonicalised first', () => {
    expect(nsec3Hash('A.Example', salt, 12)).toBe(nsec3Hash('a.example', salt, 12));
  });

  it('refuses hash algorithms it does not implement', () => {
    expect(nsec3Hash('example', salt, 12, 2)).toBeNull();
  });
});

describe('responseFingerprint', () => {
  const rr = (name: string, type: number, rdata: number[], ttl = 300): WireRecord => ({
    name,
    type,
    typeName: recordTypeName(type),
    class: 1,
    ttl,
    rdata: Buffer.from(rdata),
    section: 'answer',
  });

  it('is stable across record order, since RRset order is not significant', () => {
    const a = [
      rr('example.com', TYPE_DNSKEY, [1, 1, 0, 3, 8]),
      rr('example.com', TYPE_DNSKEY, [1, 0, 0, 3, 8]),
    ];
    expect(responseFingerprint(a)).toBe(responseFingerprint([...a].reverse()));
  });

  it('ignores TTL, which counts down independently on every server', () => {
    // including TTL would report every healthy multi-server zone as divergent
    expect(responseFingerprint([rr('example.com', TYPE_DNSKEY, [1, 1, 0, 3, 8], 300)])).toBe(
      responseFingerprint([rr('example.com', TYPE_DNSKEY, [1, 1, 0, 3, 8], 42)])
    );
  });

  it('ignores address records, which differ by design under anycast and GSLB', () => {
    // divergent A/AAAA sets are a load-balancing feature, not a DNSSEC fault
    expect(responseFingerprint([rr('example.com', TYPE_A, [1, 1, 1, 1])])).toBe(
      responseFingerprint([rr('example.com', TYPE_A, [9, 9, 9, 9])])
    );
  });

  it('ignores SOA, whose serial differs constantly while a zone propagates', () => {
    expect(responseFingerprint([rr('example.com', 6, [1])])).toBe(
      responseFingerprint([rr('example.com', 6, [2])])
    );
  });

  it('differs when a server is missing DNSSEC material its peers have', () => {
    const full = [
      rr('example.com', TYPE_DNSKEY, [1, 1, 0, 3, 8]),
      rr('example.com', TYPE_DNSKEY, [1, 0, 0, 3, 8]),
    ];
    expect(responseFingerprint(full)).not.toBe(responseFingerprint(full.slice(0, 1)));
  });

  it('differs when a server publishes a different key set', () => {
    expect(responseFingerprint([rr('example.com', TYPE_DNSKEY, [1, 1, 0, 3, 8])])).not.toBe(
      responseFingerprint([rr('example.com', TYPE_DNSKEY, [1, 1, 0, 3, 13])])
    );
  });

  // an RRSIG covering A, with the signature bytes and validity window under test control
  const sigRecord = (o: {
    inception: number;
    expiration: number;
    signature: number;
    keyTag?: number;
  }): WireRecord => {
    const head = Buffer.alloc(18);
    head.writeUInt16BE(TYPE_A, 0);
    head.writeUInt8(13, 2); // ECDSAP256SHA256
    head.writeUInt8(2, 3); // labels
    head.writeUInt32BE(300, 4); // original TTL
    head.writeUInt32BE(o.expiration, 8);
    head.writeUInt32BE(o.inception, 12);
    head.writeUInt16BE(o.keyTag ?? 34505, 16);
    return {
      name: 'example.com',
      type: 46,
      typeName: 'RRSIG',
      class: 1,
      ttl: 300,
      rdata: Buffer.concat([head, encodeName('example.com'), Buffer.alloc(64, o.signature)]),
      section: 'answer',
    };
  };

  it('tolerates a re-signed signature over the same window', () => {
    // live signers use non-deterministic ECDSA: the same server queried twice returns
    // different bytes over identical data. hashing the blob would flag every such zone
    const w = { inception: 1785391558, expiration: 1785571558 };
    expect(responseFingerprint([sigRecord({ ...w, signature: 0x11 })])).toBe(
      responseFingerprint([sigRecord({ ...w, signature: 0x22 })])
    );
  });

  it('tolerates a drifting validity window, which live signers derive from the clock', () => {
    // Cloudflare peers observed seconds apart publish different inception times for identical
    // data; comparing windows would flag every live-signed zone
    const a = sigRecord({ inception: 1785391745, expiration: 1785571745, signature: 0x11 });
    const b = sigRecord({ inception: 1785391758, expiration: 1785571758, signature: 0x11 });
    expect(responseFingerprint([a])).toBe(responseFingerprint([b]));
  });

  it('differs when a server signs with a key its peers have rolled away from', () => {
    const a = sigRecord({ inception: 1785391745, expiration: 1785571745, signature: 0x11 });
    const b = sigRecord({
      inception: 1785391745,
      expiration: 1785571745,
      signature: 0x11,
      keyTag: 9999,
    });
    expect(responseFingerprint([a])).not.toBe(responseFingerprint([b]));
  });

  it('ignores the authority section when there is an answer', () => {
    // some servers attach the zone's NS RRset to a positive answer and some do not
    // (`minimal-responses`); nic.cz runs both in the same set
    const answer = [rr('example.com', TYPE_DNSKEY, [1, 1, 0, 3, 8])];
    const chatty = [rr('example.com', 2, [1, 2, 3])];
    expect(responseFingerprint(answer, chatty)).toBe(responseFingerprint(answer, []));
  });

  it('compares the authority section when the answer is empty — it is the payload there', () => {
    // a referral or a denial proof lives entirely in the authority section
    const a = [rr('example.com', TYPE_DNSKEY, [1, 1, 0, 3, 8])];
    const b = [rr('example.com', TYPE_DNSKEY, [1, 1, 0, 3, 13])];
    expect(responseFingerprint([], a)).not.toBe(responseFingerprint([], b));
  });

  it('distinguishes the same RDATA under a different owner', () => {
    expect(responseFingerprint([rr('a.example.com', TYPE_DNSKEY, [1, 1, 0, 3, 8])])).not.toBe(
      responseFingerprint([rr('b.example.com', TYPE_DNSKEY, [1, 1, 0, 3, 8])])
    );
  });
});
