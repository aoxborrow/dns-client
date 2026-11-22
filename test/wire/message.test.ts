import dnsPacket from 'dns-packet';
import { decodeMessage, encodeMessage, encodeQuery } from '../../src/wire/index';
import { decodeRecords, rcodeName, typeName } from '../../src/records/index';
import { InvalidQueryError, ParseError, type Message } from '../../src/index';
import { CORPUS, seededRandom } from '../support/corpus';

// dns-packet is the codec this one replaces. It is a dev dependency only, here as an
// independent reading of the same bytes

// dns-packet names the types it does not know `UNKNOWN_<n>`; read as the number they carry
const fromPacketType = (type: string) =>
  type.startsWith('UNKNOWN_') ? typeName(Number(type.slice(8))) : type;

const withoutBytes = (message: Message) => ({ ...message, bytes: 0 });

describe('decodeMessage over the corpus', () => {
  it('has a corpus worth the name', () => {
    expect(CORPUS.length).toBeGreaterThan(300);
  });

  it('agrees with dns-packet on every header, question and record envelope', () => {
    for (const { label, response } of CORPUS) {
      const ours = decodeMessage(response);
      const theirs = dnsPacket.decode(Buffer.from(response));

      expect(ours.id, label).toBe(theirs.id);
      expect(ours.bytes, label).toBe(response.length);
      expect(ours.flags, label).toEqual({
        qr: theirs.type === 'response',
        aa: theirs.flag_aa,
        tc: theirs.flag_tc,
        rd: theirs.flag_rd,
        ra: theirs.flag_ra,
        ad: theirs.flag_ad,
        cd: theirs.flag_cd,
      });
      // dns-packet reads only the header's four bits
      expect(rcodeName(ours.rcode & 0x0f), label).toBe((theirs as { rcode?: string }).rcode);

      expect(
        ours.questions.map(q => [q.name, typeName(q.type)]),
        label
      ).toEqual((theirs.questions ?? []).map(q => [q.name, fromPacketType(q.type)]));

      const envelope = (records: Message['answers']) =>
        records.map(r => [r.name, typeName(r.type), r.ttl]);
      const theirEnvelope = (records: dnsPacket.Answer[] = []) =>
        records
          .filter(r => r.type !== 'OPT')
          .map(r => [r.name, fromPacketType(r.type), (r as { ttl?: number }).ttl]);
      expect(envelope(ours.answers), label).toEqual(theirEnvelope(theirs.answers));
      expect(envelope(ours.authorities), label).toEqual(theirEnvelope(theirs.authorities));
      expect(envelope(ours.additionals), label).toEqual(theirEnvelope(theirs.additionals));

      const opt = theirs.additionals?.find(r => r.type === 'OPT') as
        | { udpPayloadSize: number; ednsVersion: number; flag_do: boolean; options: unknown[] }
        | undefined;
      if (opt) {
        expect(ours.edns?.udpPayloadSize, label).toBe(opt.udpPayloadSize);
        expect(ours.edns?.version, label).toBe(opt.ednsVersion);
        expect(ours.edns?.dnssecOk, label).toBe(opt.flag_do);
        expect(ours.edns?.options.length, label).toBe(opt.options.length);
      } else {
        expect(ours.edns, label).toBeUndefined();
      }
    }
  });

  it('makes every record self-contained: decode, encode and decode again is the same', () => {
    // responses use name compression, so the bytes differ; what they mean must not
    for (const { label, response } of CORPUS) {
      const first = decodeMessage(response);
      const second = decodeMessage(encodeMessage(first));
      expect(withoutBytes(second), label).toEqual(withoutBytes(first));
    }
  });

  it('re-encodes the recorded queries byte for byte', () => {
    const seen = new Set<string>();
    for (const { label, query } of CORPUS) {
      const key = Buffer.from(query).toString('base64');
      if (seen.has(key)) continue;
      seen.add(key);
      expect(encodeMessage(decodeMessage(query)), label).toEqual(query);
    }
    expect(seen.size).toBeGreaterThan(100);
  });
});

describe('decodeMessage', () => {
  it('reports EDNS state and extends the response code from the OPT record', () => {
    const response = encodeMessage({
      id: 7,
      flags: { qr: true },
      rcode: 16, // BADVERS: does not fit the header's four bits
      questions: [{ name: 'example.com', type: 1, class: 1 }],
      edns: {
        udpPayloadSize: 1232,
        version: 0,
        dnssecOk: true,
        options: [{ code: 15, data: Uint8Array.of(0, 6) }],
      },
    });
    const message = decodeMessage(response);
    expect(message.rcode).toBe(16);
    expect(rcodeName(message.rcode)).toBe('BADVERS');
    expect(message.edns).toEqual({
      udpPayloadSize: 1232,
      version: 0,
      dnssecOk: true,
      options: [{ code: 15, data: Uint8Array.of(0, 6) }],
    });
    expect(message.additionals).toEqual([]);
  });

  it('writes compressed names inside record data out in full', () => {
    // an MX record whose exchange is "mail" + a pointer to the question name
    const question = [7, ...Buffer.from('example'), 3, ...Buffer.from('com'), 0];
    const message = Uint8Array.from([
      0,
      1,
      0x80,
      0,
      0,
      1,
      0,
      1,
      0,
      0,
      0,
      0, // header: one question, one answer
      ...question,
      0,
      15,
      0,
      1,
      0xc0,
      12,
      0,
      15,
      0,
      1,
      0,
      0,
      0,
      60,
      0,
      9, // owner: pointer to the question name
      0,
      10,
      4,
      ...Buffer.from('mail'),
      0xc0,
      12, // preference 10, mail.<pointer>
    ]);
    const [answer] = decodeMessage(message).answers;
    expect(answer.name).toBe('example.com');
    expect([...answer.rdata]).toEqual([0, 10, 4, ...Buffer.from('mail'), ...question]);
  });

  it('writes out a compressed NAPTR replacement, after its three character strings', () => {
    const question = [7, ...Buffer.from('example'), 3, ...Buffer.from('com'), 0];
    const strings = [1, ...Buffer.from('u'), 7, ...Buffer.from('E2U+sip'), 0]; // flags, services, regexp
    const replacement = [4, ...Buffer.from('sip1'), 0xc0, 12]; // sip1.<pointer>
    const rdata = [0, 100, 0, 10, ...strings, ...replacement]; // order 100, preference 10
    const message = Uint8Array.from([
      ...[0, 1, 0x80, 0, 0, 1, 0, 1, 0, 0, 0, 0], // header: one question, one answer
      ...question,
      ...[0, 35, 0, 1], // NAPTR IN
      ...[0xc0, 12, 0, 35, 0, 1, 0, 0, 0, 60, 0, rdata.length], // owner: pointer to the question
      ...rdata,
    ]);
    const decoded = decodeMessage(message);
    expect([...decoded.answers[0].rdata]).toEqual([
      0,
      100,
      0,
      10,
      ...strings,
      4,
      ...Buffer.from('sip1'),
      ...question,
    ]);
    expect(decodeRecords(decoded.answers)[0]).toMatchObject({
      type: 'NAPTR',
      services: 'E2U+sip',
      replacement: 'sip1.example.com',
    });
  });

  it('rejects a message shorter than a header, and a count that promises more than is there', () => {
    expect(() => decodeMessage(new Uint8Array(11))).toThrow(ParseError);
    const lying = encodeMessage({ id: 1, questions: [{ name: 'a.example', type: 1, class: 1 }] });
    lying[7] = 3; // claim three answers
    expect(() => decodeMessage(lying)).toThrow(ParseError);
  });

  it('never throws anything but ParseError, whatever the bytes', () => {
    const random = seededRandom(20261109);
    for (let round = 0; round < 6000; round++) {
      const source = CORPUS[Math.floor(random() * CORPUS.length)].response;
      const mangled = Uint8Array.from(source.subarray(0, Math.ceil(random() * source.length)));
      // flip a few bytes, with a bias towards the header and the first record
      const flips = 1 + Math.floor(random() * 4);
      for (let flip = 0; flip < flips; flip++) {
        const at = Math.floor(random() * random() * mangled.length);
        mangled[at] = Math.floor(random() * 256);
      }
      try {
        decodeMessage(mangled);
      } catch (error) {
        if (!(error instanceof ParseError)) {
          throw new Error(
            `round ${round}: ${String(error)} for ${Buffer.from(mangled).toString('base64')}`,
            { cause: error }
          );
        }
      }
    }
  });
});

describe('encodeQuery', () => {
  it('writes a query dns-packet reads back the same way', () => {
    const query = encodeQuery({
      id: 0x1234,
      name: 'example.com',
      type: 'MX',
      recursionDesired: true,
    });
    const read = dnsPacket.decode(Buffer.from(query));
    expect(read.id).toBe(0x1234);
    expect(read.type).toBe('query');
    expect(read.flag_rd).toBe(true);
    expect(read.flag_cd).toBe(false);
    expect(read.questions).toEqual([{ name: 'example.com', type: 'MX', class: 'IN' }]);
    const opt = read.additionals?.[0] as { type: string; udpPayloadSize: number; flag_do: boolean };
    expect(opt.type).toBe('OPT');
    expect(opt.udpPayloadSize).toBe(1232);
    expect(opt.flag_do).toBe(false);
  });

  it('sets CD, AD and the DO bit when asked', () => {
    const message = decodeMessage(
      encodeQuery({
        id: 1,
        name: 'example.com',
        type: 'DNSKEY',
        checkingDisabled: true,
        authenticData: true,
        edns: { dnssecOk: true, udpPayloadSize: 4096 },
      })
    );
    expect(message.flags).toMatchObject({ qr: false, rd: false, cd: true, ad: true });
    expect(message.edns).toMatchObject({ dnssecOk: true, udpPayloadSize: 4096, version: 0 });
  });

  it('asks for the types dns-packet encoded as type 0', () => {
    for (const [type, code] of [
      ['HTTPS', 65],
      ['SVCB', 64],
      ['OPENPGPKEY', 61],
      ['URI', 256],
    ] as const) {
      const message = decodeMessage(encodeQuery({ id: 1, name: 'example.com', type }));
      expect(message.questions[0].type).toBe(code);
      // and for the record: this is what the old encoder did with the same question
      const old = dnsPacket.decode(
        dnsPacket.encode({
          type: 'query',
          id: 1,
          questions: [{ type: type as 'A', name: 'example.com' }],
        })
      );
      expect(
        decodeMessage(encodeQuery({ id: 1, name: 'example.com', type: 0 })).questions[0].type
      ).toBe(0);
      expect(old.questions?.[0].type).not.toBe(type);
    }
  });

  it('asks for any type by number, and for the root', () => {
    expect(decodeMessage(encodeQuery({ id: 1, name: '.', type: 65280 })).questions).toEqual([
      { name: '.', type: 65280, class: 1 },
    ]);
  });

  it('sends a plain query with EDNS off, and carries EDNS options when given', () => {
    expect(
      decodeMessage(encodeQuery({ id: 1, name: 'a.example', type: 'A', edns: false })).edns
    ).toBeUndefined();
    const nsid = { code: 3, data: new Uint8Array(0) };
    expect(
      decodeMessage(encodeQuery({ id: 1, name: 'a.example', type: 'A', edns: { options: [nsid] } }))
        .edns?.options
    ).toEqual([nsid]);
  });

  it('rejects a question it cannot encode', () => {
    expect(() => encodeQuery({ id: 1, name: 'example.com', type: 'NOPE' })).toThrow(
      InvalidQueryError
    );
    expect(() => encodeQuery({ id: 1, name: `${'a'.repeat(64)}.com`, type: 'A' })).toThrow(
      InvalidQueryError
    );
    expect(() => encodeQuery({ id: 70000, name: 'example.com', type: 'A' })).toThrow(
      InvalidQueryError
    );
  });
});
