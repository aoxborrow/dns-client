import {
  clientSubnetOption,
  cookieOption,
  decodeEdnsOption,
  decodeEdnsOptions,
  decodeMessage,
  encodeMessage,
  encodeQuery,
  extendedErrors,
  nsidOption,
  paddingOption,
  ParseError,
} from '../../src/index';
import { CAPTURED, CORPUS } from '../support/corpus';

const ascii = (text: string) => Uint8Array.from(Buffer.from(text, 'latin1'));
const hex = (text: string) => Uint8Array.from(Buffer.from(text, 'hex'));

describe('decoding EDNS options', () => {
  it('reads the server identifiers real nameservers sent', () => {
    const nsids = new Set<string>();
    for (const { response } of [...CORPUS, ...CAPTURED]) {
      for (const option of decodeEdnsOptions(decodeMessage(response).edns)) {
        // nothing in real traffic falls outside the layouts
        expect(option.name).not.toMatch(/^OPTION/);
        if (option.name === 'NSID' && option.nsid) nsids.add(option.nsid);
      }
    }
    // a Cloudflare point of presence and a root server instance, from the recordings
    expect(nsids.has('4m917')).toBe(true);
    expect(nsids.has('a.r.ussea-4a')).toBe(true);
  });

  it('gives an identifier that is not text as hex only', () => {
    expect(decodeEdnsOption({ code: 3, data: hex('00ff10') })).toEqual({
      name: 'NSID',
      code: 3,
      nsid: null,
      hex: '00ff10',
    });
    expect(decodeEdnsOption({ code: 3, data: ascii('ns1') })).toEqual({
      name: 'NSID',
      code: 3,
      nsid: 'ns1',
      hex: '6e7331',
    });
  });

  it('reads a client subnet, padding the address back out', () => {
    expect(decodeEdnsOption({ code: 8, data: hex('00011800c00002') })).toEqual({
      name: 'CLIENT_SUBNET',
      code: 8,
      family: 1,
      sourcePrefixLength: 24,
      scopePrefixLength: 0,
      address: '192.0.2.0',
    });
    expect(decodeEdnsOption({ code: 8, data: hex('0002381020010db8000001') })).toMatchObject({
      family: 2,
      sourcePrefixLength: 56,
      scopePrefixLength: 16,
      address: '2001:db8:0:100::',
    });
  });

  it('reads cookies, keepalive, padding, algorithm lists and key tags', () => {
    expect(decodeEdnsOption({ code: 10, data: hex('0102030405060708') })).toMatchObject({
      name: 'COOKIE',
      clientCookie: '0102030405060708',
      serverCookie: null,
    });
    expect(
      decodeEdnsOption({ code: 10, data: hex('0102030405060708aabbccddeeff0011') })
    ).toMatchObject({
      serverCookie: 'aabbccddeeff0011',
    });
    expect(decodeEdnsOption({ code: 11, data: hex('012c') })).toMatchObject({
      name: 'TCP_KEEPALIVE',
      timeoutMs: 30000,
    });
    expect(decodeEdnsOption({ code: 11, data: new Uint8Array(0) })).toMatchObject({
      timeoutMs: null,
    });
    expect(decodeEdnsOption({ code: 12, data: new Uint8Array(468) })).toMatchObject({
      name: 'PADDING',
      length: 468,
    });
    expect(decodeEdnsOption({ code: 5, data: hex('080d0f') })).toEqual({
      name: 'DAU',
      code: 5,
      algorithms: [8, 13, 15],
    });
    expect(decodeEdnsOption({ code: 14, data: hex('4f66952a') })).toEqual({
      name: 'KEY_TAG',
      code: 14,
      keyTags: [20326, 38186],
    });
  });

  it('reads extended errors, and finds them on a message', () => {
    const response = encodeMessage({
      id: 1,
      flags: { qr: true },
      rcode: 2,
      edns: {
        udpPayloadSize: 1232,
        version: 0,
        dnssecOk: true,
        options: [
          { code: 15, data: Uint8Array.of(0, 6, ...ascii('signature expired\0')) },
          { code: 15, data: Uint8Array.of(0xff, 0xff) },
          { code: 3, data: ascii('ns1') },
        ],
      },
    });
    expect(extendedErrors(decodeMessage(response).edns)).toEqual([
      {
        name: 'EDE',
        code: 15,
        infoCode: 6,
        purpose: 'DNSSEC Bogus',
        extraText: 'signature expired',
      },
      { name: 'EDE', code: 15, infoCode: 65535, purpose: null, extraText: '' },
    ]);
    expect(extendedErrors(undefined)).toEqual([]);
  });

  it('returns an option it does not know, or cannot read, with its bytes', () => {
    expect(decodeEdnsOption({ code: 65001, data: hex('0102') })).toEqual({
      name: 'OPTION65001',
      code: 65001,
      data: '0102',
    });
    for (const bad of [
      { code: 8, data: hex('0001') }, // subnet too short
      { code: 8, data: hex('00032000c0000201') }, // unknown family
      { code: 10, data: hex('01020304') }, // cookie too short
      { code: 11, data: hex('01') }, // keepalive of one byte
      { code: 14, data: hex('4f') }, // half a key tag
      { code: 15, data: hex('00') }, // error with no code
    ]) {
      expect(decodeEdnsOption(bad).name, JSON.stringify(bad)).toBe(`OPTION${bad.code}`);
    }
  });
});

describe('building EDNS options', () => {
  it('builds options that decode to what was asked for', () => {
    expect(decodeEdnsOption(nsidOption())).toMatchObject({ name: 'NSID', hex: '' });
    expect(decodeEdnsOption(paddingOption(64))).toMatchObject({ name: 'PADDING', length: 64 });
    expect(decodeEdnsOption(cookieOption(hex('0102030405060708')))).toMatchObject({
      clientCookie: '0102030405060708',
      serverCookie: null,
    });
    expect(
      decodeEdnsOption(cookieOption(hex('0102030405060708'), hex('aabbccddeeff0011')))
    ).toMatchObject({
      serverCookie: 'aabbccddeeff0011',
    });
  });

  it('cuts a client subnet to its prefix and clears the bits past it', () => {
    expect([...clientSubnetOption('192.0.2.200', 24).data]).toEqual([0, 1, 24, 0, 192, 0, 2]);
    expect([...clientSubnetOption('192.0.2.200', 26).data]).toEqual([0, 1, 26, 0, 192, 0, 2, 192]);
    expect([...clientSubnetOption('0.0.0.0', 0).data]).toEqual([0, 1, 0, 0]);
    expect(decodeEdnsOption(clientSubnetOption('2001:db8:1:2:3:4:5:6', 56))).toMatchObject({
      family: 2,
      sourcePrefixLength: 56,
      address: '2001:db8:1::',
    });
  });

  it('rejects options that cannot be built', () => {
    expect(() => cookieOption(hex('0102'))).toThrow(ParseError);
    expect(() => cookieOption(hex('0102030405060708'), hex('aa'))).toThrow(ParseError);
    expect(() => clientSubnetOption('example.com', 24)).toThrow(ParseError);
    expect(() => clientSubnetOption('192.0.2.1', 33)).toThrow(ParseError);
  });

  it('carries built options in a query', () => {
    const query = encodeQuery({
      id: 1,
      name: 'example.com',
      type: 'A',
      edns: { options: [nsidOption(), clientSubnetOption('192.0.2.0', 24)] },
    });
    expect(decodeEdnsOptions(decodeMessage(query).edns).map(option => option.name)).toEqual([
      'NSID',
      'CLIENT_SUBNET',
    ]);
  });
});
