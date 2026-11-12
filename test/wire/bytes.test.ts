import { formatIpv6, toBase32Hex, toBase64, toHex, utf8Decode } from '../../src/wire/bytes';

const ascii = (text: string) => Uint8Array.from(Buffer.from(text, 'latin1'));

describe('byte formatting', () => {
  it('encodes base32hex without padding (RFC 4648 §10 vectors)', () => {
    const vectors: [string, string][] = [
      ['', ''],
      ['f', 'CO'],
      ['fo', 'CPNG'],
      ['foo', 'CPNMU'],
      ['foob', 'CPNMUOG'],
      ['fooba', 'CPNMUOJ1'],
      ['foobar', 'CPNMUOJ1E8'],
    ];
    for (const [input, expected] of vectors) expect(toBase32Hex(ascii(input))).toBe(expected);
  });

  it('encodes base64 with padding and hex in lowercase', () => {
    expect(toBase64(ascii('foobar'))).toBe('Zm9vYmFy');
    expect(toBase64(ascii('foob'))).toBe('Zm9vYg==');
    expect(toBase64(Uint8Array.of(0xff, 0x00, 0xfe))).toBe('/wD+');
    expect(toHex(Uint8Array.of(0x00, 0x0f, 0xab, 0xff))).toBe('000fabff');
  });

  it('writes IPv6 addresses in the RFC 5952 form', () => {
    const address = (hex: string) => Uint8Array.from(Buffer.from(hex, 'hex'));
    expect(formatIpv6(address('20010db8000000000000000000000001'))).toBe('2001:db8::1');
    expect(formatIpv6(address('00000000000000000000000000000000'))).toBe('::');
    expect(formatIpv6(address('00000000000000000000000000000001'))).toBe('::1');
    expect(formatIpv6(address('20010db8000000000000000000000000'))).toBe('2001:db8::');
    // a single zero group is not shortened
    expect(formatIpv6(address('20010db8000000010001000100010001'))).toBe('2001:db8:0:1:1:1:1:1');
    // the longest run wins, and the first on a tie
    expect(formatIpv6(address('20010000000000010000000000000001'))).toBe('2001:0:0:1::1');
    expect(formatIpv6(address('20010db8000000000001000000000001'))).toBe('2001:db8::1:0:0:1');
  });

  it('decodes text as UTF-8 and replaces what is not', () => {
    expect(utf8Decode(Uint8Array.from(Buffer.from('größe')))).toBe('größe');
    expect(utf8Decode(Uint8Array.of(0x61, 0xff, 0x62))).toBe('a�b');
  });
});
