import {
  classCode,
  className,
  InvalidQueryError,
  rcodeName,
  RCODES,
  RECORD_TYPES,
  typeCode,
  typeName,
} from '../src/index';

describe('record types', () => {
  it('maps mnemonics to codes in any case', () => {
    expect(typeCode('A')).toBe(1);
    expect(typeCode('aaaa')).toBe(28);
    expect(typeCode(' Mx ')).toBe(15);
    expect(typeCode('*')).toBe(255);
  });

  it('knows the types dns-packet could not ask for', () => {
    expect(typeCode('HTTPS')).toBe(65);
    expect(typeCode('SVCB')).toBe(64);
    expect(typeCode('OPENPGPKEY')).toBe(61);
    expect(typeCode('URI')).toBe(256);
  });

  it('accepts numbers and the RFC 3597 generic form', () => {
    expect(typeCode(65)).toBe(65);
    expect(typeCode('TYPE65')).toBe(65);
    expect(typeCode('type65280')).toBe(65280);
  });

  it('rejects what is not a type', () => {
    expect(() => typeCode('NOPE')).toThrow(InvalidQueryError);
    expect(() => typeCode('TYPE70000')).toThrow(InvalidQueryError);
    expect(() => typeCode(-1)).toThrow(InvalidQueryError);
    expect(() => typeCode(1.5)).toThrow(InvalidQueryError);
  });

  it('names every code, falling back to the generic form', () => {
    expect(typeName(1)).toBe('A');
    expect(typeName(255)).toBe('ANY');
    expect(typeName(65280)).toBe('TYPE65280');
  });

  it('round-trips every known type', () => {
    for (const [name, code] of Object.entries(RECORD_TYPES)) {
      expect(typeCode(name)).toBe(code);
      expect(typeCode(typeName(code))).toBe(code);
    }
  });
});

describe('classes and response codes', () => {
  it('maps classes both ways', () => {
    expect(classCode('IN')).toBe(1);
    expect(classCode('ch')).toBe(3);
    expect(classCode('CLASS32')).toBe(32);
    expect(className(1)).toBe('IN');
    expect(className(32)).toBe('CLASS32');
    expect(() => classCode('XX')).toThrow(InvalidQueryError);
  });

  it('names response codes, including the extended ones', () => {
    expect(rcodeName(0)).toBe('NOERROR');
    expect(rcodeName(3)).toBe('NXDOMAIN');
    expect(rcodeName(16)).toBe('BADVERS');
    expect(rcodeName(99)).toBe('RCODE99');
  });

  it('numbers the TSIG and TKEY codes as the IANA registry does', () => {
    expect(RCODES.BADVERS).toBe(16);
    expect(RCODES.BADSIG).toBe(16);
    expect(RCODES.BADKEY).toBe(17);
    expect(RCODES.BADTIME).toBe(18);
    expect(RCODES.BADMODE).toBe(19);
    expect(RCODES.BADNAME).toBe(20);
    // a header rcode of 16 is the EDNS code, so the shared value keeps the BADVERS name
    expect(rcodeName(16)).toBe('BADVERS');
    expect(rcodeName(17)).toBe('BADKEY');
    expect(rcodeName(18)).toBe('BADTIME');
    expect(rcodeName(19)).toBe('BADMODE');
  });
});
