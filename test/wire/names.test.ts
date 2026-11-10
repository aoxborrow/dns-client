import {
  canonicalName,
  countLabels,
  encodeName,
  isSubdomain,
  labelsToName,
  nameToLabels,
  ParseError,
  parentName,
  readName,
  splitName,
} from '../../src/index';

const bytes = (...values: (number | string)[]) =>
  Uint8Array.from(
    values.flatMap(value =>
      typeof value === 'number' ? [value] : [...Buffer.from(value, 'latin1')]
    )
  );

const nameAt = (message: Uint8Array, offset: number) => {
  const read = readName(message, offset);
  return { name: labelsToName(read.labels), end: read.end };
};

describe('reading names', () => {
  it('reads an uncompressed name', () => {
    const message = bytes(3, 'www', 7, 'example', 3, 'com', 0, 0xff);
    expect(nameAt(message, 0)).toEqual({ name: 'www.example.com', end: 17 });
  });

  it('reads the root', () => {
    expect(nameAt(bytes(0), 0)).toEqual({ name: '.', end: 1 });
  });

  it('follows a compression pointer and reports the end at the pointer', () => {
    // offset 0: example.com; offset 13: www + pointer to 0
    const message = bytes(7, 'example', 3, 'com', 0, 3, 'www', 0xc0, 0x00, 0xaa);
    expect(nameAt(message, 13)).toEqual({ name: 'www.example.com', end: 19 });
  });

  it('keeps the case it was sent in', () => {
    expect(nameAt(bytes(3, 'WwW', 3, 'CoM', 0), 0).name).toBe('WwW.CoM');
  });

  it('escapes bytes that are not plain text', () => {
    expect(nameAt(bytes(3, 'a.b', 2, 'c\\', 2, 0x00, 0xff, 0), 0).name).toBe(
      'a\\.b.c\\\\.\\000\\255'
    );
  });

  it('rejects a pointer that points forwards or at itself', () => {
    expect(() => readName(bytes(0xc0, 0x00), 0)).toThrow(ParseError);
    expect(() => readName(bytes(0xc0, 0x04, 0, 0, 1, 'a', 0), 0)).toThrow(ParseError);
  });

  it('rejects a name that runs off the end', () => {
    expect(() => readName(bytes(3, 'ww'), 0)).toThrow(ParseError);
    expect(() => readName(bytes(3, 'www'), 0)).toThrow(ParseError);
    expect(() => readName(bytes(0xc0), 0)).toThrow(ParseError);
  });

  it('rejects label types it does not know', () => {
    expect(() => readName(bytes(0x40, 0), 0)).toThrow(ParseError);
    expect(() => readName(bytes(0x80, 0), 0)).toThrow(ParseError);
  });

  it('rejects a name longer than 255 bytes', () => {
    // five 63-byte labels are 320 bytes on the wire
    const label = 'a'.repeat(63);
    const message = bytes(63, label, 63, label, 63, label, 63, label, 63, label, 0);
    expect(() => readName(message, 0)).toThrow(/longer than 255/);
  });
});

describe('writing names', () => {
  it('encodes a name without compression, in the case given', () => {
    expect(encodeName('Www.Example.com')).toEqual(bytes(3, 'Www', 7, 'Example', 3, 'com', 0));
  });

  it('treats a trailing dot as the same name, and encodes the root', () => {
    expect(encodeName('example.com.')).toEqual(encodeName('example.com'));
    expect(encodeName('.')).toEqual(bytes(0));
    expect(encodeName('')).toEqual(bytes(0));
  });

  it('round-trips every escape through the wire', () => {
    for (const name of [
      'a\\.b.example',
      'back\\\\slash.example',
      '\\000\\255.example',
      '_dmarc.example',
      '*.example',
    ]) {
      const read = readName(encodeName(name), 0);
      expect(labelsToName(read.labels)).toBe(name);
    }
  });

  it('rejects labels and names that are too long, empty labels and non-ASCII', () => {
    expect(() => encodeName(`${'a'.repeat(64)}.com`)).toThrow(/longer than 63/);
    expect(() => encodeName(Array(5).fill('a'.repeat(63)).join('.'))).toThrow(/longer than 255/);
    expect(() => encodeName('a..b')).toThrow(/empty label/);
    expect(() => encodeName('münchen.de')).toThrow(/non-ASCII/);
    expect(() => encodeName('bad\\')).toThrow(ParseError);
  });

  it('accepts a name of exactly 255 bytes', () => {
    // 63+1, 63+1, 63+1, 61+1, and the root: 255
    const name = ['a'.repeat(63), 'b'.repeat(63), 'c'.repeat(63), 'd'.repeat(61)].join('.');
    expect(encodeName(name)).toHaveLength(255);
    expect(nameToLabels(name)).toHaveLength(4);
  });
});

describe('name helpers', () => {
  it('splits on unescaped dots only', () => {
    expect(splitName('a.b.c')).toEqual(['a', 'b', 'c']);
    expect(splitName('a\\.b.c')).toEqual(['a\\.b', 'c']);
    expect(splitName('.')).toEqual([]);
    expect(splitName('example.com.')).toEqual(['example', 'com']);
  });

  it('folds ASCII case and drops the trailing dot for comparison', () => {
    expect(canonicalName('WWW.Example.COM.')).toBe('www.example.com');
    expect(canonicalName('.')).toBe('.');
    expect(canonicalName('')).toBe('.');
  });

  it('counts labels and finds the parent', () => {
    expect(countLabels('www.example.com')).toBe(3);
    expect(countLabels('.')).toBe(0);
    expect(parentName('www.example.com')).toBe('example.com');
    expect(parentName('com')).toBe('.');
    expect(parentName('.')).toBe('.');
  });

  it('tells whether a name is inside a zone, by whole labels', () => {
    expect(isSubdomain('www.example.com', 'example.com')).toBe(true);
    expect(isSubdomain('Example.COM', 'example.com')).toBe(true);
    expect(isSubdomain('notexample.com', 'example.com')).toBe(false);
    expect(isSubdomain('example.com', 'www.example.com')).toBe(false);
    expect(isSubdomain('anything.at.all', '.')).toBe(true);
  });
});
