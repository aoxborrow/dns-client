import { InvalidQueryError } from '../errors';

/** record classes, from the IANA "DNS CLASSes" registry */
export const RECORD_CLASSES = {
  IN: 1, // Internet
  CH: 3, // Chaos
  HS: 4, // Hesiod
  NONE: 254, // used in dynamic update
  ANY: 255, // any class, in a question
} as const;

/** a class mnemonic, such as `IN` */
export type RecordClassName = keyof typeof RECORD_CLASSES;

const CODES = new Map<string, number>(Object.entries(RECORD_CLASSES));
const NAMES = new Map<number, string>(
  Object.entries(RECORD_CLASSES).map(([name, code]) => [code, name])
);

/** the mnemonic for a class code, or the RFC 3597 form (`CLASS32`) for one with no name */
export function className(code: number): string {
  return NAMES.get(code) ?? `CLASS${code}`;
}

/** the code for a class given as a mnemonic (any case), an RFC 3597 `CLASSnnn`, or a number */
export function classCode(cls: string | number): number {
  if (typeof cls === 'number') {
    if (!Number.isInteger(cls) || cls < 0 || cls > 0xffff) {
      throw new InvalidQueryError(`Record class out of range: ${cls}`);
    }
    return cls;
  }
  const upper = cls.trim().toUpperCase();
  const known = CODES.get(upper);
  if (known !== undefined) return known;
  const generic = /^CLASS(\d{1,5})$/.exec(upper);
  if (generic && Number(generic[1]) <= 0xffff) return Number(generic[1]);
  throw new InvalidQueryError(`Unknown record class: ${cls}`);
}
