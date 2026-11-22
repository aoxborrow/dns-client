import { RecordSyntaxError } from '../errors';

// what is wrong with a record, as data. `code` names the rule the record broke and
// `values` holds what broke it, so a program can act on a problem or word it in its own
// language. `detail` says the same in English, for showing to a person as it is.
//
// codes are lowercase words joined by hyphens. A `field` value names the part of the
// record the problem is in, as the English detail does: `name`, `target`, `exchange`,
// `address`, `key tag` and so on

/** every validation problem code, with the values a problem of that code carries */
export interface RecordProblemValues {
  /** the envelope: name, type, class and TTL */
  'invalid-ttl': { ttl: number };
  'missing-type': Record<string, never>;
  'unknown-type': { type: string };
  'unknown-class': { class: string };
  'outside-zone': { zone: string };

  /** names, in the envelope and in the data */
  'empty-name': { field: string };
  'zone-relative-name': { field: string };
  'invalid-name': { field: string; reason: string };
  'invalid-label': { field: string; label: string };
  'misplaced-wildcard': { field: string };
  'wildcard-target': { field: string };

  /** the syntax of the data */
  'no-data': Record<string, never>;
  'missing-field': { field: string };
  'quoted-field': { field: string };
  'number-out-of-range': { field: string; max: number; text: string };
  'string-too-long': { field: string };
  'data-too-long': Record<string, never>;
  'invalid-escape': { escape: string };
  'trailing-backslash': Record<string, never>;
  'unclosed-quote': Record<string, never>;
  'invalid-hex': { field: string };
  'invalid-base64': { field: string };
  'invalid-base32hex': { field: string };
  'unknown-mnemonic': { field: string; text: string };
  'invalid-value': { field: string; text: string };
  'invalid-address': { field: string; text: string };
  'unknown-service-parameter': { key: string };
  'repeated-service-parameter': { key: string };
  'missing-parameter-value': { key: string };
  'unexpected-parameter-value': { key: string };
  'extra-data': { text: string };
  'generic-length-mismatch': Record<string, never>;
  'invalid-generic-data': { type: string };
  'generic-form-only': { type: string };

  /** rules on top of syntax */
  'cname-to-self': Record<string, never>;
  'null-mx-preference': { preference: number };
  'invalid-caa-tag': { tag: string };
  'digest-length': { digestType: number; expected: number; actual: number };

  /** sets of records */
  'multiple-cnames': { targets: string[] };
  'cname-and-other-data': { types: string[] };
  'repeated-record': { data: string; count: number };
}

/** a validation problem code, such as `invalid-address` */
export type RecordProblemCode = keyof RecordProblemValues;

/**
 * one problem. A problem found while checking a record carries the record's `name` and
 * `type` as they were given; one from `parseRecordData`, which sees only the data, has
 * neither
 */
export type RecordProblem = {
  [C in RecordProblemCode]: {
    code: C;
    values: RecordProblemValues[C];
    detail: string;
    name?: string;
    type?: string;
  };
}[RecordProblemCode];

/** a problem with a set of records, which always says which record it is about */
export type RecordClash = RecordProblem & { name: string; type: string };

// the error for one problem
export function recordError<C extends RecordProblemCode>(
  code: C,
  values: RecordProblemValues[C],
  detail: string,
  options: { cause?: unknown } = {}
): RecordSyntaxError {
  return new RecordSyntaxError(detail, {
    ...options,
    problems: [{ code, values, detail } as RecordProblem],
  });
}

// the error for one or more problems. With one, the message is its detail; with more, it
// lists them all
export function recordErrors(problems: RecordProblem[]): RecordSyntaxError {
  const message =
    problems.length === 1
      ? problems[0].detail
      : `${problems.length} problems: ${problems.map(problem => problem.detail).join('; ')}`;
  return new RecordSyntaxError(message, { problems });
}
