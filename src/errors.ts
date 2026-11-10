// errors the library throws. Each carries `retryable`: whether trying the same thing
// again could plausibly succeed. More classes arrive with the layers that need them.

export class DnsError extends Error {
  // whether repeating the operation could succeed
  readonly retryable: boolean = false;

  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'DnsError';
  }
}

// bytes or text that are not valid DNS: a malformed message, record or name
export class ParseError extends DnsError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'ParseError';
  }
}

// a question that cannot be asked as given: an unknown type, a name that cannot be encoded
export class InvalidQueryError extends DnsError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'InvalidQueryError';
  }
}

// record text that is not valid for its type. The message is written to be shown to the
// person who typed the record
export class RecordSyntaxError extends DnsError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'RecordSyntaxError';
  }
}
