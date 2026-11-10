import { rcodeName } from './protocol/header';
import type { ExtendedErrorOption } from './records/edns';
import type { TransportName } from './transports/types';

// errors the library throws. Each carries `retryable`: whether trying the same thing
// again could plausibly succeed.
//
// codes are DNS-native. An error raised from a server's answer carries `rcode`,
// `rcodeName` and `extendedErrors`; one raised before any answer (a timeout, a refused
// connection, a proxy failure) carries none. There is no HTTP-style status code

export interface DnsErrorOptions {
  cause?: unknown;
  // the server the question was put to, as the caller named it
  server?: string;
  // the name asked about
  query?: string;
  // the record type asked for
  type?: string;
  transport?: TransportName;
  // the response code of the answer this error was raised from
  rcode?: number;
  extendedErrors?: ExtendedErrorOption[];
}

// what an error looks like inside a result or an event: plain data, no class instance
export interface ErrorData {
  name: string;
  message: string;
  retryable: boolean;
  rcode?: number;
  rcodeName?: string;
  extendedErrors?: ExtendedErrorOption[];
}

export class DnsError extends Error {
  // whether repeating the operation could succeed
  readonly retryable: boolean = false;
  server?: string;
  query?: string;
  type?: string;
  transport?: TransportName;
  rcode?: number;
  rcodeName?: string;
  extendedErrors?: ExtendedErrorOption[];

  constructor(message: string, options: DnsErrorOptions = {}) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'DnsError';
    this.addContext(options);
    if (options.rcode !== undefined) {
      this.rcode = options.rcode;
      this.rcodeName = rcodeName(options.rcode);
    }
    if (options.extendedErrors?.length) this.extendedErrors = options.extendedErrors;
  }

  // fill in whatever is not already known about the exchange the error came from. A layer
  // deep in a transport knows the socket failed; only the caller knows what was being asked
  addContext(context: Pick<DnsErrorOptions, 'server' | 'query' | 'type' | 'transport'>): this {
    this.server ??= context.server;
    this.query ??= context.query;
    this.type ??= context.type;
    this.transport ??= context.transport;
    return this;
  }
}

// bytes or text that are not valid DNS: a malformed message, record or name
export class ParseError extends DnsError {
  constructor(message: string, options?: DnsErrorOptions) {
    super(message, options);
    this.name = 'ParseError';
  }
}

// a question that cannot be asked as given: an unknown type, a name that cannot be encoded
export class InvalidQueryError extends DnsError {
  constructor(message: string, options?: DnsErrorOptions) {
    super(message, options);
    this.name = 'InvalidQueryError';
  }
}

// record text that is not valid for its type. The message is written to be shown to the
// person who typed the record
export class RecordSyntaxError extends DnsError {
  constructor(message: string, options?: DnsErrorOptions) {
    super(message, options);
    this.name = 'RecordSyntaxError';
  }
}

// there is no server to ask: none was given, or its name does not resolve
export class NoServerError extends DnsError {
  constructor(message: string, options?: DnsErrorOptions) {
    super(message, options);
    this.name = 'NoServerError';
  }
}

// no answer arrived in the time allowed
export class TimeoutError extends DnsError {
  override readonly retryable: boolean = true;

  constructor(message: string, options?: DnsErrorOptions) {
    super(message, options);
    this.name = 'TimeoutError';
  }
}

// the server could not be reached, or the connection to it failed. Also what a failure
// thrown by a caller's own `fetch` or `connect` becomes
export class ConnectionError extends DnsError {
  override readonly retryable: boolean = true;

  constructor(message: string, options?: DnsErrorOptions) {
    super(message, options);
    this.name = 'ConnectionError';
  }
}

// the proxy could not be reached, refused the request or rejected the credentials
export class ProxyError extends DnsError {
  override readonly retryable: boolean = true;

  constructor(message: string, options?: DnsErrorOptions) {
    super(message, options);
    this.name = 'ProxyError';
  }
}

// the server accepted the query and then said nothing: it closed the connection, or sent
// an empty body
export class EmptyResponseError extends DnsError {
  override readonly retryable: boolean = true;

  constructor(message: string, options?: DnsErrorOptions) {
    super(message, options);
    this.name = 'EmptyResponseError';
  }
}

// an answer that cannot be trusted as the answer to the question: it does not decode, or
// it is about a different question
export class InvalidResponseError extends DnsError {
  constructor(message: string, options?: DnsErrorOptions) {
    super(message, options);
    this.name = 'InvalidResponseError';
  }
}

// the answer was cut short and there is no larger transport left to ask over
export class TruncatedError extends DnsError {
  constructor(message: string, options?: DnsErrorOptions) {
    super(message, options);
    this.name = 'TruncatedError';
  }
}

// an error as plain data, for results and events
export function errorData(error: unknown): ErrorData {
  if (error instanceof DnsError) {
    return {
      name: error.name,
      message: error.message,
      retryable: error.retryable,
      ...(error.rcode !== undefined && { rcode: error.rcode, rcodeName: error.rcodeName }),
      ...(error.extendedErrors && { extendedErrors: error.extendedErrors }),
    };
  }
  if (error instanceof Error) {
    return { name: error.name, message: error.message, retryable: false };
  }
  return { name: 'Error', message: String(error), retryable: false };
}
