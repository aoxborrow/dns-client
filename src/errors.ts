import { rcodeName } from './protocol/header';
import type { RcodeName } from './protocol/header';
import type { ExtendedErrorOption } from './records/edns';
import type { RecordProblem } from './records/problems';
import type { TraceHop } from './resolvers/answer';
import type { TransportName } from './transports/types';

/** what an error is made with: its cause, and what is known of the exchange it came from */
export interface DnsErrorOptions {
  cause?: unknown;
  /** the server the question was put to, as the caller named it */
  server?: string;
  /** the name asked about */
  query?: string;
  /** the record type asked for */
  type?: string;
  transport?: TransportName;
  /** the response code of the answer this error was raised from */
  rcode?: number;
  extendedErrors?: ExtendedErrorOption[];
}

/** what an error looks like inside a result or an event: plain data, no class instance */
export interface ErrorData {
  name: string;
  message: string;
  retryable: boolean;
  rcode?: number;
  rcodeName?: RcodeName | `RCODE${number}`;
  extendedErrors?: ExtendedErrorOption[];
}

/**
 * one server's part in a query that failed: the address it was asked at, and why it gave
 * nothing usable
 */
export interface ServerFailure {
  server: string;
  error: DnsError;
}

/**
 * errors the library throws. Each carries `retryable`: whether trying the same thing again could
 * plausibly succeed.
 *
 * codes are DNS-native. An error raised from a server's answer carries `rcode`, `rcodeName` and
 * `extendedErrors`; one raised before any answer (a timeout, a refused connection, a proxy failure)
 * carries none. There is no HTTP-style status code
 *
 * Every error the library throws is one of its subclasses, told apart by class and `name`.
 */
export class DnsError extends Error {
  /** whether repeating the operation could succeed */
  readonly retryable: boolean = false;
  server?: string;
  query?: string;
  type?: string;
  transport?: TransportName;
  rcode?: number;
  rcodeName?: RcodeName | `RCODE${number}`;
  extendedErrors?: ExtendedErrorOption[];
  /** from the authoritative resolver: the servers asked before the query failed */
  trace?: TraceHop[];
  /**
   * from a resolver that asked more than one server: what went wrong at each, in the order
   * they were asked. This error is among them
   */
  failures?: ServerFailure[];

  constructor(message: string, options: DnsErrorOptions = {}) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'DnsError';
    addErrorContext(this, options);
    if (options.rcode !== undefined) {
      this.rcode = options.rcode;
      this.rcodeName = rcodeName(options.rcode);
    }
    if (options.extendedErrors?.length) this.extendedErrors = options.extendedErrors;
  }

  /**
   * plain data for JSON. `failures` holds this error too, so each failure is written as
   * its server, name and message, and the result has no cycle
   */
  toJSON(): ErrorData &
    Pick<DnsErrorOptions, 'server' | 'query' | 'type' | 'transport'> & {
      failures?: { server: string; name: string; message: string; rcode?: number }[];
    } {
    return {
      name: this.name,
      message: this.message,
      retryable: this.retryable,
      server: this.server,
      query: this.query,
      type: this.type,
      transport: this.transport,
      rcode: this.rcode,
      rcodeName: this.rcodeName,
      extendedErrors: this.extendedErrors,
      failures: this.failures?.map(({ server, error }) => ({
        server,
        name: error.name,
        message: error.message,
        rcode: error.rcode,
      })),
    };
  }
}

// fill in whatever is not already known about the exchange an error came from. A layer
// deep in a transport knows the socket failed; only the caller knows what was being asked
export function addErrorContext(
  error: DnsError,
  context: Pick<DnsErrorOptions, 'server' | 'query' | 'type' | 'transport'>
): void {
  error.server ??= context.server;
  error.query ??= context.query;
  error.type ??= context.type;
  error.transport ??= context.transport;
}

/** bytes or text that are not valid DNS: a malformed message, record or name */
export class ParseError extends DnsError {
  constructor(message: string, options?: DnsErrorOptions) {
    super(message, options);
    this.name = 'ParseError';
  }
}

/** a question that cannot be asked as given: an unknown type, a name that cannot be encoded */
export class InvalidQueryError extends DnsError {
  constructor(message: string, options?: DnsErrorOptions) {
    super(message, options);
    this.name = 'InvalidQueryError';
  }
}

/**
 * record text that is not valid for its type. The message is written to be shown to the
 * person who typed the record. `problems` says the same as data: one entry for each thing
 * found wrong, each with a code and the values behind it
 */
export class RecordSyntaxError extends DnsError {
  readonly problems: RecordProblem[];

  constructor(message: string, options: DnsErrorOptions & { problems: RecordProblem[] }) {
    super(message, options);
    this.name = 'RecordSyntaxError';
    this.problems = options.problems;
  }
}

/**
 * there is no server to ask: none was given, or its name does not resolve. A server that
 * cannot be read at all is the caller's mistake, and a TypeError
 */
export class NoServerError extends DnsError {
  constructor(message: string, options?: DnsErrorOptions) {
    super(message, options);
    this.name = 'NoServerError';
  }
}

/** no answer arrived in the time allowed */
export class TimeoutError extends DnsError {
  override readonly retryable: boolean = true;

  constructor(message: string, options?: DnsErrorOptions) {
    super(message, options);
    this.name = 'TimeoutError';
  }
}

/**
 * the server could not be reached, or the connection to it failed. Also what a failure
 * thrown by a caller's own `fetch` or `connect` becomes
 */
export class ConnectionError extends DnsError {
  override readonly retryable: boolean = true;

  constructor(message: string, options?: DnsErrorOptions) {
    super(message, options);
    this.name = 'ConnectionError';
  }
}

/** the proxy could not be reached, refused the request or rejected the credentials */
export class ProxyError extends DnsError {
  override readonly retryable: boolean = true;

  constructor(message: string, options?: DnsErrorOptions) {
    super(message, options);
    this.name = 'ProxyError';
  }
}

/**
 * the server accepted the query and then said nothing: it closed the connection, or sent
 * an empty body
 */
export class EmptyResponseError extends DnsError {
  override readonly retryable: boolean = true;

  constructor(message: string, options?: DnsErrorOptions) {
    super(message, options);
    this.name = 'EmptyResponseError';
  }
}

/**
 * an answer that cannot be trusted as the answer to the question: it does not decode, or
 * it is about a different question
 */
export class InvalidResponseError extends DnsError {
  constructor(message: string, options?: DnsErrorOptions) {
    super(message, options);
    this.name = 'InvalidResponseError';
  }
}

/** the answer was cut short and there is no larger transport left to ask over */
export class TruncatedError extends DnsError {
  constructor(message: string, options?: DnsErrorOptions) {
    super(message, options);
    this.name = 'TruncatedError';
  }
}

/** an error as plain data, for results and events */
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
