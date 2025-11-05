// convert any error to DnsError (preserves DnsError and RetryableDnsError types)
export function toDnsError(error: unknown): DnsError {
  // already a DnsError or RetryableDnsError, return as-is
  if (error instanceof DnsError) {
    return error;
  }

  // extract message from Error or convert unknown to string
  const message =
    error instanceof Error ? error.message : String(error) || 'An unknown error occurred';

  // create DnsError instance
  const codedError = new (class extends DnsError {})(message);

  // if it's an Error, preserve the original error properties
  if (error instanceof Error) {
    codedError.name = error.name;
    codedError.stack = error.stack;
  } else {
    codedError.name = 'DnsError';
  }

  return codedError;
}

// base error class for custom errors with codes
// matches Node.js SystemError structure
export class DnsError extends Error {
  public code: number;
  public errno: number;
  public syscall: string;

  constructor(message: string) {
    super(message);
    this.name = 'DnsError';

    // SystemError-like properties
    // code: numeric error code (set by subclass property initializer or defaults to -1)
    // errno: numeric error code (always equals code)
    // syscall: always 'dns-client' for DNS client operations
    this.code = -1;
    this.errno = -1;
    this.syscall = 'dns-client';

    Object.setPrototypeOf(this, new.target.prototype);

    // Maintain proper stack trace (Node.js only)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
  }

  // determine if this error should trigger a retry
  // can be overridden by subclasses for custom logic
  shouldRetry() {
    return false;
  }
}

// abstract base class for retryable errors
export class RetryableDnsError extends DnsError {
  constructor(message: string) {
    super(message);
    this.name = 'RetryableError';
  }

  // determine if this error should trigger a retry
  // can be overridden by subclasses for custom logic
  shouldRetry() {
    return true;
  }
}

// query timeout error
export class TimeoutError extends RetryableDnsError {
  public code = 408; // Request Timeout

  constructor(message: string) {
    super(message);
    this.name = 'TimeoutError';
    // ensure errno matches code
    this.errno = this.code;
  }
}

// connection error
export class ConnectionError extends RetryableDnsError {
  public code = 503; // Service Unavailable

  constructor(message: string) {
    super(message);
    this.name = 'ConnectionError';
    this.errno = this.code;
  }
}

// no DNS server found
export class ServerNotFoundError extends DnsError {
  public code = 501; // Not Implemented

  constructor(message: string) {
    super(message);
    this.name = 'ServerNotFoundError';
    this.errno = this.code;
  }
}

// invalid response from DNS server
export class InvalidResponseError extends RetryableDnsError {
  public code = 502; // Bad Gateway

  constructor(message: string) {
    super(message);
    this.name = 'InvalidResponseError';
    this.errno = this.code;
  }
}

// DNS parsing error for individual record parsing
export class ParsingError extends DnsError {
  public code = 422; // Unprocessable Entity

  constructor(message: string) {
    super(message);
    this.name = 'ParsingError';
    this.errno = this.code;
  }
}

// DNS configuration error
export class ConfigurationError extends DnsError {
  public code = 500; // Internal Server Error

  constructor(message: string) {
    super(message);
    this.name = 'ConfigurationError';
    this.errno = this.code;
  }
}

// DNS response truncated error
export class TruncatedResponseError extends DnsError {
  public code = 413; // Payload Too Large

  constructor(message: string) {
    super(message);
    this.name = 'TruncatedResponseError';
    this.errno = this.code;
  }
}

// AbortSignal cancellation error
export class AbortError extends DnsError {
  public code = 499; // Client Closed Request

  constructor(message: string) {
    super(message);
    this.name = 'AbortError';
    this.errno = this.code;
  }

  // never retry abort errors
  shouldRetry() {
    return false;
  }
}
