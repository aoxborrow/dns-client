import {
  ConnectionError,
  DnsError,
  EmptyResponseError,
  InvalidQueryError,
  InvalidResponseError,
  NoServerError,
  ParseError,
  ProxyError,
  TimeoutError,
  TruncatedError,
} from '../errors';
import type { ErrorData } from '../errors';
import { RCODES } from '../protocol/header';

// the errors the facade throws, shaped like the ones `node:dns` throws: a plain `Error`
// with `code`, `syscall` and `hostname`, and `errno` where Node sets one. The library's
// own errors carry no codes; this file is the one place they are given some

export interface NodeDnsError extends Error {
  errno: number | undefined;
  code: string;
  syscall: string;
  hostname: string;
}

// libuv's numbers for the getaddrinfo failures `lookup` reports. The resolve methods
// leave `errno` unset, as Node does
const GETADDRINFO_ERRNO: Record<string, number> = {
  EAI_AGAIN: -3001,
  ENOTFOUND: -3008,
};

// an error in Node's format: `queryA ENOTFOUND example.invalid`. The library error it
// stands for, if any, is its `cause`
export function nodeError(
  code: string,
  syscall: string,
  hostname: string,
  options: { errno?: number; cause?: unknown } = {}
): NodeDnsError {
  const error = new Error(
    `${syscall} ${code} ${hostname}`,
    options.cause === undefined ? undefined : { cause: options.cause }
  ) as NodeDnsError;
  // in Node's order, so the error prints the same
  error.errno = options.errno;
  error.code = code;
  error.syscall = syscall;
  error.hostname = hostname;
  return error;
}

export function getaddrinfoError(code: string, hostname: string, cause?: unknown): NodeDnsError {
  return nodeError(code, 'getaddrinfo', hostname, { errno: GETADDRINFO_ERRNO[code], cause });
}

// the code for a response that answers nothing, or undefined for one that does
export function rcodeError(rcode: number): string | undefined {
  switch (rcode) {
    case RCODES.NOERROR:
      return undefined;
    case RCODES.NXDOMAIN:
      return 'ENOTFOUND';
    case RCODES.SERVFAIL:
      return 'ESERVFAIL';
    case RCODES.REFUSED:
      return 'EREFUSED';
    case RCODES.FORMERR:
      return 'EFORMERR';
    case RCODES.NOTIMP:
      return 'ENOTIMP';
    default:
      return 'EBADRESP';
  }
}

// the code for a failure the library threw: no usable response arrived
export function failureCode(error: unknown): string {
  if (error instanceof TimeoutError) return 'ETIMEOUT';
  if (
    error instanceof ConnectionError ||
    error instanceof ProxyError ||
    error instanceof EmptyResponseError ||
    error instanceof NoServerError
  ) {
    return 'ECONNREFUSED';
  }
  if (
    error instanceof InvalidResponseError ||
    error instanceof ParseError ||
    error instanceof TruncatedError
  ) {
    return 'EBADRESP';
  }
  if (error instanceof InvalidQueryError) return 'EBADNAME';
  if (error instanceof Error && error.name === 'AbortError') return 'ECANCELLED';
  if (error instanceof DnsError) return 'EBADRESP';
  // not the library's: a bug, or the caller's own transport failing
  return 'ECONNREFUSED';
}

// the code for a truncated UDP answer whose TCP retry failed. c-ares does not hand back
// the truncated answer: the query fails the way its TCP connection did
export function tcpFallbackCode(error: ErrorData): string {
  switch (error.name) {
    case 'TimeoutError':
      return 'ETIMEOUT';
    case 'ConnectionError':
    case 'ProxyError':
    case 'EmptyResponseError':
      return 'ECONNREFUSED';
    default:
      return 'EBADRESP';
  }
}

// Node's argument errors: a TypeError with a code, thrown before anything is asked
export function argumentError(message: string, code = 'ERR_INVALID_ARG_VALUE'): TypeError {
  const error = new TypeError(message) as TypeError & { code: string };
  error.code = code;
  return error;
}

export function checkHostname(hostname: unknown, argument = 'name'): string {
  if (typeof hostname !== 'string') {
    throw argumentError(
      `The "${argument}" argument must be of type string. Received ${describe(hostname)}`,
      'ERR_INVALID_ARG_TYPE'
    );
  }
  return hostname;
}

function describe(value: unknown): string {
  if (value === null || value === undefined) return String(value);
  if (typeof value === 'function') return 'function';
  if (typeof value === 'object') return 'an instance of Object';
  if (typeof value === 'symbol') return `type symbol (${value.toString()})`;
  return `type ${typeof value} (${value as number | boolean | bigint})`;
}
