// @aoxborrow/dns: the resolvers, the answers they return, the errors and the types to
// work with them. The codec, the record functions, the transports and DNSSEC have entries
// of their own (`/wire`, `/records`, `/transports`, `/dnssec`); the record types and the
// errors are here as well, so a program that only asks questions needs nothing else.
//
// questions are asked through a resolver. The function both are built on (`./exchange`:
// one question to one server) is not exported: asking one particular server is the
// `server` option on `Resolver.query`
export {
  ConnectionError,
  DnsError,
  EmptyResponseError,
  errorData,
  InvalidQueryError,
  InvalidResponseError,
  NoServerError,
  ParseError,
  ProxyError,
  RecordSyntaxError,
  TimeoutError,
  TruncatedError,
} from './errors';
export type { DnsErrorOptions, ErrorData, ServerFailure } from './errors';
export * from './resolvers/index';
export { createTransports } from './transports/set';
export type { Transports } from './transports/set';
export type * from './transports/types';
export type * from './records/types';
export type {
  RecordClash,
  RecordProblem,
  RecordProblemCode,
  RecordProblemValues,
} from './records/problems';
export type { ExtendedErrorOption, TypedEdnsOption } from './records/edns';
export type { RcodeName } from './protocol/header';
export type { RecordClassName } from './protocol/classes';
export type { RecordTypeName } from './protocol/types';
export type {
  Edns,
  EdnsOption,
  HeaderFlags,
  Message,
  Question,
  ResourceRecord,
  Section,
} from './wire/message';
export type { Security } from './dnssec/validate';
export type { ReasonCode, SecurityReason, SecurityStatus } from './dnssec/reasons';
export type { ChainLink, LinkKind } from './dnssec/judge';
export type { TrustAnchor } from './dnssec/types';
