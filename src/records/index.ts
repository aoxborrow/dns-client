// records layer: typed record interfaces, protocol tables, and the functions that parse,
// format and validate records. Runs on any runtime and has no side effects on import.
// the errors this entry throws, so a caller that imports only `/records` can tell them apart.
// They are the same classes the root exports
export { DnsError, InvalidQueryError, ParseError, RecordSyntaxError } from '../errors';
export type { DnsErrorOptions } from '../errors';
export { classCode, className, RECORD_CLASSES } from '../protocol/classes';
export type { RecordClassName } from '../protocol/classes';
export { DEFAULT_UDP_PAYLOAD_SIZE, EDNS_OPTIONS, EXTENDED_DNS_ERRORS } from '../protocol/edns';
export { HEADER_FLAGS, OPCODES, rcodeName, RCODES } from '../protocol/header';
export type { RcodeName } from '../protocol/header';
export { RECORD_TYPES, typeCode, typeName } from '../protocol/types';
export type { RecordTypeName } from '../protocol/types';
export {
  decodeDnskey,
  decodeDs,
  decodeNsec,
  decodeNsec3,
  decodeNsec3Param,
  decodeRecord,
  decodeRecords,
  decodeRrsig,
  decodeTypeBitmap,
  isKnownRecordType,
  serviceParamName,
} from './decode';
export type {
  DecodeOptions,
  DnskeyFields,
  DsFields,
  Nsec3Fields,
  Nsec3ParamFields,
  NsecFields,
  RrsigFields,
} from './decode';
export type * from './types';
export { parseIpv4, parseIpv6, reverseIp } from './addresses';
export { formatRecord, formatRecordData, formatSignatureTime } from './format';
export type { FormatOptions } from './format';
export { deduplicateRecords, flattenRecord, flattenRecords, sortRecords } from './helpers';
export type { FlatRecord, FlatRecordInput } from './helpers';
export { hasRecordParser, parseRecordData } from './parse';
export type { ParseOptions, RecordData } from './parse';
export {
  canonicalRecord,
  diffRecords,
  findCnameConflicts,
  findRepeatedRecords,
  parseRecord,
} from './validate';
export type { DiffOptions, RecordDiff, ValidateOptions } from './validate';
export { qualify, relativize } from './names';
export type {
  RecordClash,
  RecordProblem,
  RecordProblemCode,
  RecordProblemValues,
} from './problems';
export {
  clientSubnetOption,
  cookieOption,
  decodeEdnsOption,
  decodeEdnsOptions,
  extendedErrors,
  nsidOption,
  paddingOption,
} from './edns';
export type {
  AlgorithmsOption,
  ClientSubnetOption,
  CookieOption,
  ExtendedErrorOption,
  KeyTagOption,
  NsidOption,
  PaddingOption,
  TcpKeepaliveOption,
  TypedEdnsOption,
  UnknownOption,
} from './edns';
