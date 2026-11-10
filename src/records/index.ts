// records layer: typed record interfaces, protocol tables, and the functions that parse,
// format and validate records. Runs on any runtime and has no side effects on import.
export { classCode, className, RECORD_CLASSES } from '../protocol/classes';
export type { RecordClassName } from '../protocol/classes';
export { DEFAULT_UDP_PAYLOAD_SIZE, EDNS_OPTIONS, EXTENDED_DNS_ERRORS } from '../protocol/edns';
export { HEADER_FLAGS, OPCODES, rcodeName, RCODES } from '../protocol/header';
export type { RcodeName } from '../protocol/header';
export { RECORD_TYPES, typeCode, typeName } from '../protocol/types';
export type { RecordTypeName } from '../protocol/types';
