// wire layer: encoding queries and decoding messages on Uint8Array, keeping the raw RDATA.
// Runs on any runtime.
// the errors this entry throws, the same classes the root exports
export { DnsError, InvalidQueryError, ParseError } from '../errors';
export { decodeMessage } from './message';
export type {
  Edns,
  EdnsOption,
  HeaderFlags,
  Message,
  Question,
  ResourceRecord,
  Section,
} from './message';
export { encodeMessage, encodeQuery } from './encode';
export type { EncodableMessage, Query, QueryEdns } from './encode';
export {
  canonicalName,
  compareNames,
  countLabels,
  encodeName,
  isSubdomain,
  labelsToName,
  nameToLabels,
  parentName,
  readName,
  splitName,
  toAsciiName,
} from './names';
export type { NameRead } from './names';
export {
  compareBytes,
  concatBytes,
  fromBase64,
  fromHex,
  readU16,
  readU32,
  toBase32Hex,
  toBase64,
  toHex,
  writeU16,
  writeU32,
} from './bytes';
