// wire layer: encoding queries and decoding messages on Uint8Array, keeping the raw RDATA.
// Runs on any runtime.
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
  countLabels,
  encodeName,
  isSubdomain,
  labelsToName,
  nameToLabels,
  parentName,
  readName,
  splitName,
} from './names';
export type { NameRead } from './names';
