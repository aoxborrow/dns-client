// the fixed parts of a DNS message header (RFC 1035 §4.1.1, RFC 2535 for AD and CD)

// flag bits within the 16-bit flags word
export const HEADER_FLAGS = {
  QR: 0x8000, // this message is a response
  AA: 0x0400, // the responding server is authoritative for the name
  TC: 0x0200, // the message was truncated to fit the transport
  RD: 0x0100, // recursion desired
  RA: 0x0080, // recursion available
  AD: 0x0020, // the resolver authenticated the data
  CD: 0x0010, // checking disabled: return data even if validation fails
} as const;

// operation codes, from the IANA "DNS OpCodes" registry
export const OPCODES = {
  QUERY: 0,
  IQUERY: 1, // obsolete
  STATUS: 2,
  NOTIFY: 4,
  UPDATE: 5,
  DSO: 6,
} as const;

// response codes, from the IANA "DNS RCODEs" registry. Codes above 15 only fit with EDNS
export const RCODES = {
  NOERROR: 0, // no error
  FORMERR: 1, // the server could not interpret the query
  SERVFAIL: 2, // the server failed to process the query
  NXDOMAIN: 3, // the name does not exist
  NOTIMP: 4, // the server does not support this kind of query
  REFUSED: 5, // the server refuses to answer for policy reasons
  YXDOMAIN: 6, // a name exists that should not
  YXRRSET: 7, // a record set exists that should not
  NXRRSET: 8, // a record set that should exist does not
  NOTAUTH: 9, // the server is not authoritative for the zone
  NOTZONE: 10, // a name is not within the zone
  DSOTYPENI: 11, // DSO type not implemented
  BADVERS: 16, // unsupported EDNS version
  BADSIG: 16, // TSIG signature failure, sharing 16 with BADVERS as the registry lists it
  BADKEY: 17, // key not recognised
  BADTIME: 18, // signature outside its time window
  BADMODE: 19, // TKEY mode not supported
  BADNAME: 20, // duplicate key name
  BADALG: 21, // algorithm not supported
  BADTRUNC: 22, // bad truncation
  BADCOOKIE: 23, // bad or missing server cookie
} as const;

export type RcodeName = keyof typeof RCODES;

// the first name listed for a code wins. 16 reads as BADVERS because a header rcode of 16
// can only be the EDNS one: a TSIG BADSIG travels in the TSIG record's error field with a
// header rcode of NOTAUTH (RFC 8945 §5.2)
const RCODE_NAMES = new Map<number, string>();
for (const [name, code] of Object.entries(RCODES)) {
  if (!RCODE_NAMES.has(code)) RCODE_NAMES.set(code, name);
}

// the mnemonic for a response code, or `RCODE<n>` for one with no name
export function rcodeName(code: number): string {
  return RCODE_NAMES.get(code) ?? `RCODE${code}`;
}
