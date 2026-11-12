import { InvalidQueryError } from '../errors';

// resource record types, from the IANA "Resource Record (RR) TYPEs" registry
// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
export const RECORD_TYPES = {
  'A': 1, // a host address
  'NS': 2, // an authoritative name server
  'MD': 3, // a mail destination (OBSOLETE - use MX)
  'MF': 4, // a mail forwarder (OBSOLETE - use MX)
  'CNAME': 5, // the canonical name for an alias
  'SOA': 6, // marks the start of a zone of authority
  'MB': 7, // a mailbox domain name (EXPERIMENTAL)
  'MG': 8, // a mail group member (EXPERIMENTAL)
  'MR': 9, // a mail rename domain name (EXPERIMENTAL)
  'NULL': 10, // a null RR (EXPERIMENTAL)
  'WKS': 11, // a well known service description
  'PTR': 12, // a domain name pointer
  'HINFO': 13, // host information
  'MINFO': 14, // mailbox or mail list information
  'MX': 15, // mail exchange
  'TXT': 16, // text strings
  'RP': 17, // for Responsible Person
  'AFSDB': 18, // for AFS Data Base location
  'X25': 19, // for X.25 PSDN address
  'ISDN': 20, // for ISDN address
  'RT': 21, // for Route Through
  'NSAP': 22, // for NSAP address: NSAP style A record (DEPRECATED)
  'NSAP-PTR': 23, // for domain name pointer: NSAP style (DEPRECATED)
  'SIG': 24, // for security signature
  'KEY': 25, // for security key
  'PX': 26, // x.400 mail mapping information
  'GPOS': 27, // geographical Position
  'AAAA': 28, // iP6 Address
  'LOC': 29, // location Information
  'NXT': 30, // next Domain (OBSOLETE)
  'EID': 31, // endpoint Identifier
  'NIMLOC': 32, // nimrod Locator
  'SRV': 33, // server Selection
  'ATMA': 34, // aTM Address
  'NAPTR': 35, // naming Authority Pointer
  'KX': 36, // key Exchanger
  'CERT': 37, // cERT
  'A6': 38, // a6 (OBSOLETE - use AAAA)
  'DNAME': 39, // dNAME
  'SINK': 40, // sINK
  'OPT': 41, // oPT
  'APL': 42, // aPL
  'DS': 43, // delegation Signer
  'SSHFP': 44, // sSH Key Fingerprint
  'IPSECKEY': 45, // iPSECKEY
  'RRSIG': 46, // rRSIG
  'NSEC': 47, // nSEC
  'DNSKEY': 48, // dNSKEY
  'DHCID': 49, // dHCID
  'NSEC3': 50, // nSEC3
  'NSEC3PARAM': 51, // nSEC3PARAM
  'TLSA': 52, // tLSA
  'SMIMEA': 53, // s/MIME cert association
  'HIP': 55, // host Identity Protocol
  'NINFO': 56, // nINFO
  'RKEY': 57, // rKEY
  'TALINK': 58, // trust Anchor LINK
  'CDS': 59, // child DS
  'CDNSKEY': 60, // dNSKEY(s) the Child wants reflected in DS
  'OPENPGPKEY': 61, // openPGP Key
  'CSYNC': 62, // child-To-Parent Synchronization
  'ZONEMD': 63, // message Digest Over Zone Data
  'SVCB': 64, // general-purpose service binding
  'HTTPS': 65, // sVCB-compatible type for use with HTTP
  'DSYNC': 66, // endpoint discovery for delegation synchronization
  'HHIT': 67, // hierarchical Host Identity Tag
  'BRID': 68, // uAS Broadcast Remote Identification
  'SPF': 99,
  'UINFO': 100,
  'UID': 101,
  'GID': 102,
  'UNSPEC': 103,
  'NID': 104,
  'L32': 105,
  'L64': 106,
  'LP': 107,
  'EUI48': 108, // an EUI-48 address
  'EUI64': 109, // an EUI-64 address
  'NXNAME': 128, // nXDOMAIN indicator for Compact Denial of Existence
  'TKEY': 249, // transaction Key
  'TSIG': 250, // transaction Signature
  'IXFR': 251, // incremental transfer
  'AXFR': 252, // transfer of an entire zone
  'MAILB': 253, // mailbox-related RRs (MB: MG or MR)
  'MAILA': 254, // mail agent RRs (OBSOLETE - see MX)
  'ANY': 255, // a request for some or all records the server has available
  'URI': 256, // uRI
  'CAA': 257, // certification Authority Restriction
  'AVC': 258, // application Visibility and Control
  'DOA': 259, // digital Object Architecture
  'AMTRELAY': 260, // automatic Multicast Tunneling Relay
  'RESINFO': 261, // resolver Information as Key/Value Pairs
  'WALLET': 262, // public wallet address
  'CLA': 263, // bP Convergence Layer Adapter
  'IPN': 264, // bP Node Number
  'TA': 32768, // dNSSEC Trust Authorities
  'DLV': 32769, // dNSSEC Lookaside Validation (OBSOLETE)
} as const;

export type RecordTypeName = keyof typeof RECORD_TYPES;

const CODES = new Map<string, number>(Object.entries(RECORD_TYPES));
const NAMES = new Map<number, string>(
  Object.entries(RECORD_TYPES).map(([name, code]) => [code, name])
);

// the mnemonic for a type code, or the RFC 3597 form (`TYPE65280`) for one with no name
export function typeName(code: number): string {
  return NAMES.get(code) ?? `TYPE${code}`;
}

// the code for a type given as a mnemonic (any case), an RFC 3597 `TYPEnnn`, or a number
export function typeCode(type: string | number): number {
  if (typeof type === 'number') {
    if (!Number.isInteger(type) || type < 0 || type > 0xffff) {
      throw new InvalidQueryError(`Record type out of range: ${type}`);
    }
    return type;
  }
  const upper = type.trim().toUpperCase();
  if (upper === '*') return RECORD_TYPES.ANY;
  const known = CODES.get(upper);
  if (known !== undefined) return known;
  const generic = /^TYPE(\d{1,5})$/.exec(upper);
  if (generic && Number(generic[1]) <= 0xffff) return Number(generic[1]);
  throw new InvalidQueryError(`Unknown record type: ${type}`);
}
