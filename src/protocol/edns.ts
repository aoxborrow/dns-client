/** EDNS(0) option codes, from the IANA "DNS EDNS0 Option Codes (OPT)" registry */
export const EDNS_OPTIONS = {
  LLQ: 1, // long-lived queries
  UL: 2, // update lease
  NSID: 3, // name server identifier
  OWNER: 4,
  DAU: 5, // DNSSEC algorithms understood
  DHU: 6, // DS hashes understood
  N3U: 7, // NSEC3 hashes understood
  CLIENT_SUBNET: 8,
  EXPIRE: 9,
  COOKIE: 10,
  TCP_KEEPALIVE: 11,
  PADDING: 12,
  CHAIN: 13,
  KEY_TAG: 14,
  EDE: 15, // extended DNS error
  CLIENT_TAG: 16,
  SERVER_TAG: 17,
} as const;

/** extended DNS error codes (RFC 8914 and the IANA registry that followed it) */
export const EXTENDED_DNS_ERRORS = {
  0: 'Other Error',
  1: 'Unsupported DNSKEY Algorithm',
  2: 'Unsupported DS Digest Type',
  3: 'Stale Answer',
  4: 'Forged Answer',
  5: 'DNSSEC Indeterminate',
  6: 'DNSSEC Bogus',
  7: 'Signature Expired',
  8: 'Signature Not Yet Valid',
  9: 'DNSKEY Missing',
  10: 'RRSIGs Missing',
  11: 'No Zone Key Bit Set',
  12: 'NSEC Missing',
  13: 'Cached Error',
  14: 'Not Ready',
  15: 'Blocked',
  16: 'Censored',
  17: 'Filtered',
  18: 'Prohibited',
  19: 'Stale NXDomain Answer',
  20: 'Not Authoritative',
  21: 'Not Supported',
  22: 'No Reachable Authority',
  23: 'Network Error',
  24: 'Invalid Data',
  25: 'Signature Expired before Valid',
  26: 'Too Early',
  27: 'Unsupported NSEC3 Iterations Value',
} as const;

/**
 * the EDNS payload size to advertise: large enough for most signed answers over UDP, small
 * enough to stay under the common 1500-byte path MTU (DNS flag day 2020)
 */
export const DEFAULT_UDP_PAYLOAD_SIZE = 1232;
