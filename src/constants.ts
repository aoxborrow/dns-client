// the default public DNS server to use if not provided
export const DEFAULT_PUBLIC_DNS_SERVER = '1.1.1.1';
export const DEFAULT_PUBLIC_DOH_SERVER = 'https://cloudflare-dns.com/dns-query';

// DNS transport types
export const DNS_TRANSPORT_UDP = 'udp'; // UDP transport (dns-packet)
export const DNS_TRANSPORT_TCP = 'tcp'; // TCP transport (dns-packet)
export const DNS_TRANSPORT_DOH = 'doh'; // DNS-over-HTTPS transport (https wire-format)
export const DNS_TRANSPORT_TYPES = [
  DNS_TRANSPORT_UDP,
  DNS_TRANSPORT_TCP,
  DNS_TRANSPORT_DOH,
] as const;

// common record types, can add more as needed
export const A_RECORD = 'A';
export const AAAA_RECORD = 'AAAA';
export const ANY_RECORD = 'ANY'; // not technically a record type
export const CAA_RECORD = 'CAA';
export const CDNSKEY_RECORD = 'CDNSKEY';
export const CDS_RECORD = 'CDS';
export const CERT_RECORD = 'CERT';
export const CNAME_RECORD = 'CNAME';
export const DNAME_RECORD = 'DNAME';
export const DNSKEY_RECORD = 'DNSKEY';
export const DS_RECORD = 'DS';
export const HINFO_RECORD = 'HINFO';
export const HTTPS_RECORD = 'HTTPS';
export const KEY_RECORD = 'KEY'; // deprecated, use DNSKEY
export const LOC_RECORD = 'LOC';
export const MX_RECORD = 'MX';
export const NAPTR_RECORD = 'NAPTR';
export const NS_RECORD = 'NS';
export const NSEC_RECORD = 'NSEC';
export const NSEC3_RECORD = 'NSEC3';
export const NSEC3PARAM_RECORD = 'NSEC3PARAM';
export const OPENPGPKEY_RECORD = 'OPENPGPKEY';
export const OPT_RECORD = 'OPT';
export const PTR_RECORD = 'PTR';
export const RP_RECORD = 'RP';
export const RRSIG_RECORD = 'RRSIG';
export const SIG_RECORD = 'SIG'; // deprecated, use RRSIG
export const SOA_RECORD = 'SOA';
export const SRV_RECORD = 'SRV';
export const SSHFP_RECORD = 'SSHFP';
export const SVCB_RECORD = 'SVCB';
export const TLSA_RECORD = 'TLSA';
export const TSIG_RECORD = 'TSIG';
export const TXT_RECORD = 'TXT';
export const URI_RECORD = 'URI';

// list of supported record types
// complete list of all known record types from IANA is in DNS_RECORD_CODES_IANA
// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
export const DNS_RECORD_TYPES = [
  SOA_RECORD,
  NS_RECORD,
  A_RECORD,
  AAAA_RECORD,
  CNAME_RECORD,
  DNAME_RECORD,
  MX_RECORD,
  TXT_RECORD,
  CAA_RECORD,
  TLSA_RECORD,
  DS_RECORD,
  DNSKEY_RECORD,
  RRSIG_RECORD,
  NSEC_RECORD,
  NSEC3_RECORD,
  NSEC3PARAM_RECORD,
  CDS_RECORD,
  CDNSKEY_RECORD,
  KEY_RECORD,
  SIG_RECORD,
  SRV_RECORD,
  HTTPS_RECORD,
  SVCB_RECORD,
  CERT_RECORD,
  HINFO_RECORD,
  TSIG_RECORD,
  OPENPGPKEY_RECORD,
  RP_RECORD,
  SSHFP_RECORD,
  URI_RECORD,
  NAPTR_RECORD,
  LOC_RECORD,
  PTR_RECORD,
] as const;

// DNS record classes
// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-2
export const DNS_RECORD_CLASSES = {
  IN: 1, // Internet
  CS: 2, // CSNET (obsolete)
  CH: 3, // CHAOS
  HS: 4, // Hesiod
  ANY: 255, // ANY (query class)
} as const;

// dns packet header flags
// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-12
// response flags:
export const FLAG_AUTHORITATIVE_ANSWER = 'AA'; // Authoritative Answer: server is authoritative for this domain
export const FLAG_AUTHENTIC_DATA = 'AD'; // Authentic Data: response data was authenticated via dnssec
export const FLAG_TRUNCATED_RESPONSE = 'TC'; // Truncated Response: response was truncated due to size limits
export const FLAG_RECURSION_AVAILABLE = 'RA'; // Recursion Available: server supports recursive queries
// query flags:
export const FLAG_RECURSION_DESIRED = 'RD'; // Recursion Desired: client requested recursive resolution
export const FLAG_CHECKING_DISABLED = 'CD'; // Checking Disabled: client requested to receive results even if dnssec validation fails
export const FLAG_DNSSEC_OK = 'DO'; // DNSSEC OK: return DNSSEC records (EDNS header in OPT)

// all dns header flags
export const DNS_FLAGS = {
  [FLAG_AUTHORITATIVE_ANSWER]: 1 << 10, // 1024
  [FLAG_TRUNCATED_RESPONSE]: 1 << 9, // 512
  [FLAG_RECURSION_DESIRED]: 1 << 8, // 256
  [FLAG_RECURSION_AVAILABLE]: 1 << 7, // 128
  [FLAG_AUTHENTIC_DATA]: 1 << 5, // 32
  [FLAG_CHECKING_DISABLED]: 1 << 4, // 16
  [FLAG_DNSSEC_OK]: 1 << 15, //  32768
} as const;

// query flags, sent to server
export const DNS_QUERY_FLAGS = [
  FLAG_RECURSION_DESIRED,
  FLAG_CHECKING_DISABLED,
  FLAG_DNSSEC_OK,
] as const;

// DNS response/error codes
// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5
export const DNS_RESPONSE_CODES = {
  NOERROR: 0, // No Error	[RFC1035]
  FORMERR: 1, // Format Error	[RFC1035]
  SERVFAIL: 2, // Server Failure	[RFC1035]
  NXDOMAIN: 3, // Non-Existent Domain	[RFC1035]
  NOTIMP: 4, // Not Implemented	[RFC1035]
  REFUSED: 5, // Query Refused	[RFC1035]
  YXDOMAIN: 6, // Name Exists when it should not	[RFC2136][RFC6672]
  YXRRSET: 7, // RR Set Exists when it should not	[RFC2136]
  NXRRSET: 8, // RR Set that should exist does not	[RFC2136]
  NOTAUTH: 9, // Server Not Authoritative for zone	[RFC2136]
  NOTZONE: 10, // Name not contained in zone	[RFC2136]
  DSOTYPENI: 11, // DSO-TYPE Not Implemented	[RFC8490]
  BADVERS: 16, // Bad OPT Version	[RFC6891]
  BADSIG: 17, // TSIG Signature Failure	[RFC8945]
  BADKEY: 18, // Key not recognized	[RFC8945]
  BADTIME: 19, // Signature out of time window	[RFC8945]
  BADNAME: 20, // Duplicate key name	[RFC2930]
  BADALG: 21, // Algorithm not supported	[RFC2930]
  BADTRUNC: 22, // Bad Truncation	[RFC8945]
  BADCOOKIE: 23, // Bad/missing Server Cookie	[RFC7873]
} as const;

// EDNS Option Codes (IANA Registry)
// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11
export const EDNS_OPTIONS = {
  LLQ: 1, // Long-Lived Queries
  UL: 2, // Update Lease
  NSID: 3, // Name Server Identifier
  OWNER: 4, // Owner Option
  DAU: 5, // DNSSEC Algorithm Understood
  DHU: 6, // DS Hash Understood
  N3U: 7, // NSEC3 Hash Understood
  CLIENT_SUBNET: 8, // Client Subnet (ECS)
  EXPIRE: 9, // EDNS Expire
  COOKIE: 10, // DNS Cookies
  TCP_KEEPALIVE: 11, // TCP Keep-Alive
  PADDING: 12, // EDNS Padding
  CHAIN: 13, // EDNS Chain Query
  KEY_TAG: 14, // EDNS Key Tag
  EDE: 15, // Extended DNS Error
  CLIENT_TAG: 16, // Client Tag
  SERVER_TAG: 17, // Server Tag
  UMBRELLA_IDENT: 20208, // Cisco Umbrella Identity
  DEVICEID: 26946, // Cisco DeviceID
} as const;

// Extended DNS Errors, RFC 8914
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
  26: 'Too Early (QUIC; RFC 9250)',
  27: 'Unsupported NSEC3 Iterations Value',
} as const;

// ALL possible record types from IANA
// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
export const DNS_RECORD_CODES_IANA = {
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
  'PX': 26, // X.400 mail mapping information
  'GPOS': 27, // Geographical Position
  'AAAA': 28, // IP6 Address
  'LOC': 29, // Location Information
  'NXT': 30, // Next Domain (OBSOLETE)
  'EID': 31, // Endpoint Identifier
  'NIMLOC': 32, // Nimrod Locator
  'SRV': 33, // Server Selection
  'ATMA': 34, // ATM Address
  'NAPTR': 35, // Naming Authority Pointer
  'KX': 36, // Key Exchanger
  'CERT': 37, // CERT
  'A6': 38, // A6 (OBSOLETE - use AAAA)
  'DNAME': 39, // DNAME
  'SINK': 40, // SINK
  'OPT': 41, // OPT
  'APL': 42, // APL
  'DS': 43, // Delegation Signer
  'SSHFP': 44, // SSH Key Fingerprint
  'IPSECKEY': 45, // IPSECKEY
  'RRSIG': 46, // RRSIG
  'NSEC': 47, // NSEC
  'DNSKEY': 48, // DNSKEY
  'DHCID': 49, // DHCID
  'NSEC3': 50, // NSEC3
  'NSEC3PARAM': 51, // NSEC3PARAM
  'TLSA': 52, // TLSA
  'SMIMEA': 53, // S/MIME cert association
  'HIP': 55, // Host Identity Protocol
  'NINFO': 56, // NINFO
  'RKEY': 57, // RKEY
  'TALINK': 58, // Trust Anchor LINK
  'CDS': 59, // Child DS
  'CDNSKEY': 60, // DNSKEY(s) the Child wants reflected in DS
  'OPENPGPKEY': 61, // OpenPGP Key
  'CSYNC': 62, // Child-To-Parent Synchronization
  'ZONEMD': 63, // Message Digest Over Zone Data
  'SVCB': 64, // General-purpose service binding
  'HTTPS': 65, // SVCB-compatible type for use with HTTP
  'DSYNC': 66, // Endpoint discovery for delegation synchronization
  'HHIT': 67, // Hierarchical Host Identity Tag
  'BRID': 68, // UAS Broadcast Remote Identification
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
  'NXNAME': 128, // NXDOMAIN indicator for Compact Denial of Existence
  'TKEY': 249, // Transaction Key
  'TSIG': 250, // Transaction Signature
  'IXFR': 251, // incremental transfer
  'AXFR': 252, // transfer of an entire zone
  'MAILB': 253, // mailbox-related RRs (MB: MG or MR)
  'MAILA': 254, // mail agent RRs (OBSOLETE - see MX)
  'URI': 256, // URI
  'CAA': 257, // Certification Authority Restriction
  'AVC': 258, // Application Visibility and Control
  'DOA': 259, // Digital Object Architecture
  'AMTRELAY': 260, // Automatic Multicast Tunneling Relay
  'RESINFO': 261, // Resolver Information as Key/Value Pairs
  'WALLET': 262, // Public wallet address
  'CLA': 263, // BP Convergence Layer Adapter
  'IPN': 264, // BP Node Number
  'TA': 32768, // DNSSEC Trust Authorities
  'DLV': 32769, // DNSSEC Lookaside Validation (OBSOLETE)
  '*': 255, // A request for some or all records the server has available
  'ANY': 255, // A request for some or all records the server has available
} as const;

// known text-based record types that should use UTF-8 text representation (not binary/hex)
export const DNS_TEXT_RECORD_TYPES = [
  'TXT',
  'SPF',
  'HINFO',
  'MINFO',
  'RP',
  'ISDN',
  'X25',
  'RT',
  'GPOS',
  'EID',
  'NIMLOC',
  'NINFO',
  'UINFO',
  'AXFR',
  'IXFR',
  'KX',
  'PX',
  'TKEY',
  'TA',
  'DLV',
] as const;
