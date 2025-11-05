import type { Question, Answer, DecodedPacket } from 'dns-packet';
import type { DnsError } from './errors.js';
import {
  A_RECORD,
  AAAA_RECORD,
  CNAME_RECORD,
  MX_RECORD,
  NAPTR_RECORD,
  NS_RECORD,
  PTR_RECORD,
  SOA_RECORD,
  SRV_RECORD,
  TXT_RECORD,
  CAA_RECORD,
  CERT_RECORD,
  DNSKEY_RECORD,
  DS_RECORD,
  KEY_RECORD,
  RRSIG_RECORD,
  SIG_RECORD,
  TLSA_RECORD,
  DNS_RESPONSE_CODES,
  DNS_FLAGS,
  EXTENDED_DNS_ERRORS,
  DNS_RECORD_CODES_IANA,
  DNS_RECORD_CLASSES,
  CDNSKEY_RECORD,
  CDS_RECORD,
  DNAME_RECORD,
  NSEC_RECORD,
  NSEC3_RECORD,
  NSEC3PARAM_RECORD,
  TSIG_RECORD,
  SSHFP_RECORD,
  URI_RECORD,
  LOC_RECORD,
  HINFO_RECORD,
  HTTPS_RECORD,
  RP_RECORD,
  SVCB_RECORD,
  OPENPGPKEY_RECORD,
  OPT_RECORD,
  EDNS_OPTIONS,
  DNS_TRANSPORT_TYPES,
  DNS_RECORD_TYPES,
  type DNS_QUERY_FLAGS,
} from './constants.js';

// configuration options for DNS queries
// external API uses Partial<DnsOptions>, internal uses full DnsOptions
export interface DnsOptions {
  server: string; // nameserver IP or hostname. starts from root if not provided
  transport: DnsTransportType; // 'udp' | 'tcp' | 'doh' (default: 'udp')
  authoritative: boolean; // perform recursive resolution from root servers (default: false)
  flags: DnsQueryFlag[]; // list of DNS query flags to send to the server (default: [RD] when not authoritative)

  // error handling
  tcpFallback: boolean; // retry over TCP if the UDP response has TC=1 (truncated) (default: true)
  timeout: number; // timeout in ms (default: 5000)
  retries: number; // retry attempts (default: 0)
  backoff: number; // base delay for exponential backoff in ms (default: 100)
  signal?: AbortSignal; // for cancellation/timeout

  // performance
  cache: boolean; // enable cache (default: true)
  cacheSize: number; // max cache entries (default: 1000)
  concurrency: number; // max concurrent queries (default: 10)
}

// case-insensitive versions of DNS types for better DX
export type RecordType = DnsRecordType | Lowercase<DnsRecordType>;
export type QueryFlag = DnsQueryFlag | Lowercase<DnsQueryFlag>;

// query parameters for query() and queryAll() methods that support multiple record types
export interface DnsQuery {
  query: string;
  types?: readonly RecordType[]; // case-insensitive: 'a' | 'A', 'aaaa' | 'AAAA', etc.
  server?: string;
  flags?: readonly QueryFlag[]; // case-insensitive: 'rd' | 'RD', 'do' | 'DO', etc.
}

// individual query object used by resolver
export type DnsQuestion = {
  query: string;
  type: DnsRecordType;
  server: string;
  flags: DnsQueryFlag[];
};

// all supported DNS transports
export type DnsTransportType = (typeof DNS_TRANSPORT_TYPES)[number];

// function interface for DNS transport operation
export interface DnsTransportQuery {
  (question: DnsQuestion, options: DnsOptions): Promise<DnsPacket>;
}

// a numeric code for a DNS record type
export type DnsRecordCode = (typeof DNS_RECORD_CODES_IANA)[keyof typeof DNS_RECORD_CODES_IANA];

// the numeric DNS response/error code, e.g. 0 for NOERROR, 2 for SERVFAIL, etc
export type DnsResponseCode = (typeof DNS_RESPONSE_CODES)[keyof typeof DNS_RESPONSE_CODES];

// the type of DNS response/error code, e.g. 'NOERROR', 'SERVFAIL', etc
export type DnsResponseType = keyof typeof DNS_RESPONSE_CODES;

// the DNS record class, e.g. 'IN' for Internet, 'CS' for CSNET, etc
export type DnsRecordClass = keyof typeof DNS_RECORD_CLASSES;

// a DNS record type
export type DnsRecordType = (typeof DNS_RECORD_TYPES)[number];

// a flattened DNS record object for presentational purposes, should work for creating zone files
// TODO: test compatibility with https://github.com/elgs/dns-zonefile
export interface FlatDnsRecord {
  name: string;
  type: DnsRecordType;
  ttl?: number;
  content: string;
}

// any DNS header flag
export type DnsFlag = keyof typeof DNS_FLAGS;

// query flags which are sent to the server
export type DnsQueryFlag = (typeof DNS_QUERY_FLAGS)[number];

// a single entry of a DNS resolution hop, with the details of the nameserver and query
export type DnsResolutionHop = {
  server: string;
  serverHost: string | null;
  timestamp: Date;
  elapsed: number | null;
  bytes: number | null;
  rcode: DnsResponseCode | null;
  rcodeName: DnsResponseType | null;
  flags: DnsFlag[];
};

// only a valid error code
export type DnsExtendedErrorCode = keyof typeof EXTENDED_DNS_ERRORS;

// error code => optional message for extended DNS error codes
export type DnsExtendedErrors = Partial<Record<DnsExtendedErrorCode, string>>;

// a DNS answer, with all the details of the query and response
export interface DnsAnswer {
  query: string; // the fqdn/qname that was queried
  type: DnsRecordType; // the record type that was queried (renamed from recordType)
  server: string; // required, the final server that answered the query
  serverHost: string | null; // the hostname of the server that answered the query
  elapsed: number | null; // query duration in ms
  bytes: number | null; // the number of bytes in the response
  rcode: DnsResponseCode | null; // e.g. 0 for NOERROR, 2 for SERVFAIL, etc
  rcodeName: DnsResponseType | null; // e.g. 'NOERROR', 'SERVFAIL', etc
  extendedErrors: DnsExtendedErrors | null; // extended DNS error codes
  ednsOptions: EdnsOption[] | null; // EDNS options
  // comments?: string[]; // optional message(s) returned by DoH servers
  error: DnsError | null; // populated when query fails and throwErrors=false
  flags: DnsFlag[]; // a list of DNS query flags from the response
  records: DnsRecord[];
  authorities: DnsRecord[];
  additionals: DnsRecord[];
  trace: DnsResolutionHop[]; // a list of DnsResolutionHop objects in order, showing delegation/referrals/etc
}

//--------------------------------
// dns-packet types
//--------------------------------

// just aliases for convenience
export type PacketQuestion = Question;
export type PacketAnswer = Answer;

// full type for dns-packet's DecodedPacket, plus some extra fields: rcode and bytes
// https://github.com/DefinitelyTyped/DefinitelyTyped/blob/master/types/dns-packet/index.d.ts
// https://github.com/mafintosh/dns-packet/blob/7b6662025c49c0e31d2f0c5cbd726e4423805639/index.js#L181-L197
export interface DnsPacket extends DecodedPacket {
  // whether the packet is a query or a response. This field may be
  // omitted if it is clear from the context of usage what type of packet
  // it is.
  type?: 'query' | 'response' | undefined;
  id?: number | undefined;
  // a bit-mask combination of zero or more of:
  // FLAG_AUTHORITATIVE_ANSWER, FLAG_TRUNCATED_RESPONSE, FLAG_RECURSION_DESIRED,
  // FLAG_RECURSION_AVAILABLE, FLAG_AUTHENTIC_DATA, FLAG_CHECKING_DISABLED
  flags?: number | undefined;

  // from DecodedPacket
  flag_qr: boolean;
  flag_aa: boolean;
  flag_tc: boolean;
  flag_rd: boolean;
  flag_ra: boolean;
  flag_z: boolean;
  flag_ad: boolean;
  flag_cd: boolean;

  // added by me, not in DecodedPacket
  rcode: DnsResponseType; // the DNS response code, e.g. 'NOERROR', 'SERVFAIL', etc
  bytes?: number; // the number of bytes in the response

  // meat of the packet
  questions?: PacketQuestion[] | undefined;
  answers?: PacketAnswer[] | undefined;
  additionals?: PacketAnswer[] | undefined;
  authorities?: PacketAnswer[] | undefined;
}

// OPT is not a real DNS record, but an EDNS0 pseudo-record for metadata
export interface OptRecord {
  type: typeof OPT_RECORD;
  name: string; // always '.' for OPT
  // EDNS0 fields from the OPT record header
  udp_payload_size: number;
  extended_rcode: number;
  edns_version: number;
  flags: number;
  flag_do: boolean; // DNSSEC OK bit
  // raw EDNS options - these get parsed separately by EDNS functions
  options: RawEdnsOption[];
}

//--------------------------------
// EDNS types
//--------------------------------

// EDNS option types
export type EdnsOptionType = keyof typeof EDNS_OPTIONS;
export type EdnsOptionCode = (typeof EDNS_OPTIONS)[keyof typeof EDNS_OPTIONS];
export type EdnsOptionCodeByType<T extends EdnsOptionType> = (typeof EDNS_OPTIONS)[T];

export interface EdnsBaseOption<T extends EdnsOptionType> {
  code: EdnsOptionCodeByType<T>;
  type?: T | undefined;
  _data?: Buffer | undefined;
}

// raw EDNS option structure from dns-packet
export type RawEdnsOption = {
  code: number;
  data: Buffer;
};

export interface EdnsNsid extends EdnsBaseOption<'NSID'> {
  nsid: string;
}

export interface EdnsClientSubnet extends EdnsBaseOption<'CLIENT_SUBNET'> {
  family?: number | undefined;
  sourcePrefixLength?: number | undefined;
  scopePrefixLength?: number | undefined;
  ip: string | undefined;
}

export interface EdnsCookie extends EdnsBaseOption<'COOKIE'> {
  clientCookie: string;
  serverCookie: string | null;
  valid: boolean;
}

export interface EdnsTcpKeepAlive extends EdnsBaseOption<'TCP_KEEPALIVE'> {
  timeout?: number;
  unit?: string;
}

export interface EdnsPadding extends EdnsBaseOption<'PADDING'> {
  paddingLength: number;
  purpose: string;
}

export interface EdnsDnssecCapability extends EdnsBaseOption<'DAU' | 'DHU' | 'N3U'> {
  algorithms: number[];
  algorithmType: string;
}

export interface EdnsKeyTag extends EdnsBaseOption<'KEY_TAG'> {
  tags: number[];
}

// union type for all EDNS option types
export type EdnsOption =
  | EdnsNsid
  | EdnsClientSubnet
  | EdnsCookie
  | EdnsTcpKeepAlive
  | EdnsPadding
  | EdnsDnssecCapability
  | EdnsKeyTag;

//--------------------------------
// DnsRecord types
//--------------------------------

// common base interface for all DNS records
interface BaseDnsRecord {
  name: string;
  ttl: number;
  type: DnsRecordType;
  class: DnsRecordClass; // DNS class, almost always 'IN' (Internet)
}

// specific record type interfaces
export interface ARecord extends BaseDnsRecord {
  type: typeof A_RECORD;
  address: string;
}

export interface AaaaRecord extends BaseDnsRecord {
  type: typeof AAAA_RECORD;
  address: string;
}

// CAA tag type for structured CAA records
export enum CaaTag {
  // explicitly authorizes a single certificate authority to issue a certificate (any type) for the hostname
  ISSUE = 'issue',

  // explicitly authorizes a single certificate authority to issue a wildcard certificate (and only wildcard) for the hostname
  ISSUEWILD = 'issuewild',

  // specifies a URL to which a certificate authority may report policy violations
  IODEF = 'iodef',

  // specifies an email address to which a certificate authority may report policy violations
  CONTACTEMAIL = 'contactemail',

  // specifies a phone number to which a certificate authority may report policy violations
  CONTACTPHONE = 'contactphone',
}

export interface CaaRecord extends BaseDnsRecord {
  type: typeof CAA_RECORD;
  flags: number;
  tag: CaaTag | string; // Allow unknown tags as strings
  value: string;
}

export interface CertRecord extends BaseDnsRecord {
  type: typeof CERT_RECORD;
  algorithm: number;
  certificate: string;
  certificate_type: string;
  key_tag: number;
}

export interface CnameRecord extends BaseDnsRecord {
  type: typeof CNAME_RECORD;
  value: string;
}

export interface DnskeyRecord extends BaseDnsRecord {
  type: typeof DNSKEY_RECORD;
  flags: number;
  protocol: number;
  algorithm: number;
  public_key: string;
}

export interface DsRecord extends BaseDnsRecord {
  type: typeof DS_RECORD;
  key_tag: number;
  algorithm: number;
  digest_type: number;
  digest: string;
}

export interface KeyRecord extends BaseDnsRecord {
  type: typeof KEY_RECORD;
  flags: number;
  protocol: number;
  algorithm: number;
  public_key: string;
}

export interface MxRecord extends BaseDnsRecord {
  type: typeof MX_RECORD;
  exchange: string;
  priority: number;
}

export interface NaptrRecord extends BaseDnsRecord {
  type: typeof NAPTR_RECORD;
  flags: string;
  service: string;
  regexp: string;
  replacement: string;
  order: number;
  preference: number;
}

export interface NsRecord extends BaseDnsRecord {
  type: typeof NS_RECORD;
  value: string;
}

export interface PtrRecord extends BaseDnsRecord {
  type: typeof PTR_RECORD;
  value: string;
}

export interface RpRecord extends BaseDnsRecord {
  type: typeof RP_RECORD;
  mbox: string;
  txt: string;
}

export interface RrsigRecord extends BaseDnsRecord {
  type: typeof RRSIG_RECORD;
  type_covered: string;
  algorithm: number;
  labels: number;
  original_ttl: number;
  signature_expiration: number;
  signature_inception: number;
  key_tag: number;
  signer_name: string;
  signature: string;
}

export interface SigRecord extends BaseDnsRecord {
  type: typeof SIG_RECORD;
  type_covered: string;
  algorithm: number;
  labels: number;
  original_ttl: number;
  signature_expiration: number;
  signature_inception: number;
  key_tag: number;
  signer_name: string;
  signature: string;
}

export interface SoaRecord extends BaseDnsRecord {
  type: typeof SOA_RECORD;
  nsname: string;
  hostmaster: string;
  serial: number;
  refresh: number;
  retry: number;
  expire: number;
  minimum: number;
}

export interface SrvRecord extends BaseDnsRecord {
  type: typeof SRV_RECORD;
  priority: number;
  weight: number;
  port: number;
  target: string;
}

export interface TlsaRecord extends BaseDnsRecord {
  type: typeof TLSA_RECORD;
  cert: string;
  mtype: number;
  selector: number;
  usage: number;
}

export interface TxtRecord extends BaseDnsRecord {
  type: typeof TXT_RECORD;
  value: string;
}

export interface CdnskeyRecord extends BaseDnsRecord {
  type: typeof CDNSKEY_RECORD;
  flags: number;
  protocol: number;
  algorithm: number;
  public_key: string;
}

export interface CdsRecord extends BaseDnsRecord {
  type: typeof CDS_RECORD;
  key_tag: number;
  algorithm: number;
  digest_type: number;
  digest: string;
}

export interface DnameRecord extends BaseDnsRecord {
  type: typeof DNAME_RECORD;
  value: string;
}

export interface NsecRecord extends BaseDnsRecord {
  type: typeof NSEC_RECORD;
  next_domain: string;
  rr_types: string[];
}

export interface Nsec3Record extends BaseDnsRecord {
  type: typeof NSEC3_RECORD;
  algorithm: number;
  flags: number;
  iterations: number;
  salt: string;
  next_domain: string;
  rr_types: string[];
}

export interface Nsec3paramRecord extends BaseDnsRecord {
  type: typeof NSEC3PARAM_RECORD;
  algorithm: number;
  flags: number;
  iterations: number;
  salt: string;
}

export interface TsigRecord extends BaseDnsRecord {
  type: typeof TSIG_RECORD;
  algorithm: string;
  time_signed: number;
  fudge: number;
  mac_size: number;
  mac: string;
  original_id: number;
  error: number;
  other_len: number;
  other_data: string;
}

export interface SshfpRecord extends BaseDnsRecord {
  type: typeof SSHFP_RECORD;
  algorithm: number;
  fp_type: number;
  fingerprint: string;
}

export interface UriRecord extends BaseDnsRecord {
  type: typeof URI_RECORD;
  priority: number;
  weight: number;
  target: string;
}

export interface LocRecord extends BaseDnsRecord {
  type: typeof LOC_RECORD;
  version: number;
  size: string;
  horiz_pre: string;
  vert_pre: string;
  latitude: number;
  longitude: number;
  altitude: number;
}

export interface HinfoRecord extends BaseDnsRecord {
  type: typeof HINFO_RECORD;
  cpu: string;
  os: string;
}

export interface HttpsRecord extends BaseDnsRecord {
  type: typeof HTTPS_RECORD;
  svc_priority: number;
  target_name: string;
  svc_params: Record<string, unknown>;
}

export interface SvcbRecord extends BaseDnsRecord {
  type: typeof SVCB_RECORD;
  svc_priority: number;
  target_name: string;
  svc_params: Record<string, unknown>;
}

export interface OpenpgpkeyRecord extends BaseDnsRecord {
  type: typeof OPENPGPKEY_RECORD;
  key: string;
}

// union type for all possible DNS records
export type DnsRecord =
  | AaaaRecord
  | ARecord
  | CaaRecord
  | CdnskeyRecord
  | CdsRecord
  | CertRecord
  | CnameRecord
  | DnameRecord
  | DnskeyRecord
  | DsRecord
  | HinfoRecord
  | HttpsRecord
  | KeyRecord
  | LocRecord
  | MxRecord
  | NaptrRecord
  | NsRecord
  | NsecRecord
  | Nsec3Record
  | Nsec3paramRecord
  | OpenpgpkeyRecord
  | PtrRecord
  | RpRecord
  | RrsigRecord
  | SigRecord
  | SoaRecord
  | SrvRecord
  | SshfpRecord
  | SvcbRecord
  | TlsaRecord
  | TsigRecord
  | TxtRecord
  | UriRecord;
