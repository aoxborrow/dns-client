// typed DNS records. Every record has the same envelope and a `type` that says which
// fields follow. Field names are camelCase and follow the RFC that defines the type.
//
// encodings: names have no trailing dot ('.' is the root); hex is lowercase; base64 is
// standard with padding; base32hex is uppercase with no padding. Times inside a record
// (RRSIG, SIG, TSIG) are left as the numbers on the wire: seconds since 1970.

interface RecordBase {
  // owner name, in the case the server sent it
  name: string;
  // class mnemonic, almost always 'IN'
  class: string;
  ttl: number;
}

/** an A record: an IPv4 address (RFC 1035) */
export interface ARecord extends RecordBase {
  type: 'A';
  address: string;
}

/** an AAAA record: an IPv6 address (RFC 3596) */
export interface AaaaRecord extends RecordBase {
  type: 'AAAA';
  /** RFC 5952 text form */
  address: string;
}

/** an NS record: a nameserver for the zone (RFC 1035) */
export interface NsRecord extends RecordBase {
  type: 'NS';
  target: string;
}

/** a CNAME record: the name is an alias for `target` (RFC 1035) */
export interface CnameRecord extends RecordBase {
  type: 'CNAME';
  target: string;
}

/** a PTR record: a name the owner points to, as in reverse lookups (RFC 1035) */
export interface PtrRecord extends RecordBase {
  type: 'PTR';
  target: string;
}

/**
 * a DNAME record: every name below the owner is an alias for the same name below `target` (RFC
 * 6672)
 */
export interface DnameRecord extends RecordBase {
  type: 'DNAME';
  target: string;
}

/** an SOA record: the zone's primary nameserver, contact, serial and timers (RFC 1035) */
export interface SoaRecord extends RecordBase {
  type: 'SOA';
  /** primary nameserver for the zone */
  mname: string;
  /** the responsible person's mailbox, written as a name */
  rname: string;
  serial: number;
  refresh: number;
  retry: number;
  expire: number;
  /** how long a negative answer may be cached */
  minimum: number;
}

/** an MX record: a mail exchanger and its preference (RFC 1035) */
export interface MxRecord extends RecordBase {
  type: 'MX';
  preference: number;
  /** '.' for a null MX: the domain accepts no mail */
  exchange: string;
}

/** a TXT record: one or more character-strings (RFC 1035) */
export interface TxtRecord extends RecordBase {
  type: 'TXT';
  /**
   * the character-strings in the record, in order, each at most 255 bytes. A backslash is
   * written `\\` and a byte that is not UTF-8 `\DDD`, as in a zone file
   */
  strings: string[];
}

/** a CAA record: which certificate authorities may issue for the name (RFC 8659) */
export interface CaaRecord extends RecordBase {
  type: 'CAA';
  /** bit 7 (128) is "issuer critical" */
  flags: number;
  tag: string;
  value: string;
}

/** a TLSA record: a TLS certificate association for DANE (RFC 6698) */
export interface TlsaRecord extends RecordBase {
  type: 'TLSA';
  usage: number;
  selector: number;
  matchingType: number;
  /** hex */
  certificate: string;
}

interface DelegationSigner {
  keyTag: number;
  algorithm: number;
  digestType: number;
  // hex
  digest: string;
}

/** a DS record: the digest of a child zone's key, held by the parent (RFC 4034) */
export interface DsRecord extends RecordBase, DelegationSigner {
  type: 'DS';
}

/** a CDS record: the DS the child zone asks its parent to publish (RFC 7344) */
export interface CdsRecord extends RecordBase, DelegationSigner {
  type: 'CDS';
}

interface PublicKey {
  flags: number;
  protocol: number;
  algorithm: number;
  // base64
  publicKey: string;
}

/** a DNSKEY record: a zone's public key (RFC 4034) */
export interface DnskeyRecord extends RecordBase, PublicKey {
  type: 'DNSKEY';
}

/** a CDNSKEY record: the key the child zone asks its parent to publish a DS for (RFC 7344) */
export interface CdnskeyRecord extends RecordBase, PublicKey {
  type: 'CDNSKEY';
}

/** a KEY record: a public key, as SIG(0) and TKEY use (RFC 2535) */
export interface KeyRecord extends RecordBase, PublicKey {
  type: 'KEY';
}

interface Signature {
  // mnemonic of the type the signature covers
  typeCovered: string;
  algorithm: number;
  labels: number;
  originalTtl: number;
  // seconds since 1970
  signatureExpiration: number;
  // seconds since 1970
  signatureInception: number;
  keyTag: number;
  signerName: string;
  // base64
  signature: string;
}

/** an RRSIG record: a signature over an RRset (RFC 4034) */
export interface RrsigRecord extends RecordBase, Signature {
  type: 'RRSIG';
}

/** a SIG record: a signature, as SIG(0) uses (RFC 2931) */
export interface SigRecord extends RecordBase, Signature {
  type: 'SIG';
}

/**
 * an NSEC record: the next name in the zone and the types at this one, for denial of existence (RFC
 * 4034)
 */
export interface NsecRecord extends RecordBase {
  type: 'NSEC';
  nextDomain: string;
  /** mnemonics of the types present at this name */
  types: string[];
}

/** an NSEC3 record: hashed denial of existence (RFC 5155) */
export interface Nsec3Record extends RecordBase {
  type: 'NSEC3';
  algorithm: number;
  /** bit 0 (1) is opt-out */
  flags: number;
  iterations: number;
  /** hex, or '' for no salt */
  salt: string;
  /** the next hashed owner name, base32hex */
  nextDomain: string;
  types: string[];
}

/** an NSEC3PARAM record: the zone's NSEC3 parameters (RFC 5155) */
export interface Nsec3paramRecord extends RecordBase {
  type: 'NSEC3PARAM';
  algorithm: number;
  flags: number;
  iterations: number;
  /** hex, or '' for no salt */
  salt: string;
}

/** an SRV record: where a service runs (RFC 2782) */
export interface SrvRecord extends RecordBase {
  type: 'SRV';
  priority: number;
  weight: number;
  port: number;
  target: string;
}

/**
 * the parameters of an SVCB or HTTPS record (RFC 9460). A key the library does not know
 * is kept under `other`, by its number, as hex
 */
export interface ServiceParams {
  mandatory?: string[];
  alpn?: string[];
  noDefaultAlpn?: true;
  port?: number;
  ipv4Hint?: string[];
  /** base64 */
  ech?: string;
  ipv6Hint?: string[];
  dohPath?: string;
  ohttp?: true;
  other?: Record<number, string>;
}

interface ServiceBinding {
  // 0 is alias mode: the record points at another name and carries no parameters
  priority: number;
  // '.' means the owner name itself
  target: string;
  params: ServiceParams;
}

/** an SVCB record: a service binding (RFC 9460) */
export interface SvcbRecord extends RecordBase, ServiceBinding {
  type: 'SVCB';
}

/** an HTTPS record: a service binding for HTTPS (RFC 9460) */
export interface HttpsRecord extends RecordBase, ServiceBinding {
  type: 'HTTPS';
}

/** a CERT record: a certificate or a revocation list (RFC 4398) */
export interface CertRecord extends RecordBase {
  type: 'CERT';
  certificateType: number;
  keyTag: number;
  algorithm: number;
  /** base64 */
  certificate: string;
}

/** an HINFO record: CPU and operating system (RFC 1035), and what RFC 8482 answers ANY with */
export interface HinfoRecord extends RecordBase {
  type: 'HINFO';
  cpu: string;
  os: string;
}

/** a TSIG record: a transaction signature (RFC 8945) */
export interface TsigRecord extends RecordBase {
  type: 'TSIG';
  /** the algorithm's name, e.g. 'hmac-sha256' */
  algorithm: string;
  /** seconds since 1970 */
  timeSigned: number;
  fudge: number;
  /** base64 */
  mac: string;
  originalId: number;
  error: number;
  /** base64, usually '' */
  otherData: string;
}

/** an OPENPGPKEY record: an OpenPGP public key (RFC 7929) */
export interface OpenpgpkeyRecord extends RecordBase {
  type: 'OPENPGPKEY';
  /** base64 */
  key: string;
}

/** an RP record: a responsible person (RFC 1183) */
export interface RpRecord extends RecordBase {
  type: 'RP';
  mbox: string;
  txt: string;
}

/** an SSHFP record: an SSH host key fingerprint (RFC 4255) */
export interface SshfpRecord extends RecordBase {
  type: 'SSHFP';
  algorithm: number;
  fingerprintType: number;
  /** hex */
  fingerprint: string;
}

/** a URI record: a URI for a service (RFC 7553) */
export interface UriRecord extends RecordBase {
  type: 'URI';
  priority: number;
  weight: number;
  target: string;
}

/** a NAPTR record: a rewrite rule (RFC 3403) */
export interface NaptrRecord extends RecordBase {
  type: 'NAPTR';
  order: number;
  preference: number;
  flags: string;
  services: string;
  regexp: string;
  replacement: string;
}

/** a LOC record: a geographical location (RFC 1876) */
export interface LocRecord extends RecordBase {
  type: 'LOC';
  version: number;
  /** diameter of the sphere enclosing the location, in metres */
  size: number;
  /** in metres */
  horizontalPrecision: number;
  /** in metres */
  verticalPrecision: number;
  /** degrees, positive north */
  latitude: number;
  /** degrees, positive east */
  longitude: number;
  /** metres above the WGS 84 spheroid */
  altitude: number;
}

/**
 * a record of a type the library has no fields for, or whose data it could not read
 * (which is an error instead when decoding is `strict`). The type is in the RFC 3597 form, so it never collides with a known one
 */
export interface UnknownRecord extends RecordBase {
  type: `TYPE${number}`;
  /** the record's data, hex */
  data: string;
}

/** any record the library decodes: one of the typed records, or an `UnknownRecord` */
export type DnsRecord =
  | ARecord
  | AaaaRecord
  | NsRecord
  | CnameRecord
  | PtrRecord
  | DnameRecord
  | SoaRecord
  | MxRecord
  | TxtRecord
  | CaaRecord
  | TlsaRecord
  | DsRecord
  | CdsRecord
  | DnskeyRecord
  | CdnskeyRecord
  | KeyRecord
  | RrsigRecord
  | SigRecord
  | NsecRecord
  | Nsec3Record
  | Nsec3paramRecord
  | SrvRecord
  | SvcbRecord
  | HttpsRecord
  | CertRecord
  | HinfoRecord
  | TsigRecord
  | OpenpgpkeyRecord
  | RpRecord
  | SshfpRecord
  | UriRecord
  | NaptrRecord
  | LocRecord
  | UnknownRecord;

/** the mnemonics of the types the library decodes into their own fields */
export type KnownRecordType = Exclude<DnsRecord, UnknownRecord>['type'];

/** the record interface for a type mnemonic: RecordOf<'MX'> is MxRecord */
export type RecordOf<T extends KnownRecordType> = Extract<DnsRecord, { type: T }>;
