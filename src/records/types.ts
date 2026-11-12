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

export interface ARecord extends RecordBase {
  type: 'A';
  address: string;
}

export interface AaaaRecord extends RecordBase {
  type: 'AAAA';
  // RFC 5952 text form
  address: string;
}

export interface NsRecord extends RecordBase {
  type: 'NS';
  target: string;
}

export interface CnameRecord extends RecordBase {
  type: 'CNAME';
  target: string;
}

export interface PtrRecord extends RecordBase {
  type: 'PTR';
  target: string;
}

export interface DnameRecord extends RecordBase {
  type: 'DNAME';
  target: string;
}

export interface SoaRecord extends RecordBase {
  type: 'SOA';
  // primary nameserver for the zone
  mname: string;
  // the responsible person's mailbox, written as a name
  rname: string;
  serial: number;
  refresh: number;
  retry: number;
  expire: number;
  // how long a negative answer may be cached
  minimum: number;
}

export interface MxRecord extends RecordBase {
  type: 'MX';
  preference: number;
  // '.' for a null MX: the domain accepts no mail
  exchange: string;
}

export interface TxtRecord extends RecordBase {
  type: 'TXT';
  // the character-strings in the record, in order, each at most 255 bytes
  strings: string[];
}

export interface CaaRecord extends RecordBase {
  type: 'CAA';
  // bit 7 (128) is "issuer critical"
  flags: number;
  tag: string;
  value: string;
}

export interface TlsaRecord extends RecordBase {
  type: 'TLSA';
  usage: number;
  selector: number;
  matchingType: number;
  // hex
  certificate: string;
}

interface DelegationSigner {
  keyTag: number;
  algorithm: number;
  digestType: number;
  // hex
  digest: string;
}

export interface DsRecord extends RecordBase, DelegationSigner {
  type: 'DS';
}

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

export interface DnskeyRecord extends RecordBase, PublicKey {
  type: 'DNSKEY';
}

export interface CdnskeyRecord extends RecordBase, PublicKey {
  type: 'CDNSKEY';
}

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

export interface RrsigRecord extends RecordBase, Signature {
  type: 'RRSIG';
}

export interface SigRecord extends RecordBase, Signature {
  type: 'SIG';
}

export interface NsecRecord extends RecordBase {
  type: 'NSEC';
  nextDomain: string;
  // mnemonics of the types present at this name
  types: string[];
}

export interface Nsec3Record extends RecordBase {
  type: 'NSEC3';
  algorithm: number;
  // bit 0 (1) is opt-out
  flags: number;
  iterations: number;
  // hex, or '' for no salt
  salt: string;
  // the next hashed owner name, base32hex
  nextDomain: string;
  types: string[];
}

export interface Nsec3paramRecord extends RecordBase {
  type: 'NSEC3PARAM';
  algorithm: number;
  flags: number;
  iterations: number;
  // hex, or '' for no salt
  salt: string;
}

export interface SrvRecord extends RecordBase {
  type: 'SRV';
  priority: number;
  weight: number;
  port: number;
  target: string;
}

// the parameters of an SVCB or HTTPS record (RFC 9460). A key the library does not know
// is kept under `other`, by its number, as hex
export interface ServiceParams {
  mandatory?: string[];
  alpn?: string[];
  noDefaultAlpn?: true;
  port?: number;
  ipv4Hint?: string[];
  // base64
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

export interface SvcbRecord extends RecordBase, ServiceBinding {
  type: 'SVCB';
}

export interface HttpsRecord extends RecordBase, ServiceBinding {
  type: 'HTTPS';
}

export interface CertRecord extends RecordBase {
  type: 'CERT';
  certificateType: number;
  keyTag: number;
  algorithm: number;
  // base64
  certificate: string;
}

export interface HinfoRecord extends RecordBase {
  type: 'HINFO';
  cpu: string;
  os: string;
}

export interface TsigRecord extends RecordBase {
  type: 'TSIG';
  // the algorithm's name, e.g. 'hmac-sha256'
  algorithm: string;
  // seconds since 1970
  timeSigned: number;
  fudge: number;
  // base64
  mac: string;
  originalId: number;
  error: number;
  // base64, usually ''
  otherData: string;
}

export interface OpenpgpkeyRecord extends RecordBase {
  type: 'OPENPGPKEY';
  // base64
  key: string;
}

export interface RpRecord extends RecordBase {
  type: 'RP';
  mbox: string;
  txt: string;
}

export interface SshfpRecord extends RecordBase {
  type: 'SSHFP';
  algorithm: number;
  fingerprintType: number;
  // hex
  fingerprint: string;
}

export interface UriRecord extends RecordBase {
  type: 'URI';
  priority: number;
  weight: number;
  target: string;
}

export interface NaptrRecord extends RecordBase {
  type: 'NAPTR';
  order: number;
  preference: number;
  flags: string;
  services: string;
  regexp: string;
  replacement: string;
}

export interface LocRecord extends RecordBase {
  type: 'LOC';
  version: number;
  // diameter of the sphere enclosing the location, in metres
  size: number;
  // in metres
  horizontalPrecision: number;
  // in metres
  verticalPrecision: number;
  // degrees, positive north
  latitude: number;
  // degrees, positive east
  longitude: number;
  // metres above the WGS 84 spheroid
  altitude: number;
}

// a record of a type the library has no fields for, or whose data it could not read in
// lenient mode. The type is in the RFC 3597 form, so it never collides with a known one
export interface UnknownRecord extends RecordBase {
  type: `TYPE${number}`;
  // the record's data, hex
  data: string;
}

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

// the mnemonics of the types the library decodes into their own fields
export type KnownRecordType = Exclude<DnsRecord, UnknownRecord>['type'];

// the record interface for a type mnemonic: RecordOf<'MX'> is MxRecord
export type RecordOf<T extends KnownRecordType> = Extract<DnsRecord, { type: T }>;
