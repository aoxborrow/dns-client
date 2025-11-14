import dnsPacket from 'dns-packet';
import { Buffer } from 'buffer';
import {
  DNS_FLAGS,
  A_RECORD,
  AAAA_RECORD,
  CAA_RECORD,
  CERT_RECORD,
  CNAME_RECORD,
  DNAME_RECORD,
  DNSKEY_RECORD,
  DS_RECORD,
  KEY_RECORD,
  MX_RECORD,
  NAPTR_RECORD,
  NS_RECORD,
  PTR_RECORD,
  RRSIG_RECORD,
  SIG_RECORD,
  SOA_RECORD,
  SRV_RECORD,
  TLSA_RECORD,
  TXT_RECORD,
  CDNSKEY_RECORD,
  CDS_RECORD,
  NSEC_RECORD,
  NSEC3_RECORD,
  NSEC3PARAM_RECORD,
  TSIG_RECORD,
  URI_RECORD,
  LOC_RECORD,
  HINFO_RECORD,
  EDNS_OPTIONS,
  OPT_RECORD,
  RP_RECORD,
  SSHFP_RECORD,
  DNS_TEXT_RECORD_TYPES,
  FLAG_DNSSEC_OK,
} from './constants.js';
import { ParsingError } from './errors.js';
import type {
  DnsRecordType,
  DnsRecordClass,
  ARecord,
  AaaaRecord,
  CnameRecord,
  NsRecord,
  PtrRecord,
  TxtRecord,
  CaaRecord,
  DnskeyRecord,
  DsRecord,
  MxRecord,
  NaptrRecord,
  RrsigRecord,
  SoaRecord,
  SrvRecord,
  TlsaRecord,
  DnameRecord,
  Nsec3Record,
  NsecRecord,
  HinfoRecord,
  PacketAnswer,
  PacketQuestion,
  DnsRecord,
  RpRecord,
  SshfpRecord,
  DnsQuestion,
  CdnskeyRecord,
  CdsRecord,
  CertRecord,
  KeyRecord,
  LocRecord,
  Nsec3paramRecord,
  SigRecord,
  TsigRecord,
  UriRecord,
  DnsQueryFlag,
} from './types.js';
import { toBase32Hex, sanitizeString } from './utils.js';

// pass the flag constants and get a bitmask for them
export function getQueryFlagsBitmask(flags: DnsQueryFlag[]) {
  return flags.reduce((mask, flag) => {
    // ignore DNSSEC_OK flag, it's an EDNS flag
    if (flag === FLAG_DNSSEC_OK) return mask;
    // otherwise, add the flag to the bitmask
    return mask | DNS_FLAGS[flag];
  }, 0);
}

// create a DNS packet for the given query
export function createDnsPacket(question: DnsQuestion): Buffer {
  // check if DNSSEC_OK flag is set
  const dnssecOk = question.flags.includes(FLAG_DNSSEC_OK);

  // create bitmask for the query flags, excludes DNSSEC_OK flag (EDNS flag)
  const flagsBitmask = getQueryFlagsBitmask(question.flags);

  // encode the query packet, with EDNS flag set
  return dnsPacket.encode({
    type: 'query',
    id: 1,
    flags: flagsBitmask,
    questions: [{ type: question.type, name: question.query } as PacketQuestion],
    additionals: [
      {
        // all EDNS fields are required for wire format
        type: 'OPT',
        name: '.',
        udpPayloadSize: 4096, // larger buffer for DNSSEC responses
        extendedRcode: 0,
        ednsVersion: 0,
        // DNSSEC_OK flag: include DNSSEC records in response
        flags: dnssecOk ? DNS_FLAGS.DO : 0,
        flag_do: dnssecOk, // seems to work best setting both ways
        options: [
          {
            // @ts-expect-error - EDNS_OPTIONS is not typed correctly
            code: EDNS_OPTIONS.NSID, // NSID option code
            data: Buffer.alloc(0), // Empty data for NSID request
          },
          // {
          //   code: EDNS_OPTIONS.CLIENT_SUBNET, // Client Subnet option code
          //   family: 1, // IPv4
          //   sourcePrefixLength: 0,
          //   scopePrefixLength: 0,
          //   ip: '0.0.0.0',
          // },
          // NOTE: couldn't get confirmation of these working, need to try more servers
          // {
          //   // @ts-ignore
          //   code: EDNS_OPTIONS.COOKIE, // DNS Cookies option code
          //   data: Buffer.from([1, 2, 3, 4, 5, 6, 7, 8]), // Empty data for DNS Cookies request
          // },
          // {
          //   code: EDNS_OPTIONS.TCP_KEEPALIVE, // TCP Keep-Alive option code
          //   timeout: 500, // 500 centiseconds = 5 seconds
          // },
          // {
          //   code: EDNS_OPTIONS.PADDING, // Padding option code
          //   length: 1024,
          // },
          // {
          //   code: EDNS_OPTIONS.KEY_TAG, // DNSSEC Key Tag option code
          //   tags: [1234, 5678],
          // },
        ],
      },
    ],
  });
}

// format a single answer from dns-packet into our DnsRecord type
// convention is lowercase for hex fields, uppercase for base32hex fields, same-case for base64 fields
export function parsePacketAnswer(answer: PacketAnswer): DnsRecord | null {
  const baseData = {
    name: answer.name,
    ttl: 'ttl' in answer ? answer.ttl || 0 : 0,
    type: answer.type as DnsRecordType,
    class: ('class' in answer ? (answer.class as DnsRecordClass) : 'IN') || 'IN', // default to 'IN' (Internet)
  };

  try {
    switch (answer.type) {
      // **********
      // string record types from dns-packet
      // **********
      case A_RECORD:
      case AAAA_RECORD: {
        return { address: answer.data, ...baseData } as ARecord | AaaaRecord;
      }

      case CNAME_RECORD: {
        return { value: answer.data, ...baseData } as CnameRecord;
      }

      case DNAME_RECORD: {
        return {
          value: answer.data,
          ...baseData,
        } as DnameRecord;
      }

      case NS_RECORD: {
        return { value: answer.data, ...baseData } as NsRecord;
      }

      case PTR_RECORD: {
        return { value: answer.data, ...baseData } as PtrRecord;
      }

      // **********
      // structured record types from dns-packet
      // **********
      case CAA_RECORD: {
        return {
          ...baseData,
          flags: answer.data.flags || 0,
          tag: answer.data.tag,
          value: answer.data.value,
        } as CaaRecord;
      }

      case DNSKEY_RECORD: {
        return {
          ...baseData,
          flags: answer.data.flags,
          protocol: 3, // DNSKEY protocol is always 3
          algorithm: answer.data.algorithm,
          public_key: answer.data.key.toString('base64'),
        } as DnskeyRecord;
      }

      case DS_RECORD: {
        return {
          ...baseData,
          key_tag: answer.data.keyTag,
          algorithm: answer.data.algorithm,
          digest_type: answer.data.digestType,
          digest: answer.data.digest.toString('hex').toLowerCase(),
        } as DsRecord;
      }

      case HINFO_RECORD: {
        return {
          ...baseData,
          cpu: answer.data.cpu,
          os: answer.data.os,
        } as HinfoRecord;
      }

      case MX_RECORD: {
        return {
          ...baseData,
          priority: answer.data.preference || 0,
          exchange: answer.data.exchange,
        } as MxRecord;
      }

      case NAPTR_RECORD: {
        return {
          ...baseData,
          order: answer.data.order,
          preference: answer.data.preference,
          flags: answer.data.flags,
          service: answer.data.services,
          regexp: answer.data.regexp,
          replacement: answer.data.replacement,
        } as NaptrRecord;
      }

      case NSEC_RECORD: {
        const nsecData = answer.data;
        return {
          ...baseData,
          next_domain: sanitizeString(nsecData.nextDomain || ''),
          rr_types: nsecData.rrtypes || [],
        } as NsecRecord;
      }

      case NSEC3_RECORD: {
        const nsec3Data = answer.data;
        return {
          ...baseData,
          algorithm: nsec3Data.algorithm,
          flags: nsec3Data.flags,
          iterations: nsec3Data.iterations,
          salt: nsec3Data.salt ? nsec3Data.salt.toString('hex').toLowerCase() : '',
          next_domain: nsec3Data.nextDomain ? toBase32Hex(nsec3Data.nextDomain) : '',
          rr_types: nsec3Data.rrtypes || [],
        } as Nsec3Record;
      }

      case RP_RECORD: {
        return {
          ...baseData,
          mbox: answer.data.mbox,
          txt: answer.data.txt,
        } as RpRecord;
      }

      case RRSIG_RECORD: {
        return {
          ...baseData,
          type_covered: answer.data.typeCovered,
          algorithm: answer.data.algorithm,
          labels: answer.data.labels,
          original_ttl: answer.data.originalTTL,
          signature_expiration: answer.data.expiration,
          signature_inception: answer.data.inception,
          key_tag: answer.data.keyTag,
          signer_name: answer.data.signersName,
          signature: answer.data.signature.toString('base64'),
        } as RrsigRecord;
      }

      case SOA_RECORD: {
        return {
          ...baseData,
          nsname: answer.data.mname,
          hostmaster: answer.data.rname,
          serial: answer.data.serial || 0,
          refresh: answer.data.refresh || 0,
          retry: answer.data.retry || 0,
          expire: answer.data.expire || 0,
          minimum: answer.data.minimum || 0,
        } as SoaRecord;
      }

      case SRV_RECORD: {
        return {
          ...baseData,
          priority: answer.data.priority || 0,
          weight: answer.data.weight || 0,
          port: answer.data.port,
          target: answer.data.target,
        } as SrvRecord;
      }

      case SSHFP_RECORD: {
        return {
          ...baseData,
          algorithm: answer.data.algorithm,
          fp_type: answer.data.hash,
          fingerprint: answer.data.fingerprint,
        } as SshfpRecord;
      }

      case TLSA_RECORD: {
        return {
          ...baseData,
          usage: answer.data.usage,
          selector: answer.data.selector,
          mtype: answer.data.matchingType,
          cert: answer.data.certificate.toString('hex').toLowerCase(),
        } as TlsaRecord;
      }

      case TXT_RECORD: {
        let txtValue: string;
        if (Array.isArray(answer.data)) {
          txtValue = answer.data
            .map((item: Buffer | string) =>
              Buffer.isBuffer(item) ? item.toString() : String(item)
            )
            .join('');
        } else if (Buffer.isBuffer(answer.data)) {
          txtValue = answer.data.toString();
        } else {
          txtValue = String(answer.data);
        }
        return { value: txtValue, ...baseData } as TxtRecord;
      }

      case OPT_RECORD: {
        // OPT records are EDNS0 pseudo-records that contain metadata
        // they are handled separately by parsePacketOptions, parseExtendedDnsErrors and parseEdnsOptions
        // so we skip them in regular record parsing
        return null;
      }

      // **********
      // parse raw unstructured record types (buffer data) from dns-packet
      // **********
      case CDNSKEY_RECORD: {
        return parseRawCdnskeyRecord(baseData.name, answer.data as Buffer, baseData.ttl);
      }

      case CDS_RECORD: {
        return parseRawCdsRecord(baseData.name, answer.data as Buffer, baseData.ttl);
      }

      case NSEC3PARAM_RECORD: {
        return parseRawNsec3paramRecord(baseData.name, answer.data as Buffer, baseData.ttl);
      }

      case TSIG_RECORD: {
        return parseRawTsigRecord(baseData.name, answer.data as Buffer, baseData.ttl);
      }

      case CERT_RECORD: {
        return parseRawCertRecord(baseData.name, answer.data as Buffer, baseData.ttl);
      }

      case KEY_RECORD: {
        return parseRawKeyRecord(baseData.name, answer.data as Buffer, baseData.ttl);
      }

      case SIG_RECORD: {
        return parseRawSigRecord(baseData.name, answer.data as Buffer, baseData.ttl);
      }

      case URI_RECORD: {
        return parseRawUriRecord(baseData.name, answer.data as Buffer, baseData.ttl);
      }

      case LOC_RECORD: {
        return parseRawLocRecord(baseData.name, answer.data as Buffer, baseData.ttl);
      }

      default:
        // for unknown/unsupported record types, create a generic record
        console.warn(`Unknown record type: ${answer.type}`);
        return createGenericRecord(baseData, answer);
    }
  } catch (error) {
    // if any parsing block throws an error, log it and convert to generic record
    console.error(error);
    return createGenericRecord(baseData, answer);
  }
}

// create a generic DnsRecord from answer data (for unknown types or parsing errors)
// dns-packet returns Buffer for unknown types; use text encoding for known text types, hex otherwise
export function createGenericRecord(
  baseData: { name: string; type: DnsRecordType; ttl: number },
  answer: PacketAnswer
): DnsRecord {
  const answerData = (answer as { data?: Buffer | string }).data;
  const data = Buffer.isBuffer(answerData)
    ? (DNS_TEXT_RECORD_TYPES as readonly string[]).includes(answer.type)
      ? answerData.toString('utf8') // use UTF-8 for known text record types
      : answerData.toString('hex').toLowerCase() // use hex for binary/unknown types
    : String(answerData);
  return {
    ...baseData,
    type: answer.type as DnsRecordType,
    data,
  } as unknown as DnsRecord;
}

//-----------------------------------------
// functions for parsing raw DNS records
//-----------------------------------------

// Helper function to parse DNSSEC algorithm field (can be numeric or string mnemonic)
export function parseDnssecAlgorithm(algorithmPart: string, recordType: string): number {
  const parsedAlgorithm = parseInt(algorithmPart, 10);

  if (!isNaN(parsedAlgorithm)) {
    return parsedAlgorithm;
  }

  // handle string mnemonics by mapping them to their numeric values
  const algorithmMap: Record<string, number> = {
    'RSAMD5': 1,
    'DH': 2,
    'DSA': 3,
    'RSASHA1': 5,
    'DSA-NSEC3-SHA1': 6,
    'RSASHA1-NSEC3-SHA1': 7,
    'RSASHA256': 8,
    'RSASHA512': 10,
    'ECC-GOST': 12,
    'ECDSAP256SHA256': 13,
    'ECDSAP384SHA384': 14,
    'ED25519': 15,
    'ED448': 16,
  };

  const algorithm = algorithmMap[algorithmPart];
  if (algorithm === undefined) {
    throw new ParsingError(`Unknown ${recordType} algorithm: ${algorithmPart}`);
  }

  return algorithm;
}

// parse raw CDNSKEY record data
export function parseRawCdnskeyRecord(name: string, data: Buffer, ttl = 0): CdnskeyRecord {
  // parse binary CDNSKEY data (same format as DNSKEY)
  // bytes 0-1: flags (big-endian)
  // byte 2: protocol (always 3)
  // byte 3: algorithm
  // remaining bytes: public key
  const flags = (data[0] << 8) | data[1];
  const protocol = data[2];
  const algorithm = data[3];
  const public_key = data.slice(4).toString('base64');
  return {
    name,
    ttl,
    type: CDNSKEY_RECORD,
    class: 'IN',
    flags,
    protocol,
    algorithm,
    public_key,
  };
}

// parse raw CDS record data
export function parseRawCdsRecord(name: string, data: Buffer, ttl = 0): CdsRecord {
  // parse binary CDS data (same format as DS)
  // bytes 0-1: key tag (big-endian)
  // byte 2: algorithm
  // byte 3: digest type
  // remaining bytes: digest
  const key_tag = (data[0] << 8) | data[1];
  const algorithm = data[2];
  const digest_type = data[3];
  const digest = data.slice(4).toString('hex').toLowerCase();
  return {
    name,
    ttl,
    type: CDS_RECORD,
    class: 'IN',
    key_tag,
    algorithm,
    digest_type,
    digest,
  };
}

// parse raw NSEC3PARAM record data
export function parseRawNsec3paramRecord(name: string, data: Buffer, ttl = 0): Nsec3paramRecord {
  // parse binary NSEC3PARAM data directly
  const algorithm = data[0];
  const flags = data[1];
  const iterations = (data[2] << 8) | data[3];
  // salt length is at byte 4, salt data follows
  let salt = '';
  if (data.length > 4) {
    const saltLength = data[4];
    if (saltLength > 0 && data.length >= 5 + saltLength) {
      salt = data
        .slice(5, 5 + saltLength)
        .toString('hex')
        .toLowerCase();
    }
  }
  return {
    name,
    ttl,
    type: NSEC3PARAM_RECORD,
    class: 'IN',
    algorithm,
    flags,
    iterations,
    salt,
  };
}

// parse raw TSIG record data
export function parseRawTsigRecord(name: string, data: Buffer, ttl = 0): TsigRecord {
  // parse binary TSIG data directly from buffer (RFC 8945)
  let offset = 0;

  // algorithm name (domain name format)
  let algorithm = '';
  while (offset < data.length && data[offset] !== 0) {
    const labelLength = data[offset];
    if (labelLength === 0) break;
    if (offset + labelLength + 1 > data.length) break;
    if (algorithm) algorithm += '.';
    algorithm += data.slice(offset + 1, offset + 1 + labelLength).toString();
    offset += labelLength + 1;
  }
  offset++; // skip null terminator

  if (offset + 16 > data.length) {
    throw new ParsingError(`TSIG record too short`);
  }

  // bytes 0-5: time signed (48-bit big-endian)
  // use multiplication for values > 32 bits to avoid JavaScript bitwise limitations
  const time_signed =
    data[offset] * 0x10000000000 +
    data[offset + 1] * 0x100000000 +
    (data[offset + 2] << 24) +
    (data[offset + 3] << 16) +
    (data[offset + 4] << 8) +
    data[offset + 5];
  offset += 6;

  // bytes 6-7: fudge (16-bit big-endian)
  const fudge = (data[offset] << 8) | data[offset + 1];
  offset += 2;

  // bytes 8-9: MAC size (16-bit big-endian)
  const mac_size = (data[offset] << 8) | data[offset + 1];
  offset += 2;

  // MAC data
  if (offset + mac_size + 6 > data.length) {
    throw new ParsingError(`TSIG record MAC data extends beyond buffer`);
  }
  const mac = data.slice(offset, offset + mac_size).toString('base64');
  offset += mac_size;

  // bytes after MAC: original ID (16-bit big-endian)
  const original_id = (data[offset] << 8) | data[offset + 1];
  offset += 2;

  // bytes after original ID: error (16-bit big-endian)
  const error = (data[offset] << 8) | data[offset + 1];
  offset += 2;

  // bytes after error: other length (16-bit big-endian)
  const other_len = (data[offset] << 8) | data[offset + 1];
  offset += 2;

  // other data
  let other_data = '';
  if (other_len > 0) {
    if (offset + other_len > data.length) {
      throw new ParsingError(`TSIG record other data extends beyond buffer`);
    }
    other_data = data.slice(offset, offset + other_len).toString('base64');
  }

  return {
    name,
    ttl,
    type: TSIG_RECORD,
    class: 'IN',
    algorithm,
    time_signed,
    fudge,
    mac_size,
    mac,
    original_id,
    error,
    other_len,
    other_data,
  };
}

// parse raw CERT record data
export function parseRawCertRecord(name: string, data: Buffer, ttl = 0): CertRecord {
  // parse binary CERT data directly from buffer
  // bytes 0-1: certificate type (big-endian)
  // bytes 2-3: key tag (big-endian)
  // byte 4: algorithm
  // remaining bytes: certificate data
  const certificate_type = ((data[0] << 8) | data[1]).toString();
  const key_tag = (data[2] << 8) | data[3];
  const algorithm = data[4];
  const certificate = data.slice(5).toString('base64');
  return {
    name,
    ttl,
    type: CERT_RECORD,
    class: 'IN',
    certificate_type,
    key_tag,
    algorithm,
    certificate,
  };
}

// parse raw KEY record data
export function parseRawKeyRecord(name: string, data: Buffer, ttl = 0): KeyRecord {
  // parse binary KEY data directly from buffer (same format as DNSKEY)
  // bytes 0-1: flags (big-endian)
  // byte 2: protocol
  // byte 3: algorithm
  // remaining bytes: public key
  const flags = (data[0] << 8) | data[1];
  const protocol = data[2];
  const algorithm = data[3];
  const public_key = data.slice(4).toString('base64');
  return {
    name,
    ttl,
    type: KEY_RECORD,
    class: 'IN',
    flags,
    protocol,
    algorithm,
    public_key,
  };
}

// parse raw SIG record data
export function parseRawSigRecord(name: string, data: Buffer, ttl = 0): SigRecord {
  // parse binary SIG data directly from buffer (same format as RRSIG)
  // bytes 0-1: type covered (big-endian)
  // byte 2: algorithm
  // byte 3: labels
  // bytes 4-7: original TTL (big-endian)
  // bytes 8-11: signature expiration (big-endian)
  // bytes 12-15: signature inception (big-endian)
  // bytes 16-17: key tag (big-endian)
  // remaining: signer name + signature
  const type_covered = ((data[0] << 8) | data[1]).toString();
  const algorithm = data[2];
  const labels = data[3];
  const original_ttl = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];
  const signature_expiration = (data[8] << 24) | (data[9] << 16) | (data[10] << 8) | data[11];
  const signature_inception = (data[12] << 24) | (data[13] << 16) | (data[14] << 8) | data[15];
  const key_tag = (data[16] << 8) | data[17];

  // parse signer name (wire format domain name)
  let offset = 18;
  let signer_name = '';
  while (offset < data.length && data[offset] !== 0) {
    const labelLength = data[offset];
    if (labelLength === 0) break;
    if (offset + labelLength + 1 > data.length) break;
    if (signer_name) signer_name += '.';
    signer_name += data.slice(offset + 1, offset + 1 + labelLength).toString();
    offset += labelLength + 1;
  }
  offset++; // skip null terminator

  // remaining bytes are the signature
  const signature = data.slice(offset).toString('base64');
  return {
    name,
    ttl,
    type: SIG_RECORD,
    class: 'IN',
    type_covered,
    algorithm,
    labels,
    original_ttl,
    signature_expiration,
    signature_inception,
    key_tag,
    signer_name,
    signature,
  };
}

// parse raw URI record data
export function parseRawUriRecord(name: string, data: Buffer, ttl = 0): UriRecord {
  // parse binary URI data directly from buffer
  // bytes 0-1: priority (big-endian)
  // bytes 2-3: weight (big-endian)
  // remaining bytes: target URI (UTF-8 string)
  const priority = (data[0] << 8) | data[1];
  const weight = (data[2] << 8) | data[3];
  const target = data.slice(4).toString('utf8');
  return {
    name,
    ttl,
    type: URI_RECORD,
    class: 'IN',
    priority,
    weight,
    target,
  };
}

// parse raw LOC record data
export function parseRawLocRecord(name: string, data: Buffer, ttl = 0): LocRecord {
  // parse binary LOC data directly from buffer
  // byte 0: version (must be 0)
  // byte 1: size (4-bit mantissa + 4-bit exponent)
  // byte 2: horizontal precision (4-bit mantissa + 4-bit exponent)
  // byte 3: vertical precision (4-bit mantissa + 4-bit exponent)
  // bytes 4-7: latitude (32-bit signed, big-endian, in thousandths of arc seconds)
  // bytes 8-11: longitude (32-bit signed, big-endian, in thousandths of arc seconds)
  // bytes 12-15: altitude (32-bit signed, big-endian, in centimeters from 100km below WGS84)
  const version = data[0];
  if (version !== 0) {
    throw new ParsingError(`Unsupported LOC record version: ${version}`);
  }

  const size = data[1];
  const horiz_pre = data[2];
  const vert_pre = data[3];

  // decode latitude (signed 32-bit big-endian)
  const latval = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];
  const latitude_raw = (latval >>> 0) - 0x80000000; // convert from unsigned to signed
  const latitude = latitude_raw / (60 * 60 * 1000); // convert from thousandths of arc seconds to degrees

  // decode longitude (signed 32-bit big-endian)
  const longval = (data[8] << 24) | (data[9] << 16) | (data[10] << 8) | data[11];
  const longitude_raw = (longval >>> 0) - 0x80000000; // convert from unsigned to signed
  const longitude = longitude_raw / (60 * 60 * 1000); // convert from thousandths of arc seconds to degrees

  // decode altitude (signed 32-bit big-endian)
  const altval = (data[12] << 24) | (data[13] << 16) | (data[14] << 8) | data[15];
  const altitude_raw = altval - 10000000; // subtract reference altitude (100km below WGS84)
  const altitude = altitude_raw / 100; // convert from centimeters to meters

  // convert size/precision values from XeY format to strings
  const decodeSize = (val: number): string => {
    const mantissa = (val >> 4) & 0x0f;
    const exponent = val & 0x0f;
    if (mantissa > 9 || exponent > 9) return '0.00';
    const value = mantissa * Math.pow(10, exponent);
    return (value / 100).toFixed(2);
  };

  return {
    name,
    ttl,
    type: LOC_RECORD,
    class: 'IN',
    version,
    size: decodeSize(size),
    horiz_pre: decodeSize(horiz_pre),
    vert_pre: decodeSize(vert_pre),
    latitude,
    longitude,
    altitude,
  };
}
