import { Buffer } from 'buffer';
import { EXTENDED_DNS_ERRORS, EDNS_OPTIONS, OPT_RECORD } from './constants.js';
import type {
  DnsExtendedErrors,
  DnsExtendedErrorCode,
  OptRecord,
  PacketAnswer,
  RawEdnsOption,
  EdnsOption,
  EdnsNsid,
  EdnsClientSubnet,
  EdnsCookie,
  EdnsTcpKeepAlive,
  EdnsPadding,
  EdnsDnssecCapability,
  EdnsKeyTag,
} from './types.js';

// parse OPT records from DNS response additionals into structured OptRecord objects
export function parsePacketOptions(additionals: PacketAnswer[]): OptRecord[] {
  if (!additionals || !Array.isArray(additionals)) {
    return [];
  }
  return additionals
    .filter(additional => additional.type === OPT_RECORD)
    .map(opt => ({
      type: OPT_RECORD,
      name: opt.name || '.',
      udp_payload_size: opt.udpPayloadSize || 512,
      extended_rcode: opt.extendedRcode || 0,
      edns_version: opt.ednsVersion || 0,
      flags: opt.flags || 0,
      flag_do: opt.flag_do || false,
      options: (opt.options || []).map((option: unknown): RawEdnsOption => {
        const typedOption = option as RawEdnsOption;
        return {
          code: typedOption.code,
          data: Buffer.isBuffer(typedOption.data)
            ? typedOption.data
            : Buffer.isBuffer((typedOption.data as { data?: Buffer })?.data)
              ? (typedOption.data as { data: Buffer }).data
              : Buffer.from([]),
        };
      }),
    }));
}

// decode extended DNS errors and other EDNS options from OPT records
// these are only present if the EDNS options are set in the query
// https://www.rfc-editor.org/rfc/rfc8914.html#name-extended-dns-error-codes
export function parseExtendedDnsErrors(opts: OptRecord[]): DnsExtendedErrors {
  const errors: DnsExtendedErrors = {};
  for (const opt of opts) {
    if (opt.options) {
      for (const option of opt.options) {
        // code 15 is the EDE option code
        if (option.code === 15 && option.data) {
          // option.data is always a Buffer in DnsOptAnswer structure
          const buffer = option.data;
          // first 2 bytes are the error code
          const errorCode = (buffer[0] << 8) | buffer[1];
          // if the error code is in our list of extended DNS error codes, add it and description
          if (errorCode in EXTENDED_DNS_ERRORS) {
            const extendedErrorCode = errorCode as DnsExtendedErrorCode;
            // the rest of the buffer contains the error text
            const errorText = buffer.slice(2).toString('utf8');
            errors[extendedErrorCode] =
              errorText || (EXTENDED_DNS_ERRORS[extendedErrorCode] as string);
          }
        }
      }
    }
  }
  return errors;
}

// parse the EDNS options from OPT records
// these are only present if the matching EDNS options are set in the query
export function parseEdnsOptions(opts: OptRecord[]): EdnsOption[] {
  const options: EdnsOption[] = [];
  for (const opt of opts) {
    if (opt.options) {
      for (const option of opt.options) {
        if (
          Object.values(EDNS_OPTIONS).includes(
            option.code as (typeof EDNS_OPTIONS)[keyof typeof EDNS_OPTIONS]
          )
        ) {
          const parsedOption = parseEdnsOption(option);
          if (parsedOption) {
            options.push(parsedOption);
          }
        }
      }
    }
  }
  return options;
}

// parse EDNS options from dns-packet
export function parseEdnsOption(opt: RawEdnsOption): EdnsOption | null {
  const option = {
    code: opt.code,
    // _data: opt.data,
  };

  switch (opt.code) {
    // Name Server Identifier
    case EDNS_OPTIONS.NSID: {
      let nsid: string;
      try {
        const text = opt.data.toString('utf8');
        nsid = /^[\x20-\x7E\s]*$/.test(text) ? text.trim() : opt.data.toString('hex');
      } catch (e) {
        console.error('parseEdnsOption', opt.code, e);
        nsid = opt.data.toString('hex');
      }
      return {
        ...option,
        nsid,
      } as EdnsNsid;
    }

    // Client Subnet
    case EDNS_OPTIONS.CLIENT_SUBNET: {
      if (opt.data.length >= 4) {
        const family = opt.data.readUInt16BE(0);
        const sourcePrefixLength = opt.data.readUInt8(2);
        const scopePrefixLength = opt.data.readUInt8(3);
        const address = opt.data.slice(4);
        return {
          ...option,
          family,
          sourcePrefixLength,
          scopePrefixLength,
          ip:
            family === 1
              ? Array.from(address.slice(0, Math.ceil(sourcePrefixLength / 8)))
                  .concat([0, 0, 0, 0])
                  .slice(0, 4)
                  .join('.')
              : address.toString('hex'),
        } as EdnsClientSubnet;
      }
      break;
    }

    // DNS Cookies
    case EDNS_OPTIONS.COOKIE: {
      if (opt.data.length >= 8) {
        const clientCookie = opt.data.slice(0, 8);
        const serverCookie = opt.data.slice(8);
        return {
          ...option,
          clientCookie: clientCookie.toString('hex'),
          serverCookie: serverCookie.length > 0 ? serverCookie.toString('hex') : null,
          valid: serverCookie.length >= 8 && serverCookie.length <= 32,
        } as EdnsCookie;
      }
      break;
    }

    // TCP Keep-Alive
    case EDNS_OPTIONS.TCP_KEEPALIVE: {
      if (opt.data.length === 2) {
        return {
          ...option,
          timeout: opt.data.readUInt16BE(0),
          unit: 'centiseconds',
        } as EdnsTcpKeepAlive;
      }
      break;
    }

    // EDNS Padding (for DNS over TLS/HTTPS)
    case EDNS_OPTIONS.PADDING: {
      return {
        ...option,
        paddingLength: opt.data.length,
        purpose: 'Traffic analysis protection',
      } as EdnsPadding;
    }

    // DNSSEC Algorithm Understanding
    case EDNS_OPTIONS.DAU:
    case EDNS_OPTIONS.DHU:
    case EDNS_OPTIONS.N3U: {
      return {
        ...option,
        algorithms: Array.from(opt.data),
        algorithmType:
          opt.code === EDNS_OPTIONS.DAU
            ? 'DNSSEC algorithms'
            : opt.code === EDNS_OPTIONS.DHU
              ? 'DS hash algorithms'
              : 'NSEC3 hash algorithms',
      } as EdnsDnssecCapability;
    }

    // DNSSEC Key Tag
    case EDNS_OPTIONS.KEY_TAG: {
      const keyTags = [];
      if (opt.data.length > 0) {
        for (let i = 0; i < opt.data.length; i += 2) {
          if (i + 1 < opt.data.length) {
            keyTags.push(opt.data.readUInt16BE(i));
          }
        }
      }
      return {
        ...option,
        tags: keyTags,
      } as EdnsKeyTag;
    }

    default: {
      return null;
    }
  }

  // unknown, vendor-specific, or unsupported options
  return null;
}
