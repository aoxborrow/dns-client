import { InvalidQueryError } from '../errors';
import { toHex } from '../wire/bytes';

// IP addresses as text and as bytes

/**
 * four bytes for a dotted-quad IPv4 address, or null if the text is not one. Each part is
 * decimal, 0 to 255, with no leading zeros
 */
export function parseIpv4(text: string): Uint8Array | null {
  const parts = text.split('.');
  if (parts.length !== 4) return null;
  const out = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    if (!/^(0|[1-9]\d{0,2})$/.test(parts[i])) return null;
    const value = Number(parts[i]);
    if (value > 255) return null;
    out[i] = value;
  }
  return out;
}

/**
 * sixteen bytes for an IPv6 address in any RFC 4291 text form, or null if the text is not
 * one: groups of one to four hex digits, at most one `::`, and optionally a dotted-quad
 * IPv4 tail. Zone identifiers (`%eth0`) are not addresses and are rejected
 */
export function parseIpv6(text: string): Uint8Array | null {
  if (!/^[0-9a-fA-F:.]+$/.test(text)) return null;
  const halves = text.split('::');
  if (halves.length > 2) return null;

  const groupsOf = (part: string): number[] | null => {
    if (part === '') return [];
    const pieces = part.split(':');
    const groups: number[] = [];
    for (let i = 0; i < pieces.length; i++) {
      const piece = pieces[i];
      if (piece.includes('.')) {
        // an IPv4 tail is only valid as the very last piece
        if (i !== pieces.length - 1) return null;
        const ipv4 = parseIpv4(piece);
        if (!ipv4) return null;
        groups.push((ipv4[0] << 8) | ipv4[1], (ipv4[2] << 8) | ipv4[3]);
      } else {
        if (!/^[0-9a-fA-F]{1,4}$/.test(piece)) return null;
        groups.push(parseInt(piece, 16));
      }
    }
    return groups;
  };

  const head = groupsOf(halves[0]);
  const tail = halves.length === 2 ? groupsOf(halves[1]) : [];
  if (!head || !tail) return null;
  // an IPv4 tail in the first half is only the end of the address when there is no `::`
  if (halves.length === 2 && halves[0].includes('.')) return null;

  const missing = 8 - head.length - tail.length;
  // `::` stands for at least one group; without it all eight must be present
  if (halves.length === 2 ? missing < 1 : missing !== 0) return null;

  const groups = [...head, ...(Array(missing).fill(0) as number[]), ...tail];
  const out = new Uint8Array(16);
  groups.forEach((group, index) => {
    out[index * 2] = group >> 8;
    out[index * 2 + 1] = group & 0xff;
  });
  return out;
}

/**
 * the name to ask for an address's PTR record: `1.2.0.192.in-addr.arpa` for IPv4, the
 * reversed nibbles under `ip6.arpa` for IPv6
 */
export function reverseIp(address: string): string {
  const text = address.trim();
  const ipv4 = parseIpv4(text);
  if (ipv4) return `${[...ipv4].reverse().join('.')}.in-addr.arpa`;
  const ipv6 = parseIpv6(text);
  if (ipv6) return `${toHex(ipv6).split('').reverse().join('.')}.ip6.arpa`;
  throw new InvalidQueryError(`Not an IP address: ${address}`);
}
