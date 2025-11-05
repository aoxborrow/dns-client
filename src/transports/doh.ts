import dnsPacket from 'dns-packet';
import { InvalidResponseError, ParsingError, TimeoutError, AbortError } from '../errors.js';
import { createDnsPacket } from '../packets.js';
import type { DnsOptions, DnsPacket, DnsQuestion, DnsTransportQuery } from '../types.js';

// resolve a DnsQuestion using DoH transport
export const dohQuery: DnsTransportQuery = async function (
  question: DnsQuestion,
  options: DnsOptions
): Promise<DnsPacket> {
  // setup abort controller with external signal linking
  const controller = new AbortController();

  // check if external signal is already aborted
  if (options.signal?.aborted) {
    throw new AbortError('Query was aborted');
  }

  // link external signal
  if (options.signal) {
    options.signal.addEventListener('abort', () => controller.abort());
  }

  // internal timeout
  const timeoutId = setTimeout(() => controller.abort(), options.timeout);

  try {
    // create DNS packet using existing function from packet.ts
    const dnsQuery = createDnsPacket(question);

    // for GET requests, encode as base64url (RFC 8484)
    const base64Query = dnsQuery.toString('base64url');

    // get the base URL for the DoH request
    const url = `${question.server}?dns=${base64Query}`;

    // build the headers for the DoH request
    const headers = {
      // request wire format response
      Accept: 'application/dns-message',
    };

    // use standard fetch API
    const response = await fetch(url, {
      method: 'GET',
      headers,
      signal: controller.signal,
    });

    if (!response.ok || response.status !== 200) {
      throw new InvalidResponseError(`Bad response from DoH Resolver ${url}: ${response.status}`);
    }

    // parse wire format (binary DNS message) response
    const binaryResponse = await response.arrayBuffer();
    const buffer = Buffer.from(binaryResponse);

    if (buffer.length === 0) {
      throw new InvalidResponseError('Received empty wire format response from DoH server');
    }

    try {
      // return the packet response with proper typing
      // rcode is already a string from dns-packet
      // bytes is added by me
      const decodedPacket = dnsPacket.decode(buffer) as DnsPacket;
      decodedPacket.bytes = buffer.length;
      return decodedPacket;
    } catch (error) {
      throw new ParsingError(`Failed to decode wire format DoH response: ${String(error)}`);
    }
  } catch (error) {
    // handle abort errors - check if it was due to timeout or external abort
    // fetch() throws DOMException (in Node.js) or Error with name 'AbortError' when aborted
    if (
      (error instanceof Error ||
        (typeof error === 'object' && error !== null && 'name' in error)) &&
      (error as { name?: string }).name === 'AbortError'
    ) {
      // check if external signal was aborted (user cancellation)
      if (options.signal?.aborted) {
        throw new AbortError('Query was aborted');
      }
      // otherwise it was a timeout
      throw new TimeoutError(
        `Timeout for query '${question.query}' at '${question.server}' after ${options.timeout}ms`
      );
    }
    // re-throw other errors as-is
    throw error;
  } finally {
    clearTimeout(timeoutId);
  }
};
