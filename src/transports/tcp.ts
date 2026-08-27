import net from 'net';
import dnsPacket from 'dns-packet';
import { createDnsPacket } from '../packets';
import type { DnsOptions, DnsPacket, DnsQuestion, DnsTransportQuery } from '../types';
import { TimeoutError, ConnectionError, ParsingError, AbortError } from '../errors';
import { isValidIpv6 } from '../utils';

// maximum TCP DNS response size to prevent memory exhaustion
const MAX_TCP_RESPONSE_SIZE = 65535; // Maximum DNS message size per RFC

// resolve a DnsQuestion using TCP transport
export const tcpQuery: DnsTransportQuery = async function (
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

  // create the DNS packet using shared function
  const encodedPacket = createDnsPacket(question);

  // TCP DNS messages are prefixed with a 2-byte length field
  const lengthPrefix = Buffer.allocUnsafe(2);
  lengthPrefix.writeUInt16BE(encodedPacket.length, 0);
  const tcpPacket = Buffer.concat([lengthPrefix, encodedPacket]);

  // create TCP connection - handle IPv6 addresses properly
  const socket = new net.Socket();

  // wait for the response packet
  return await new Promise<DnsPacket>((resolve, reject) => {
    let isResolved = false;
    let responseBuffer = Buffer.alloc(0);
    let expectedLength: number | null = null;

    // helper function to safely close socket
    const safeCloseSocket = () => {
      try {
        if (!socket.destroyed) {
          socket.removeAllListeners();
          socket.destroy();
        }
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
      } catch (error) {
        // ignore socket close errors - socket might already be closed
      }
    };

    // helper to safely resolve once
    const safeResolve = (response: DnsPacket) => {
      if (!isResolved) {
        isResolved = true;
        clearTimeout(timeoutId);
        safeCloseSocket();
        resolve(response);
      }
    };

    // helper to safely reject once
    const safeReject = (error: Error) => {
      if (!isResolved) {
        isResolved = true;
        clearTimeout(timeoutId);
        safeCloseSocket();
        reject(error);
      }
    };

    // proactively handle abort - close socket and reject immediately
    controller.signal.addEventListener('abort', () => {
      // proactively close socket and reject when aborted
      if (!isResolved) {
        safeCloseSocket();
        if (options.signal?.aborted) {
          safeReject(new AbortError('Query was aborted'));
        } else {
          safeReject(
            new TimeoutError(
              `Timeout for query '${question.query}' at '${question.server}' after ${options.timeout}ms`
            )
          );
        }
      }
    });

    // check controller abort status in event handlers (guard to prevent processing after abort)
    // Note: abort listener already handles rejection proactively, this is just a guard
    const checkAborted = () => {
      return controller.signal.aborted || isResolved;
    };

    // handle incoming data
    socket.on('data', (data: Buffer) => {
      if (isResolved || checkAborted()) return;

      responseBuffer = Buffer.concat([responseBuffer, data]);

      // check if response buffer exceeds maximum size to prevent memory exhaustion
      if (responseBuffer.length > MAX_TCP_RESPONSE_SIZE) {
        safeReject(
          new ConnectionError(
            `TCP response too large: ${responseBuffer.length} bytes exceeds maximum`
          )
        );
        return;
      }

      // if we haven't read the length yet and we have at least 2 bytes
      if (expectedLength === null && responseBuffer.length >= 2) {
        expectedLength = responseBuffer.readUInt16BE(0);
        responseBuffer = responseBuffer.subarray(2); // remove length prefix
      }

      // if we have the expected length and enough data
      if (expectedLength !== null && responseBuffer.length >= expectedLength) {
        try {
          // decode the response packet (take only the expected length)
          const responseData = responseBuffer.slice(0, expectedLength);
          const response = dnsPacket.decode(responseData) as DnsPacket;
          response.bytes = responseData.length;
          safeResolve(response);
        } catch (error) {
          safeReject(new ParsingError(`Failed to decode TCP response: ${String(error)}`));
        }
      }
    });

    // handle connection established
    socket.on('connect', () => {
      if (isResolved || checkAborted()) return;

      // send the query packet
      socket.write(tcpPacket, err => {
        if (err && !isResolved && !checkAborted()) {
          safeReject(new ConnectionError(`Failed to send TCP query: ${err.message}`));
        }
      });
    });

    // handle errors
    socket.on('error', (error: Error) => {
      if (!isResolved && !checkAborted()) {
        safeReject(new ConnectionError(error.message));
      }
    });

    // handle connection close
    socket.on('close', () => {
      if (!isResolved && !checkAborted()) {
        safeReject(new ConnectionError('TCP connection closed unexpectedly'));
      }
    });

    // initiate connection with proper IPv6 handling
    const family = isValidIpv6(question.server) ? 6 : 4;
    socket.connect({
      port: 53,
      host: question.server,
      family: family,
    });
  });
};
