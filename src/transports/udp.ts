import dgram from 'dgram';
import dnsPacket from 'dns-packet';
import { TimeoutError, ConnectionError, ParsingError, AbortError } from '../errors.js';
import { createDnsPacket } from '../packets.js';
import type { DnsOptions, DnsPacket, DnsQuestion, DnsTransportQuery } from '../types.js';
import { isValidIpv6 } from '../utils.js';

// resolve a DnsQuestion using UDP transport
export const udpQuery: DnsTransportQuery = async function (
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

  // create a UDP socket - use udp6 for IPv6 addresses, udp4 for IPv4
  const socketType = isValidIpv6(question.server) ? 'udp6' : 'udp4';
  const socket = dgram.createSocket(socketType);

  // set socket options for better reliability
  try {
    // increase receive buffer size for better handling of DNS responses
    socket.setRecvBufferSize(64 * 1024);
    // set socket to reuse address for faster socket recycling
    socket.bind({ exclusive: false });
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
  } catch (error) {
    // ignore socket option errors - not critical for functionality
  }

  // wait for the response packet
  return await new Promise<DnsPacket>((resolve, reject) => {
    let isResolved = false;
    // helper function to safely close socket
    const safeCloseSocket = () => {
      try {
        // remove all listeners to prevent memory leaks
        socket.removeAllListeners();
        // attempt to close socket, ignore errors if already closed
        socket.close();
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

    // handle the response packet, close socket, and resolve the promise
    socket.on('message', (message: Buffer) => {
      if (isResolved || checkAborted()) return;

      try {
        // decode the response packet
        const response = dnsPacket.decode(message) as DnsPacket;
        response.bytes = message.length;
        safeResolve(response);
      } catch (error) {
        safeReject(new ParsingError(`Failed to decode UDP response: ${String(error)}`));
      }
    });

    // handle errors, close socket, and reject the promise
    socket.on('error', (error: Error) => {
      if (!isResolved && !checkAborted()) {
        safeReject(new ConnectionError(error.message));
      }
    });

    // handle socket close events
    socket.on('close', () => {
      if (!isResolved && !checkAborted()) {
        safeReject(new ConnectionError('UDP socket closed unexpectedly'));
      }
    });

    // send the query packet to the DNS server AFTER event listeners are attached
    socket.send(encodedPacket, 0, encodedPacket.length, 53, question.server, err => {
      if (err && !isResolved && !checkAborted()) {
        safeReject(new ConnectionError(`Failed to send UDP query: ${err.message}`));
      }
    });
  });
};
