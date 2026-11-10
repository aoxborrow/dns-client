import {
  ConnectionError,
  DnsError,
  EmptyResponseError,
  InvalidResponseError,
  NoServerError,
} from '../errors';
import { toBase64 } from '../wire/bytes';
import { parseDohUrl } from './endpoint';
import { createTunnelFetch } from './tunnel-fetch';
import type { TunnelFetch } from './tunnel-fetch';
import type { FetchLike, Transport, TransportOptions } from './types';

// DNS over HTTPS (RFC 8484): the query is the body of a POST, or the `dns` parameter of
// a GET, and the answer is the response body.
//
// requests are made with the caller's `fetch` if one was given, through the library's
// own tunnelling fetch if a proxy was, and with the runtime's `fetch` otherwise

export type DohTransportOptions = Pick<
  TransportOptions,
  'proxy' | 'fetch' | 'tls' | 'idleTimeout' | 'dohMethod'
>;

const MEDIA_TYPE = 'application/dns-message';

const messageOf = (error: unknown) => (error instanceof Error ? error.message : String(error));

// base64url without padding, as RFC 8484 §4.1 wants the query in a URL
export function toBase64Url(bytes: Uint8Array): string {
  return toBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function createDohTransport(options: DohTransportOptions = {}): Transport {
  const method = options.dohMethod ?? 'GET';
  let tunnel: TunnelFetch | undefined;

  return {
    name: 'doh',

    async send(request) {
      const { endpoint, query, signal } = request;
      if (signal?.aborted) throw signal.reason;
      if (!endpoint.url) throw new NoServerError('No URL to send the DoH query to');
      // an endpoint may be handed straight to the transport, so the URL is checked here
      // as well as where servers are parsed
      parseDohUrl(endpoint.url);

      const headers: Record<string, string> = { Accept: MEDIA_TYPE };
      let url = endpoint.url;
      if (method === 'GET') {
        url += `${url.includes('?') ? '&' : '?'}dns=${toBase64Url(query)}`;
      } else {
        headers['Content-Type'] = MEDIA_TYPE;
      }
      const body = method === 'POST' ? query : undefined;

      let status: number;
      let contentType: string | null;
      let bytes: Uint8Array;
      try {
        let response: Awaited<ReturnType<FetchLike>>;
        if (options.fetch) {
          response = await options.fetch(url, { method, headers, ...(body && { body }), signal });
        } else if (options.proxy !== undefined) {
          tunnel ??= createTunnelFetch(options);
          response = await tunnel(url, {
            method,
            headers,
            ...(body && { body }),
            signal,
            onEvent: request.onEvent,
          });
        } else {
          response = await fetch(url, {
            method,
            headers,
            ...(body && { body: body as BodyInit }),
            signal,
          });
        }
        status = response.status;
        contentType = response.headers.get('content-type');
        bytes = new Uint8Array(await response.arrayBuffer());
      } catch (error) {
        if (signal?.aborted) throw signal.reason;
        if (error instanceof DnsError) throw error;
        // whatever a fetch throws, the caller's own included, is a connection failure
        throw new ConnectionError(`DoH request to ${endpoint.host} failed: ${messageOf(error)}`, {
          cause: error,
        });
      }

      if (status < 200 || status >= 300) {
        // a server error or rate limit may pass; a rejected request will not
        if (status >= 500 || status === 429 || status === 408) {
          throw new ConnectionError(`DoH server ${endpoint.host} answered HTTP ${status}`);
        }
        throw new InvalidResponseError(`DoH server ${endpoint.host} answered HTTP ${status}`);
      }
      if (contentType && !contentType.toLowerCase().startsWith(MEDIA_TYPE)) {
        throw new InvalidResponseError(
          `DoH server ${endpoint.host} answered with ${contentType.split(';')[0]}, not a DNS message`
        );
      }
      if (bytes.length === 0) {
        throw new EmptyResponseError(`DoH server ${endpoint.host} sent an empty response`);
      }
      return { bytes, transport: 'doh' };
    },

    close() {
      tunnel?.close();
      tunnel = undefined;
    },
  };
}
