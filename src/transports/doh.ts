import {
  ConnectionError,
  DnsError,
  EmptyResponseError,
  InvalidResponseError,
  NoServerError,
} from '../errors';
import { toBase64Url } from '../wire/bytes';
import { parseDohUrl } from './endpoint';
import { createHttp2Client } from './http2';
import type { Http2Client } from './http2';
import { resolveProxy } from './proxy';
import type { Proxy } from './proxy';
import { isNode } from './runtime';
import type { FetchLike, Transport, TransportOptions } from './types';

// DNS over HTTPS (RFC 8484): the query is the body of a POST, or the `dns` parameter of
// a GET, and the answer is the response body.
//
// requests are made with the caller's `fetch` if one was given. Without one, an https://
// URL on Node goes over HTTP/2 with `node:http2` (http2.ts): Node's own `fetch` speaks only
// HTTP/1.1, which RFC 8484 §5.2 does not recommend and some servers refuse. Everywhere
// else, and for a server that does not offer HTTP/2 or a plain http:// URL, it is the
// runtime's `fetch`.
//
// with `proxy` set and no `fetch`, Node sends the query over HTTP/2 through the proxy's
// tunnel. Nothing else can: a runtime's `fetch` cannot be pointed at a proxy, so there DoH
// needs a `fetch` that goes through it (on Workers, the `tunnelfetch` package). Without
// one the query fails, so that nothing goes around the proxy

export type DohTransportOptions = Pick<
  TransportOptions,
  'proxy' | 'fetch' | 'dohMethod' | 'tls' | 'idleTimeout'
>;

const MEDIA_TYPE = 'application/dns-message';

const messageOf = (error: unknown) => (error instanceof Error ? error.message : String(error));

// whether to send DoH with `node:http2`: on Node and Bun, which have it. Deno's `fetch`
// negotiates HTTP/2 by itself
const useHttp2 = (): boolean => isNode() && !('Deno' in globalThis);

export function createDohTransport(options: DohTransportOptions = {}): Transport {
  const method = options.dohMethod ?? 'GET';
  let http2: Http2Client | undefined;

  const proxyRefusal = (proxy: Proxy, why: string) =>
    new DnsError(
      `DNS over HTTPS cannot go through ${proxy.display} ${why}: pass a \`fetch\` ` +
        'that uses the proxy, or a `proxy` function that returns nothing for DoH'
    );

  const http2Client = () =>
    (http2 ??= createHttp2Client({
      ...(options.tls && { tls: options.tls }),
      ...(options.idleTimeout !== undefined && { idleTimeout: options.idleTimeout }),
    }));

  return {
    name: 'doh',

    async send(request) {
      const { endpoint, query, signal, onEvent } = request;
      if (signal?.aborted) throw signal.reason;
      if (!endpoint.url) throw new NoServerError('No URL to send the DoH query to');
      // an endpoint may be handed straight to the transport, so the URL is checked here
      // as well as where servers are parsed
      parseDohUrl(endpoint.url);

      // a proxy function may say this server is not proxied, by returning nothing
      const proxy = options.fetch
        ? undefined
        : resolveProxy(options.proxy, {
            host: endpoint.host,
            port: endpoint.port,
            transport: 'doh',
          });
      const overHttp2 = !options.fetch && endpoint.url.startsWith('https:') && useHttp2();
      if (proxy && !overHttp2) throw proxyRefusal(proxy, 'by itself');

      const headers: Record<string, string> = { accept: MEDIA_TYPE };
      let url = endpoint.url;
      if (method === 'GET') {
        url += `${url.includes('?') ? '&' : '?'}dns=${toBase64Url(query)}`;
      } else {
        headers['content-type'] = MEDIA_TYPE;
      }
      const body = method === 'POST' ? query : undefined;

      let status: number;
      let contentType: string | null;
      let bytes: Uint8Array;
      try {
        const answered = overHttp2
          ? await http2Client().request({
              url,
              method,
              headers,
              ...(body && { body }),
              ...(signal && { signal }),
              ...(proxy && { proxy }),
              ...(onEvent && { onEvent }),
            })
          : undefined;
        if (answered) {
          ({ status, contentType, bytes } = answered);
        } else {
          // the fetch below would go around the proxy
          if (proxy) throw proxyRefusal(proxy, 'to a server that does not speak HTTP/2');
          let response: Awaited<ReturnType<FetchLike>>;
          if (options.fetch) {
            response = await options.fetch(url, { method, headers, ...(body && { body }), signal });
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
        }
      } catch (error) {
        if (signal?.aborted) throw signal.reason;
        if (error instanceof DnsError) throw error;
        // whatever a fetch or a session throws, the caller's own fetch included, is a
        // connection failure
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
      // the HTTP/2 sessions are this transport's; a fetch, the runtime's or the caller's,
      // owns its own connections
      http2?.close();
      http2 = undefined;
    },
  };
}
