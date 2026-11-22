# Wire format and transports

`@aoxborrow/dns/wire` encodes queries and decodes messages; `@aoxborrow/dns/transports` sends
them. The resolvers use both, and most programs never need either directly. The root entry
re-exports `/wire`, and `createTransports` from `/transports`.

## `/wire`

```ts network
import { createUdpTransport } from '@aoxborrow/dns/transports';
import { decodeMessage, encodeQuery } from '@aoxborrow/dns/wire';

const query = encodeQuery({ id: 1234, name: 'example.com', type: 'A', recursionDesired: true });

const udp = createUdpTransport();
const response = await udp.send({ endpoint: { host: '1.1.1.1', port: 53 }, query });
udp.close();

const message = decodeMessage(response.bytes);
message.rcode; // 0
message.answers; // [{ name: 'example.com', type: 1, class: 1, ttl: 300, rdata: Uint8Array, section: 'answer' }]
```

`Uint8Array` in and out, no `Buffer`. Record data stays as bytes; `decodeRecords` in
`/records` types it. Names are accepted in Unicode or punycode and returned in ASCII.
Also here: `encodeMessage`, and the name helpers `canonicalName`, `compareNames`,
`isSubdomain`, `parentName`, `countLabels`, `encodeName` and `toAsciiName`. `splitName`
gives a name's labels as text, `nameToLabels` gives them as bytes and `labelsToName` turns
those back into a name, and `readName` reads a name out of a message, following
compression pointers. The byte helpers are `toHex`, `fromHex`, `toBase64`, `fromBase64`,
`toBase32Hex`, `concatBytes`, `compareBytes`, `readU16`/`writeU16` and
`readU32`/`writeU32`.

## `/transports`

The resolvers make the transports they need. Use one directly to send a message you
encoded yourself, as in the [`/wire`](#wire) example above.

| Function               | Notes                                                                                                                     |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `createUdpTransport()` | a fresh socket and source port for every query, kept for its retransmissions (RFC 5452)                                   |
| `createTcpTransport()` | a connection per query by default; `pipeline: true` keeps connections open and sends several queries down each (RFC 7766) |
| `createTlsTransport()` | DNS over TLS, pipelined by default                                                                                        |
| `createDohTransport()` | DNS over HTTPS, GET by default (`dohMethod: 'POST'`)                                                                      |

`/transports/doh` holds `createDohTransport()` alone, with the types its `send()` takes and
returns, for a program that sends DNS over HTTPS and nothing else: it leaves out the UDP
and TCP transports.

To share sockets and connections between resolvers, make one set with `createTransports`,
which the root entry has too, and pass it to each. A resolver does not close a set it was
given.

```ts
import { AuthoritativeResolver, createTransports, Resolver } from '@aoxborrow/dns';

const transports = createTransports({ pipeline: true, idleTimeout: 10_000 });
const recursive = new Resolver({ servers: ['1.1.1.1'], transport: 'tcp', transports });
const iterative = new AuthoritativeResolver({ transports });

// …
transports.close();
```

Resolvers given no transport options share one set for the whole process.
`closeDefaultTransports()` closes it, for code that wants its sockets gone at a known point.
Those sockets never keep a process alive. `DEFAULT_PORTS` has each transport's port: 53 for
UDP and TCP, 853 for TLS, 443 for HTTPS.

The `connect` option is the function that opens a TCP connection. Left out, the library
uses `createNodeConnect()` on Node and `createCloudflareConnect()` on Cloudflare Workers,
and either can be called to make one to pass in. `createCloudflareConnect()` takes the
runtime's own `connect`, imported from `cloudflare:sockets`; without it, it loads that
module itself the first time a connection is opened.

### DNS over HTTPS

On Node, DNS over HTTPS to an `https://` URL goes over HTTP/2 with `node:http2`,
one session per server shared by every query to it (RFC 8484 recommends HTTP/2 at least,
and some servers refuse HTTP/1.1). A session idle for `idleTimeout` milliseconds (5000 by
default) is closed, and `tls` (`ca`, `rejectUnauthorized`) applies to it as to DNS over
TLS. A server that does not offer HTTP/2, an `http://` URL, Deno, browsers and Workers go
through `fetch`; pass your own `fetch` to use it everywhere.

### Proxies

Every transport can go through a SOCKS5 or HTTP CONNECT proxy. With `proxy` set nothing
goes around it: a query that cannot go through the proxy fails.

```ts
import { Resolver } from '@aoxborrow/dns';

const resolver = new Resolver({
  servers: ['1.1.1.1'],
  proxy: 'socks5://user:pass@proxy.example:1080',
});
```

| Transport         | Through the proxy                                                                                                                                                     |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| TCP, DNS over TLS | a tunnel to the server; TLS starts inside it                                                                                                                          |
| UDP               | a SOCKS5 UDP association where the proxy offers one, otherwise TCP through the tunnel. The answer's `transport` says which                                            |
| DNS over HTTPS    | on Node, HTTP/2 through a tunnel to the server; a server that does not offer HTTP/2 fails. Elsewhere, pass a `fetch` that uses the proxy. Without one the query fails |

`proxy` can be a function that picks a proxy per server, or returns nothing to leave a
server unproxied. An explicit `connect` wins over `proxy` for TCP and TLS. Credentials
never appear in an error or an event.

On a deployed Cloudflare Worker TLS cannot start inside a tunnel, so the built-in tunnel
carries plain TCP there and nothing else. For DNS over HTTPS through a proxy on Workers,
pass a `fetch` that does its own TLS, such as
[`tunnelfetch`](https://github.com/latentharbor/tunnelfetch); that combination has not
been run with this library.
