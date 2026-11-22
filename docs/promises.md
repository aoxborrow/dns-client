# The `node:dns/promises` facade

`@aoxborrow/dns/promises` runs on Node.

The `node:dns/promises` API over the library's `Resolver`: the same functions, a
`Resolver` class, the same return shapes, and errors shaped like Node's. Code written for
`node:dns/promises` usually changes only its import; where it differs from Node is listed below.

```ts network
import net from 'node:net';
import { connectLookup, lookup, resolveMx, Resolver } from '@aoxborrow/dns/promises';

await resolveMx('gmail.com'); // [{ exchange: 'gmail-smtp-in.l.google.com', priority: 5, type: 'MX' }, …]
await lookup('example.com'); // { address: '…', family: 4 }

const resolver = new Resolver({ timeout: 2000, tries: 2 });
resolver.setServers(['1.1.1.1', '[2606:4700:4700::1111]:53']);
await resolver.resolve4('example.com', { ttl: true }); // [{ address: '…', ttl: 300 }]

// the callback form `net.connect`, `tls.connect`, `http.Agent` and undici's `connect` take
net.connect({ host: 'example.com', port: 80, lookup: connectLookup });
```

There: `resolve` and every `resolve*` Node has (`resolve4`, `resolve6`, `resolveAny`,
`resolveCaa`, `resolveCname`, `resolveMx`, `resolveNaptr`, `resolveNs`, `resolvePtr`,
`resolveSoa`, `resolveSrv`, `resolveTlsa`, `resolveTxt`), `reverse`, `lookup` with its hints
(`ADDRCONFIG`, `ALL`, `V4MAPPED`), `getServers`, `setServers`, `getDefaultResultOrder`,
`setDefaultResultOrder`, `Resolver` with `cancel()`, and every error-code constant Node has
(`NODATA`, `FORMERR`, `SERVFAIL`, `NOTFOUND`, `NOTIMP`, `REFUSED`, `BADQUERY`, `BADNAME`,
`BADFAMILY`, `BADRESP`, `CONNREFUSED`, `TIMEOUT`, `EOF`, `FILE`, `NOMEM`, `DESTRUCTION`,
`BADSTR`, `BADFLAGS`, `NONAME`, `BADHINTS`, `NOTINITIALIZED`, `LOADIPHLPAPI`,
`ADDRGETNETWORKPARAMS`, `CANCELLED`), the ones the facade never gives included. The
`default` export is all of it as one object, so `import dns from '@aoxborrow/dns/promises'`
works as it does with `node:dns/promises`. Added: `connectLookup`, and `close()` on a
`Resolver`. Not there: `lookupService`, `setLocalAddress`, the `maxTimeout` option.

Where it differs from Node:

- It caches by TTL, as the library's `Resolver` does; Node does not. Pass `cache: false`
  for Node's behaviour.
- Node's `timeout` (milliseconds per attempt) and `tries` (attempts per server) work as in
  Node; `tries: 4` is the library's `retries: 3`. `maxTimeout` is not supported. Every other
  option of the library's `Resolver` is accepted too.
- `lookup` does not call getaddrinfo. It returns an IP address as it is, then reads the
  hosts file, answers `localhost` and names under it with the loopback addresses
  (RFC 6761), and otherwise asks the DNS servers for A and AAAA at once. `ADDRCONFIG` is
  accepted and has no effect.
- `reverse` only asks the DNS servers. Node's reads the hosts file first, so an address
  named there gets the hosts file's name from Node and the PTR record's from this.
- `cancel()` rejects every call in progress with `ECANCELLED`; what was already sent is
  still answered, into the cache.

Errors are plain `Error`s with `code`, `syscall` and `hostname`, as Node's are:

| Code                                           | When                                                                       |
| ---------------------------------------------- | -------------------------------------------------------------------------- |
| `ENOTFOUND`                                    | NXDOMAIN; from `lookup`, also a name with no addresses                     |
| `ENODATA`                                      | NOERROR with an empty answer section                                       |
| `ESERVFAIL`, `EREFUSED`, `EFORMERR`, `ENOTIMP` | the server answered with that rcode                                        |
| `EBADRESP`                                     | any other rcode, or `InvalidResponseError`, `ParseError`, `TruncatedError` |
| `ETIMEOUT`                                     | `TimeoutError`                                                             |
| `ECONNREFUSED`                                 | `ConnectionError`, `ProxyError`, `EmptyResponseError`, `NoServerError`     |
| `EBADNAME`                                     | `InvalidQueryError`                                                        |
| `ECANCELLED`                                   | `cancel()`                                                                 |
| `EAI_AGAIN`                                    | from `lookup`: no server could say whether the name exists                 |

The library error behind a code, when there is one, is its `cause`. These codes exist only
in this entry; the rest of the library has none.

As in Node, a truncated answer whose TCP retry fails is not returned: the call rejects the
way the TCP query failed, `ETIMEOUT` or `ECONNREFUSED`.
