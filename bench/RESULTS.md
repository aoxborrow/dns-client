# Benchmarks

Written by `bench/run.ts`. Reproduce with `yarn workspace @aoxborrow/dns bench --network`; see `bench/README.md`.

- **Date:** 2026-11-16
- **CPU:** Apple M2 Max, 12 cores
- **OS:** macOS 14.8.5 (Darwin 23.6.0)
- **Node:** v24.14.1
- **Contenders:** dns2 3.1.1, tangerine 2.1.3, dns-packet 5.6.1 (for the fetch DoH client), DiG 9.10.6

Not measured:

- `Bun.dns`: `bun` is not installed on the machine these numbers come from.
- `Deno.resolveDns`: `deno` is not installed on the machine these numbers come from.
- `dnsperf`: `dnsperf` is not installed on the machine these numbers come from.
- `dns-socket`: unmaintained. Its last release, 4.2.2, was published on 2021-05-28; it is not a contender.

## On the fixture server

An in-process server on localhost, UDP, TCP and plain-HTTP DoH on one port each, answering every question with one A record. No network is involved, so this measures the client: building the query, the sockets, matching and decoding the answer. The server shares the thread with the client it is answering, which costs every contender the same. Every query asks a name not asked before, so no cache helps unless the scenario is about the cache.

### Latency

Cold: a new client and its first query, median of 30 (modules already loaded). Warm: 1,000 sequential queries on one client after 300 to settle, per query. The last column is those 1,000 queries end to end.

| Client | Transport | cold ms (median) | cold ms (p95) | warm p50 µs | warm p95 µs | 1,000 sequential, ms |
| :-- | --: | --: | --: | --: | --: | --: |
| @aoxborrow/dns Resolver | UDP | 0.19 | 0.59 | 131 | 192 | 141 |
| @aoxborrow/dns Resolver, TCP pipelined | TCP | 0.26 | 0.50 | 49 | 85 | 57 |
| @aoxborrow/dns Resolver, DoH | DoH | 0.16 | 0.41 | 115 | 204 | 129 |
| @aoxborrow/dns/promises resolve4 | UDP | 0.26 | 0.59 | 175 | 232 | 182 |
| node:dns Resolver (c-ares) | UDP | 0.10 | 0.25 | 65 | 83 | 67 |
| dns2 UDPClient | UDP | 0.25 | 0.47 | 116 | 151 | 120 |
| tangerine (DoH) | DoH | 0.22 | 0.37 | 84 | 140 | 94 |
| fetch + dns-packet (DoH) | DoH | 0.23 | 0.98 | 145 | 224 | 165 |
| `dig`, a process per query | process | 3.5 | n/a | 0 ms* | n/a | n/a |

\* `dig`'s own "Query time", which leaves out starting the process; it reports whole milliseconds.

### Throughput

2,000 queries with at most this many in flight, queries per second (median of 3).

| Client | 10 in flight | 100 in flight | 1,000 in flight |
| :-- | --: | --: | --: |
| @aoxborrow/dns Resolver | 10,656 | 6,939 | 10,179 |
| @aoxborrow/dns Resolver, TCP pipelined | 30,243 | 35,594 | 31,671 |
| @aoxborrow/dns Resolver, DoH | 10,571 | 11,398 | n/a† |
| @aoxborrow/dns/promises resolve4 | 9,024 | 11,300 | 10,158 |
| node:dns Resolver (c-ares) | 30,071 | 34,119 | 32,008 |
| dns2 UDPClient | 11,997 | 7,116 | 13,064 |
| tangerine (DoH) | 17,668 | 19,517 | n/a† |
| fetch + dns-packet (DoH) | 10,525 | 10,744 | n/a† |

† DoH over HTTP/1.1 opens a connection for each query in flight. Past about 128 at once the local server's accept queue (macOS `kern.ipc.somaxconn`) resets connections, which measures the test server, so DoH stops at 100.

### Cache hits

The same name 10,000 times in a row on a client with its cache on, and how many of those queries reached the server.

| Client | answers per second | queries that reached the server |
| :-- | --: | --: |
| @aoxborrow/dns Resolver | 209,841 | 0 |
| @aoxborrow/dns Resolver, TCP pipelined | 207,846 | 0 |
| @aoxborrow/dns Resolver, DoH | 227,129 | 0 |
| @aoxborrow/dns/promises resolve4 | 176,548 | 0 |
| node:dns Resolver (c-ares) | 11,657 | 10,000 |
| dns2 UDPClient | no cache | n/a |
| tangerine (DoH) | 1,335,076 | 0 |
| fetch + dns-packet (DoH) | no cache | n/a |

### Sockets and memory

Run first, in a new process. A new client sends 1,000 queries at once (DoH: 100): the UDP source ports the server saw and the TCP connections it accepted. Then 10,000 more in bursts of 100: the sockets still open after them, and the heap retained after a forced GC with the client still alive. Memory numbers are noisy at this size; read them as orders of magnitude.

| Client | queries at once | UDP source ports | TCP connections | sockets open after | heap retained, KB |
| :-- | --: | --: | --: | --: | --: |
| @aoxborrow/dns Resolver | 1,000 | 1,000 | 0 | 0 | 238 |
| @aoxborrow/dns Resolver, TCP pipelined | 1,000 | 0 | 1 | 0 | 414 |
| @aoxborrow/dns Resolver, DoH | 100 | 0 | 100 | 100 | 6,521 |
| @aoxborrow/dns/promises resolve4 | 1,000 | 1,000 | 0 | 0 | 372 |
| node:dns Resolver (c-ares) | 1,000 | 1 | 0 | 0 | -10 |
| dns2 UDPClient | 1,000 | 1,000 | 0 | 0 | 63 |
| tangerine (DoH) | 100 | 0 | 100 | 100 | 2,510 |
| fetch + dns-packet (DoH) | 100 | 0 | 100 | 100 | 9,515 |

Every query got its answer.

## On the real network

The 100 names in `bench/top-100.ts`, A records, against three public resolvers over UDP and DoH (DoH URLs by IP address). Cold: a new client's first query, median of 10. Sequential: the 100 names one after another on one client. Burst: the 100 names with 20 in flight. Popular names are in every resolver's cache, so this is mostly round-trip time to the resolver; the differences between clients are small next to the network's own variance. One run, from one place: compare rows within a table, not across tables.

### Cloudflare 1.1.1.1

| Client | Transport | cold ms | p50 ms | p95 ms | 100 sequential, ms | 100 in a burst, ms | failed |
| :-- | --: | --: | --: | --: | --: | --: | --: |
| @aoxborrow/dns Resolver | UDP | 16.4 | 13.0 | 96.3 | 2,421 | 202 | 0 |
| @aoxborrow/dns Resolver, TCP pipelined | TCP | 22.5 | 12.1 | 26.0 | 1,370 | 117 | 0 |
| @aoxborrow/dns Resolver, DoH‡ | DoH | 187.1 | 12.3 | 93.1 | 1,934 | 205 | 0 |
| @aoxborrow/dns/promises resolve4 | UDP | 12.4 | 13.0 | 24.3 | 1,642 | 201 | 0 |
| node:dns Resolver (c-ares) | UDP | 11.7 | 11.7 | 21.1 | 1,418 | 200 | 0 |
| dns2 UDPClient | UDP | 13.6 | 14.8 | 144.1 | 3,806 | 218 | 0 |
| tangerine (DoH) | DoH | 17.2 | 18.2 | 152.2 | 4,512 | 177 | 0 |
| fetch + dns-packet (DoH) | DoH | 21.2 | 15.4 | 24.5 | 1,594 | 168 | 0 |
| `dig`, a process per query | process | n/a | 16.1 (query 12) | 26.3 | 1,851 | n/a | 0 |

### Google 8.8.8.8

| Client | Transport | cold ms | p50 ms | p95 ms | 100 sequential, ms | 100 in a burst, ms | failed |
| :-- | --: | --: | --: | --: | --: | --: | --: |
| @aoxborrow/dns Resolver | UDP | 18.2 | 18.3 | 30.7 | 1,927 | 251 | 0 |
| @aoxborrow/dns Resolver, TCP pipelined | TCP | 31.6 | 17.9 | 33.0 | 1,936 | 162 | 0 |
| @aoxborrow/dns Resolver, DoH‡ | DoH | 102.9 | 22.3 | 47.9 | 2,493 | 362 | 0 |
| @aoxborrow/dns/promises resolve4 | UDP | 18.0 | 16.7 | 25.5 | 1,814 | 2,295 | 0 |
| node:dns Resolver (c-ares) | UDP | 16.4 | 16.3 | 22.5 | 1,504 | 245 | 0 |
| dns2 UDPClient | UDP | 17.6 | 17.2 | 148.9 | 3,013 | 594 | 0 |
| tangerine (DoH) | DoH | 53.6 | 57.0 | 216.2 | 7,981 | 348 | 0 |
| fetch + dns-packet (DoH) | DoH | 18.6 | 18.0 | 25.0 | 1,628 | 366 | 0 |
| `dig`, a process per query | process | n/a | 20.8 (query 16) | 28.3 | 1,939 | n/a | 0 |

### Quad9 9.9.9.9

| Client | Transport | cold ms | p50 ms | p95 ms | 100 sequential, ms | 100 in a burst, ms | failed |
| :-- | --: | --: | --: | --: | --: | --: | --: |
| @aoxborrow/dns Resolver | UDP | 9.4 | 10.8 | 181.0 | 4,309 | 1,806 | 0 |
| @aoxborrow/dns Resolver, TCP pipelined | TCP | 152.5 | 10.6 | 150.5 | 3,133 | 80 | 0 |
| @aoxborrow/dns Resolver, DoH‡ | DoH | 43.7 | 11.9 | 150.6 | 2,588 | 138 | 0 |
| @aoxborrow/dns/promises resolve4 | UDP | 9.0 | 8.9 | 12.4 | 926 | 68 | 0 |
| node:dns Resolver (c-ares) | UDP | 8.1 | 9.1 | 123.1 | 1,635 | 83 | 0 |
| dns2 UDPClient | UDP | 8.4 | 8.7 | 11.8 | 901 | 90 | 0 |
| tangerine (DoH) | DoH | 10.2 | 11.3 | 145.9 | 3,504 | 354 | 0 |
| fetch + dns-packet (DoH) | DoH | 185.5 | 38.5 | 180.8 | 5,665 | 393 | 210 |
| `dig`, a process per query | process | n/a | 14.0 (query 10) | 21.5 | 1,537 | n/a | 0 |

DoH failures here are HTTP 505s: some of this resolver's sites answer only HTTP/2, as RFC 8484 §5.2 recommends, and the clients built on Node's own `fetch` speak HTTP/1.1. tangerine brings undici 8, which negotiates HTTP/2. `@aoxborrow/dns` now sends DoH over HTTP/2 with `node:http2` on Node.

‡ Re-run on its own on the same day, after DoH on Node moved from `fetch` (HTTP/1.1) to `node:http2`; the other rows are from the full run. Before the change this row failed all 210 queries to Quad9 with HTTP 505, like the `fetch` client. Cold is higher than the `fetch` rows because a new client opens its own TLS connection and HTTP/2 session, where Node's `fetch` keeps one connection pool for the whole process, so its "cold" query reuses a connection an earlier client opened.

### The operating system's resolver

`dns.lookup` cannot be pointed at a server: it asks getaddrinfo, which asks whatever this machine is set up to use, through the system's own cache (mDNSResponder on macOS). After the first pass that cache answers, so this row measures the system cache and the thread pool, not a DNS client.

| Client | cold ms | p50 ms | p95 ms | 100 sequential, ms | 100 in a burst, ms | failed |
| :-- | --: | --: | --: | --: | --: | --: |
| node:dns lookup (getaddrinfo) | 9.5 | 11.34 | 131.50 | 1,950 | 20 | 0 |

### Iterative resolution from the root

Each of the 100 names resolved from the root servers down, over IPv4 UDP, one name at a time. Only this library and `dig +trace` do this; the others ask a recursive resolver. `dig +trace` takes the root server list from the configured resolver and does not reuse anything between names, so it compares with the "new for each name" row.

| Resolver | total, s | per name p50 ms | per name p95 ms | queries per name | failed |
| :-- | --: | --: | --: | --: | --: |
| @aoxborrow/dns AuthoritativeResolver, one for the list (cache shared) | 14.8 | 95 | 541 | 2.8 | 0 |
| @aoxborrow/dns AuthoritativeResolver, new for each name | 19.6 | 134 | 582 | 4.3 | 0 |
| dig +trace, a process per name | 43.2 | 244 | 1,655 | 4.0 | 0 |

## Features

|  | @aoxborrow/dns | node:dns Resolver | node:dns lookup | dns2 | tangerine | Bun.dns | Deno.resolveDns | dig |
| :-- | :-- | :-- | :-- | :-- | :-- | :-- | :-- | :-- |
| UDP | yes | yes | system resolver | yes | no | system resolver | yes | yes |
| TCP | yes, pipelined on request | on truncation only | system resolver | yes | no | system resolver | on truncation only | yes (`+tcp`) |
| DNS over TLS | yes | no | no | no | no | no | no | BIND 9.18+ (`+tls`) |
| DNS over HTTPS | yes | no | no | yes | yes, only | no | no | BIND 9.18+ (`+https`) |
| Iterative resolution from the root | yes (`AuthoritativeResolver`) | no | no | no | no | no | no | `+trace` |
| DNSSEC | primitives: record decoding, signature and DS checks, NSEC/NSEC3 | no | no | record types only | DO bit, reads the resolver's AD flag | no | no | DO bit (`+dnssec`), no validation |
| Cache | yes, by TTL, shared between callers | c-ares query cache | the system's | no | yes, pluggable (Map, Redis) | yes | no | no |
| One query on the wire for callers asking the same thing | yes | no | no | no | no | not documented | no | n/a |
| SOCKS5 and HTTP CONNECT proxies | yes | no | no | no | through its `request` function | no | no | no |
| Browsers and Workers | records, wire and DNSSEC entries anywhere; DoH through `fetch`; TCP on Cloudflare Workers | no | no | no | no | Bun only | Deno only | n/a |
| Typed records | 33 types, every field typed; unknown types as raw data | 12 types in fixed shapes | addresses only | about 20 types | Node's shapes | addresses only | 12 types | text |
| TypeScript | written in it | `@types/node` | `@types/node` | bundled types | bundled types | built in | built in | n/a |
| Runtime dependencies | none | built in | built in | none | 15 | built in | built in | n/a |
| A `node:dns/promises` drop-in | yes (`@aoxborrow/dns/promises`) | it is the original | it is the original | no | yes, over DoH | Bun implements `node:dns` | Deno implements `node:dns` | n/a |

"System resolver" means the client asks the operating system (getaddrinfo), which picks the transport and the servers. c-ares is the C library behind `node:dns`'s resolver; whether its query cache answered in the fixture runs is in the cache table above (a query that reached the server was not answered from a cache).
