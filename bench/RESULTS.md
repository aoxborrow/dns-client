# Benchmarks

Written by `bench/run.ts`. Reproduce with `yarn bench --network`; see `bench/README.md`.

- **Date:** 2026-11-22
- **CPU:** AMD EPYC, 2 cores
- **OS:** Linux 6.1.158+
- **Node:** v24.22.3
- **Contenders:** dns2 3.1.1, tangerine 2.1.3, dns-packet 5.6.1 (for the fetch DoH client), DiG 9.18.39-0ubuntu0.24.04.9-Ubuntu

Not measured:

- `Bun.dns`: `bun` is installed, but the harness does not drive it yet.
- `Deno.resolveDns`: `deno` is not installed on the machine these numbers come from.
- `dnsperf`: `dnsperf` is not installed on the machine these numbers come from.
- `dns-socket`: unmaintained. Its last release, 4.2.2, was published on 2021-05-28; it is not a contender.

## On the fixture server

An in-process server on localhost, UDP, TCP and plain-HTTP DoH on one port each, answering every question with one A record. No network is involved, so this measures the client: building the query, the sockets, matching and decoding the answer. The server shares the thread with the client it is answering, which costs every contender the same. Every query asks a name not asked before, so no cache helps unless the scenario is about the cache.

### Latency

Cold: a new client and its first query, median of 30 (modules already loaded). Warm: 1,000 sequential queries on one client after 300 to settle, per query. The last column is those 1,000 queries end to end.

| Client | Transport | cold ms (median) | cold ms (p95) | warm p50 µs | warm p95 µs | 1,000 sequential, ms |
| :-- | --: | --: | --: | --: | --: | --: |
| @aoxborrow/dns Resolver | UDP | 0.27 | 1.64 | 150 | 213 | 187 |
| @aoxborrow/dns Resolver, TCP pipelined | TCP | 0.99 | 3.38 | 85 | 135 | 100 |
| @aoxborrow/dns Resolver, DoH | DoH | 0.38 | 0.51 | 273 | 588 | 348 |
| @aoxborrow/dns/promises resolve4 | UDP | 0.17 | 1.03 | 148 | 257 | 170 |
| node:dns Resolver (c-ares) | UDP | 0.22 | 0.52 | 65 | 163 | 86 |
| dns2 UDPClient | UDP | 0.25 | 0.43 | 68 | 117 | 79 |
| tangerine (DoH) | DoH | 0.27 | 0.55 | 176 | 233 | 207 |
| fetch + dns-packet (DoH) | DoH | 0.38 | 1.50 | 263 | 393 | 316 |
| `dig`, a process per query | process | 31.1 | n/a | 0 ms* | n/a | n/a |

\* `dig`'s own "Query time", which leaves out starting the process; it reports whole milliseconds.

### Throughput

2,000 queries with at most this many in flight, queries per second (median of 3).

| Client | 10 in flight | 100 in flight | 1,000 in flight |
| :-- | --: | --: | --: |
| @aoxborrow/dns Resolver | 6,881 | 6,413 | 7,796 |
| @aoxborrow/dns Resolver, TCP pipelined | 10,638 | 11,389 | 10,612 |
| @aoxborrow/dns Resolver, DoH | 4,113 | 4,330 | n/a† |
| @aoxborrow/dns/promises resolve4 | 6,329 | 6,072 | 6,282 |
| node:dns Resolver (c-ares) | 23,670 | 29,118 | 1,836 |
| dns2 UDPClient | 15,895 | 19,250 | 390 |
| tangerine (DoH) | 9,796 | 10,056 | n/a† |
| fetch + dns-packet (DoH) | 5,217 | 5,228 | n/a† |

† DoH over HTTP/1.1 opens a connection for each query in flight. Past about 128 at once the local server's accept queue (`kern.ipc.somaxconn` on macOS, `net.core.somaxconn` on Linux) resets connections, which measures the test server, so DoH stops at 100.

### Cache hits

The same name 10,000 times in a row on a client with its cache on, and how many of those queries reached the server.

| Client | answers per second | queries that reached the server |
| :-- | --: | --: |
| @aoxborrow/dns Resolver | 113,467 | 0 |
| @aoxborrow/dns Resolver, TCP pipelined | 84,168 | 0 |
| @aoxborrow/dns Resolver, DoH | 146,063 | 0 |
| @aoxborrow/dns/promises resolve4 | 90,589 | 0 |
| node:dns Resolver (c-ares) | 11,296 | 10,000 |
| dns2 UDPClient | no cache | n/a |
| tangerine (DoH) | 787,024 | 0 |
| fetch + dns-packet (DoH) | no cache | n/a |

### Sockets and memory

Run first, in a new process. A new client sends 1,000 queries at once (DoH: 100): the UDP source ports the server saw and the TCP connections it accepted. Then 10,000 more in bursts of 100: the sockets still open after them, and the heap retained after a forced GC with the client still alive. Memory numbers are noisy at this size; read them as orders of magnitude.

| Client | queries at once | UDP source ports | TCP connections | sockets open after | heap retained, KB |
| :-- | --: | --: | --: | --: | --: |
| @aoxborrow/dns Resolver | 1,000 | 978 | 0 | 0 | 174 |
| @aoxborrow/dns Resolver, TCP pipelined | 1,000 | 0 | 1 | 0 | 278 |
| @aoxborrow/dns Resolver, DoH | 100 | 0 | 23 | 9 | 3,773 |
| @aoxborrow/dns/promises resolve4 | 1,000 | 987 | 0 | 0 | 160 |
| node:dns Resolver (c-ares) | 1,000 | 1 | 0 | 0 | 74 |
| dns2 UDPClient | 1,000 | 278 | 0 | 0 | 106 |
| tangerine (DoH) | 100 | 0 | 100 | 100 | 2,604 |
| fetch + dns-packet (DoH) | 100 | 0 | 100 | 100 | 5,550 |

Failed or empty answers: node:dns Resolver (c-ares) 3092, dns2 UDPClient 2996.

## On the real network

The 100 names in `bench/top-100.ts`, A records, against three public resolvers over UDP and DoH (DoH URLs by IP address). Cold: a new client's first query, median of 10. Sequential: the 100 names one after another on one client. Burst: the 100 names with 20 in flight. Popular names are in every resolver's cache, so this is mostly round-trip time to the resolver; the differences between clients are small next to the network's own variance. One run, from one place: compare rows within a table, not across tables.

### Cloudflare 1.1.1.1

| Client | Transport | cold ms | p50 ms | p95 ms | 100 sequential, ms | 100 in a burst, ms | failed |
| :-- | --: | --: | --: | --: | --: | --: | --: |
| @aoxborrow/dns Resolver | UDP | 2.3 | 2.9 | 5.5 | 405 | 136 | 0 |
| @aoxborrow/dns Resolver, TCP pipelined | TCP | 4.6 | 2.3 | 4.8 | 560 | 613 | 0 |
| @aoxborrow/dns Resolver, DoH | DoH | 17.8 | 4.5 | 7.9 | 654 | 265 | 0 |
| @aoxborrow/dns/promises resolve4 | UDP | 2.4 | 2.9 | 10.5 | 426 | 228 | 0 |
| node:dns Resolver (c-ares) | UDP | 2.1 | 2.4 | 11.1 | 567 | 76 | 0 |
| dns2 UDPClient | UDP | 2.0 | 2.6 | 12.0 | 696 | 205 | 0 |
| tangerine (DoH) | DoH | 4.1 | 3.9 | 13.9 | 698 | 160 | 0 |
| fetch + dns-packet (DoH) | DoH | 5.1 | 4.1 | 6.6 | 622 | 383 | 0 |
| `dig`, a process per query | process | n/a | 34.8 (query 4) | 47.2 | 3,765 | n/a | 0 |

### Google 8.8.8.8

| Client | Transport | cold ms | p50 ms | p95 ms | 100 sequential, ms | 100 in a burst, ms | failed |
| :-- | --: | --: | --: | --: | --: | --: | --: |
| @aoxborrow/dns Resolver | UDP | 8.6 | 15.4 | 225.5 | 3,917 | 48 | 0 |
| @aoxborrow/dns Resolver, TCP pipelined | TCP | 11.9 | 10.4 | 37.7 | 1,707 | 300 | 0 |
| @aoxborrow/dns Resolver, DoH | DoH | 26.6 | 11.8 | 29.9 | 1,561 | 329 | 0 |
| @aoxborrow/dns/promises resolve4 | UDP | 0.7 | 0.4 | 0.6 | 43 | 23 | 0 |
| node:dns Resolver (c-ares) | UDP | 0.2 | 0.2 | 0.2 | 18 | 4 | 0 |
| dns2 UDPClient | UDP | 0.4 | 0.3 | 0.4 | 48 | 13 | 0 |
| tangerine (DoH) | DoH | 12.2 | 11.4 | 38.1 | 1,523 | 280 | 0 |
| fetch + dns-packet (DoH) | DoH | 18.3 | 11.6 | 41.2 | 1,586 | 328 | 0 |
| `dig`, a process per query | process | n/a | 31.3 (query 0) | 43.4 | 3,574 | n/a | 0 |

### Quad9 9.9.9.9

| Client | Transport | cold ms | p50 ms | p95 ms | 100 sequential, ms | 100 in a burst, ms | failed |
| :-- | --: | --: | --: | --: | --: | --: | --: |
| @aoxborrow/dns Resolver | UDP | 2.5 | 72.4 | 2,379.6 | 52,721 | 5,885 | 4 |
| @aoxborrow/dns Resolver, TCP pipelined | TCP | 8.1 | 5.9 | 140.0 | 2,476 | 5,040 | 8 |
| @aoxborrow/dns Resolver, DoH | DoH | 13.3 | 2.1 | 3,017.5 | 20,653 | 3,838 | 0 |
| @aoxborrow/dns/promises resolve4 | UDP | 5.2 | 4.5 | 2,098.1 | 42,298 | 1,401 | 2 |
| node:dns Resolver (c-ares) | UDP | 1.0 | 2.1 | 1,001.3 | 13,916 | 2,803 | 26 |
| dns2 UDPClient | UDP | 2.0 | 2.2 | 1,463.5 | 23,629 | 5,043 | 3 |
| tangerine (DoH) | DoH | 12.3 | 13.4 | 19.2 | 1,391 | 385 | 210 |
| fetch + dns-packet (DoH) | DoH | 12.3 | 14.8 | 20.8 | 1,546 | 445 | 210 |
| `dig`, a process per query | process | n/a | 244.1 (query 216) | 2,961.8 | 57,798 | n/a | 2 |

DoH failures here are HTTP 505s: some of this resolver's sites answer only HTTP/2, as RFC 8484 §5.2 recommends, and the clients built on Node's own `fetch` speak HTTP/1.1. tangerine brings undici 8, which negotiates HTTP/2. `@aoxborrow/dns` takes a `fetch` option for a client that does.

### The operating system's resolver

`dns.lookup` cannot be pointed at a server: it asks getaddrinfo, which asks whatever this machine is set up to use, through the system's own cache (mDNSResponder on macOS). After the first pass that cache answers, so this row measures the system cache and the thread pool, not a DNS client.

| Client | cold ms | p50 ms | p95 ms | 100 sequential, ms | 100 in a burst, ms | failed |
| :-- | --: | --: | --: | --: | --: | --: |
| node:dns lookup (getaddrinfo) | 7.2 | 0.72 | 55.47 | 1,738 | 28 | 0 |

### Iterative resolution from the root

Each of the 100 names resolved from the root servers down, over IPv4 UDP, one name at a time. Only this library and `dig +trace` do this; the others ask a recursive resolver. `dig +trace` takes the root server list from the configured resolver and does not reuse anything between names, so it compares with the "new for each name" row.

| Resolver | total, s | per name p50 ms | per name p95 ms | queries per name | failed |
| :-- | --: | --: | --: | --: | --: |
| @aoxborrow/dns AuthoritativeResolver, one for the list (cache shared) | 13.1 | 48 | 289 | 3.2 | 0 |
| @aoxborrow/dns AuthoritativeResolver, new for each name | 17.6 | 104 | 331 | 4.9 | 0 |
| dig +trace, a process per name | 36.8 | 197 | 1,333 | 4.0 | 0 |

## Features

|  | @aoxborrow/dns | node:dns Resolver | node:dns lookup | dns2 | tangerine | Bun.dns | Deno.resolveDns | dig |
| :-- | :-- | :-- | :-- | :-- | :-- | :-- | :-- | :-- |
| UDP | yes | yes | system resolver | yes | no | system resolver | yes | yes |
| TCP | yes, pipelined on request | on truncation only | system resolver | yes | no | system resolver | on truncation only | yes (`+tcp`) |
| DNS over TLS | yes | no | no | no | no | no | no | BIND 9.18+ (`+tls`) |
| DNS over HTTPS | yes | no | no | yes | yes, only | no | no | BIND 9.18+ (`+https`) |
| Iterative resolution from the root | yes (`AuthoritativeResolver`) | no | no | no | no | no | no | `+trace` |
| DNSSEC | validation (`validate: true`), and the primitives it is built from | no | no | record types only | DO bit, reads the resolver's AD flag | no | no | DO bit (`+dnssec`), no validation |
| Cache | yes, by TTL, shared between callers | no (Node turns c-ares's cache off) | the system's | no | yes, pluggable (Map, Redis) | yes | no | no |
| One query on the wire for callers asking the same thing | yes | no | no | no | no | not documented | no | n/a |
| SOCKS5 and HTTP CONNECT proxies | yes | no | no | no | through its `request` function | no | no | no |
| Browsers and Workers | records, wire and DNSSEC entries anywhere; DoH through `fetch`; TCP on Cloudflare Workers | no | no | no | no | Bun only | Deno only | n/a |
| Typed records | 33 types, every field typed; unknown types as raw data | 12 types in fixed shapes | addresses only | about 20 types | Node's shapes | addresses only | 12 types | text |
| TypeScript | written in it | `@types/node` | `@types/node` | bundled types | bundled types | built in | built in | n/a |
| Runtime dependencies | none | built in | built in | none | 15 | built in | built in | n/a |
| A `node:dns/promises` drop-in | yes (`@aoxborrow/dns/promises`) | it is the original | it is the original | no | yes, over DoH | Bun implements `node:dns` | Deno implements `node:dns` | n/a |

"System resolver" means the client asks the operating system (getaddrinfo), which picks the transport and the servers. c-ares is the C library behind `node:dns`'s resolver. It has a query cache, which Node turns off: in the cache table above every query reaches the server.
