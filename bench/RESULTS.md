# Benchmarks

Written by `bench/run.ts`. Reproduce with `yarn bench --network`; see `bench/README.md`.

- **Date:** 2026-11-22
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
| @aoxborrow/dns Resolver | UDP | 0.24 | 0.42 | 150 | 216 | 159 |
| @aoxborrow/dns Resolver, TCP pipelined | TCP | 0.29 | 0.64 | 56 | 75 | 60 |
| @aoxborrow/dns Resolver, DoH | DoH | 0.18 | 0.37 | 109 | 192 | 127 |
| @aoxborrow/dns/promises resolve4 | UDP | 0.19 | 0.48 | 128 | 180 | 135 |
| node:dns Resolver (c-ares) | UDP | 0.12 | 0.18 | 62 | 81 | 66 |
| dns2 UDPClient | UDP | 0.24 | 0.67 | 156 | 254 | 167 |
| tangerine (DoH) | DoH | 0.19 | 0.29 | 73 | 119 | 81 |
| fetch + dns-packet (DoH) | DoH | 0.23 | 0.82 | 116 | 191 | 133 |
| `dig`, a process per query | process | 2.6 | n/a | 0 ms* | n/a | n/a |

\* `dig`'s own "Query time", which leaves out starting the process; it reports whole milliseconds.

### Throughput

2,000 queries with at most this many in flight, queries per second (median of 3).

| Client | 10 in flight | 100 in flight | 1,000 in flight |
| :-- | --: | --: | --: |
| @aoxborrow/dns Resolver | 9,794 | 12,407 | 11,726 |
| @aoxborrow/dns Resolver, TCP pipelined | 31,102 | 31,456 | 32,352 |
| @aoxborrow/dns Resolver, DoH | 10,890 | 11,258 | n/a† |
| @aoxborrow/dns/promises resolve4 | 11,557 | 8,495 | 12,144 |
| node:dns Resolver (c-ares) | 33,499 | 38,009 | 35,216 |
| dns2 UDPClient | 19,303 | 19,400 | 12,374 |
| tangerine (DoH) | 19,451 | 21,544 | n/a† |
| fetch + dns-packet (DoH) | 11,651 | 12,162 | n/a† |

† DoH over HTTP/1.1 opens a connection for each query in flight. Past about 128 at once the local server's accept queue (`kern.ipc.somaxconn` on macOS, `net.core.somaxconn` on Linux) resets connections, which measures the test server, so DoH stops at 100.

### Cache hits

The same name 10,000 times in a row on a client with its cache on, and how many of those queries reached the server.

| Client | answers per second | queries that reached the server |
| :-- | --: | --: |
| @aoxborrow/dns Resolver | 233,755 | 0 |
| @aoxborrow/dns Resolver, TCP pipelined | 220,191 | 0 |
| @aoxborrow/dns Resolver, DoH | 235,318 | 0 |
| @aoxborrow/dns/promises resolve4 | 211,589 | 0 |
| node:dns Resolver (c-ares) | 13,080 | 10,000 |
| dns2 UDPClient | no cache | n/a |
| tangerine (DoH) | 1,441,996 | 0 |
| fetch + dns-packet (DoH) | no cache | n/a |

### Sockets and memory

Run first, in a new process. A new client sends 1,000 queries at once (DoH: 100): the UDP source ports the server saw and the TCP connections it accepted. Then 10,000 more in bursts of 100: the sockets still open after them, and the heap retained after a forced GC with the client still alive. Memory numbers are noisy at this size; read them as orders of magnitude.

| Client | queries at once | UDP source ports | TCP connections | sockets open after | heap retained, KB |
| :-- | --: | --: | --: | --: | --: |
| @aoxborrow/dns Resolver | 1,000 | 976 | 0 | 0 | 177 |
| @aoxborrow/dns Resolver, TCP pipelined | 1,000 | 0 | 1 | 0 | 259 |
| @aoxborrow/dns Resolver, DoH | 100 | 0 | 23 | 9 | 2,350 |
| @aoxborrow/dns/promises resolve4 | 1,000 | 965 | 0 | 0 | 182 |
| node:dns Resolver (c-ares) | 1,000 | 1 | 0 | 0 | 0 |
| dns2 UDPClient | 1,000 | 1,000 | 0 | 0 | 44 |
| tangerine (DoH) | 100 | 0 | 100 | 100 | 2,440 |
| fetch + dns-packet (DoH) | 100 | 0 | 100 | 100 | 9,538 |

Every query got its answer.

## On the real network

The 100 names in `bench/top-100.ts`, A records, against three public resolvers over UDP and DoH (DoH URLs by IP address). Cold: a new client's first query, median of 10. Sequential: the 100 names one after another on one client. Burst: the 100 names with 20 in flight. Popular names are in every resolver's cache, so this is mostly round-trip time to the resolver; the differences between clients are small next to the network's own variance. One run, from one place: compare rows within a table, not across tables.

### Cloudflare 1.1.1.1

| Client | Transport | cold ms | p50 ms | p95 ms | 100 sequential, ms | 100 in a burst, ms | failed |
| :-- | --: | --: | --: | --: | --: | --: | --: |
| @aoxborrow/dns Resolver | UDP | 8.6 | 8.8 | 19.4 | 1,196 | 253 | 0 |
| @aoxborrow/dns Resolver, TCP pipelined | TCP | 15.8 | 8.3 | 13.9 | 1,118 | 170 | 0 |
| @aoxborrow/dns Resolver, DoH | DoH | 31.0 | 8.8 | 19.5 | 1,087 | 145 | 0 |
| @aoxborrow/dns/promises resolve4 | UDP | 8.4 | 8.9 | 22.4 | 1,313 | 226 | 0 |
| node:dns Resolver (c-ares) | UDP | 7.2 | 7.8 | 13.1 | 1,096 | 218 | 0 |
| dns2 UDPClient | UDP | 7.4 | 8.7 | 12.4 | 1,245 | 166 | 0 |
| tangerine (DoH) | DoH | 9.6 | 10.0 | 18.6 | 1,090 | 82 | 0 |
| fetch + dns-packet (DoH) | DoH | 9.8 | 11.4 | 21.9 | 1,433 | 107 | 0 |
| `dig`, a process per query | process | n/a | 12.8 (query 7) | 24.5 | 1,863 | n/a | 0 |

### Google 8.8.8.8

| Client | Transport | cold ms | p50 ms | p95 ms | 100 sequential, ms | 100 in a burst, ms | failed |
| :-- | --: | --: | --: | --: | --: | --: | --: |
| @aoxborrow/dns Resolver | UDP | 15.7 | 15.4 | 27.9 | 1,594 | 248 | 0 |
| @aoxborrow/dns Resolver, TCP pipelined | TCP | 24.0 | 14.7 | 20.3 | 1,276 | 165 | 0 |
| @aoxborrow/dns Resolver, DoH | DoH | 50.9 | 16.7 | 20.9 | 1,478 | 301 | 0 |
| @aoxborrow/dns/promises resolve4 | UDP | 14.3 | 14.1 | 18.4 | 1,174 | 217 | 0 |
| node:dns Resolver (c-ares) | UDP | 13.2 | 14.1 | 18.4 | 1,347 | 67 | 0 |
| dns2 UDPClient | UDP | 14.2 | 14.6 | 18.7 | 1,215 | 73 | 0 |
| tangerine (DoH) | DoH | 11.3 | 16.9 | 20.0 | 1,410 | 123 | 0 |
| fetch + dns-packet (DoH) | DoH | 8.8 | 14.8 | 19.4 | 1,257 | 145 | 0 |
| `dig`, a process per query | process | n/a | 13.5 (query 9) | 22.9 | 1,555 | n/a | 0 |

### Quad9 9.9.9.9

| Client | Transport | cold ms | p50 ms | p95 ms | 100 sequential, ms | 100 in a burst, ms | failed |
| :-- | --: | --: | --: | --: | --: | --: | --: |
| @aoxborrow/dns Resolver | UDP | 6.9 | 8.4 | 148.2 | 2,168 | 60 | 0 |
| @aoxborrow/dns Resolver, TCP pipelined | TCP | 13.1 | 7.4 | 28.2 | 1,464 | 63 | 0 |
| @aoxborrow/dns Resolver, DoH | DoH | 23.1 | 6.4 | 10.2 | 702 | 84 | 0 |
| @aoxborrow/dns/promises resolve4 | UDP | 6.7 | 6.6 | 9.5 | 683 | 58 | 0 |
| node:dns Resolver (c-ares) | UDP | 7.2 | 6.4 | 16.3 | 1,015 | 47 | 0 |
| dns2 UDPClient | UDP | 6.1 | 6.2 | 9.4 | 655 | 44 | 0 |
| tangerine (DoH) | DoH | 6.0 | 7.0 | 12.5 | 907 | 52 | 0 |
| fetch + dns-packet (DoH) | DoH | 26.0 | 28.0 | 33.8 | 2,965 | 288 | 210 |
| `dig`, a process per query | process | n/a | 11.4 (query 6) | 15.4 | 1,655 | n/a | 0 |

DoH failures here are HTTP 505s: some of this resolver's sites answer only HTTP/2, as RFC 8484 §5.2 recommends, and the clients built on Node's own `fetch` speak HTTP/1.1. tangerine brings undici 8, which negotiates HTTP/2. `@aoxborrow/dns` takes a `fetch` option for a client that does.

### The operating system's resolver

`dns.lookup` cannot be pointed at a server: it asks getaddrinfo, which asks whatever this machine is set up to use, through the system's own cache (mDNSResponder on macOS). After the first pass that cache answers, so this row measures the system cache and the thread pool, not a DNS client.

| Client | cold ms | p50 ms | p95 ms | 100 sequential, ms | 100 in a burst, ms | failed |
| :-- | --: | --: | --: | --: | --: | --: |
| node:dns lookup (getaddrinfo) | 7.4 | 8.38 | 141.01 | 1,897 | 24 | 0 |

### Iterative resolution from the root

Each of the 100 names resolved from the root servers down, over IPv4 UDP, one name at a time. Only this library and `dig +trace` do this; the others ask a recursive resolver. `dig +trace` takes the root server list from the configured resolver and does not reuse anything between names, so it compares with the "new for each name" row.

| Resolver | total, s | per name p50 ms | per name p95 ms | queries per name | failed |
| :-- | --: | --: | --: | --: | --: |
| @aoxborrow/dns AuthoritativeResolver, one for the list (cache shared) | 16.6 | 77 | 373 | 3.3 | 0 |
| @aoxborrow/dns AuthoritativeResolver, new for each name | 15.8 | 138 | 375 | 5.0 | 0 |
| dig +trace, a process per name | 28.9 | 176 | 1,099 | 4.0 | 0 |

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
