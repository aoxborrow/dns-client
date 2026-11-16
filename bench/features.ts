// what each client can do, beside the numbers. Written by hand from each project's
// documentation and source as of the date in RESULTS.md; `bench/run.ts` appends it to the
// report as it is
export const FEATURES = `## Features

|  | @aoxborrow/dns | node:dns Resolver | node:dns lookup | dns2 | tangerine | Bun.dns | Deno.resolveDns | dig |
| :-- | :-- | :-- | :-- | :-- | :-- | :-- | :-- | :-- |
| UDP | yes | yes | system resolver | yes | no | system resolver | yes | yes |
| TCP | yes, pipelined on request | on truncation only | system resolver | yes | no | system resolver | on truncation only | yes (\`+tcp\`) |
| DNS over TLS | yes | no | no | no | no | no | no | BIND 9.18+ (\`+tls\`) |
| DNS over HTTPS | yes | no | no | yes | yes, only | no | no | BIND 9.18+ (\`+https\`) |
| Iterative resolution from the root | yes (\`AuthoritativeResolver\`) | no | no | no | no | no | no | \`+trace\` |
| DNSSEC | primitives: record decoding, signature and DS checks, NSEC/NSEC3 | no | no | record types only | DO bit, reads the resolver's AD flag | no | no | DO bit (\`+dnssec\`), no validation |
| Cache | yes, by TTL, shared between callers | c-ares query cache | the system's | no | yes, pluggable (Map, Redis) | yes | no | no |
| One query on the wire for callers asking the same thing | yes | no | no | no | no | not documented | no | n/a |
| SOCKS5 and HTTP CONNECT proxies | yes | no | no | no | through its \`request\` function | no | no | no |
| Browsers and Workers | records, wire and DNSSEC entries anywhere; DoH through \`fetch\`; TCP on Cloudflare Workers | no | no | no | no | Bun only | Deno only | n/a |
| Typed records | ${'33'} types, every field typed; unknown types as raw data | 12 types in fixed shapes | addresses only | about 20 types | Node's shapes | addresses only | 12 types | text |
| TypeScript | written in it | \`@types/node\` | \`@types/node\` | bundled types | bundled types | built in | built in | n/a |
| Runtime dependencies | none | built in | built in | none | 15 | built in | built in | n/a |
| A \`node:dns/promises\` drop-in | yes (\`@aoxborrow/dns/promises\`) | it is the original | it is the original | no | yes, over DoH | Bun implements \`node:dns\` | Deno implements \`node:dns\` | n/a |

"System resolver" means the client asks the operating system (getaddrinfo), which picks the transport and the servers. c-ares is the C library behind \`node:dns\`'s resolver; whether its query cache answered in the fixture runs is in the cache table above (a query that reached the server was not answered from a cache).
`;
