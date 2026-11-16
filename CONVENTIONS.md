# Conventions

The shapes every entry point of `@aoxborrow/dns` hands back, and what it accepts.

- **Names** have no trailing dot and keep the letter case they were written in: by the
  server, for a name read off the wire, or by the caller, for the name asked about. The root
  is `.`. A name given to the library may have a trailing dot or not, in any case, in
  Unicode or punycode. Compare names with `canonicalName` (lowercase, no trailing dot),
  never with `===`.
- **A server's name** is `serverName`, beside its address in `server`.
- **Header flags** are an object of booleans (`{ rd: true, cd: false, ad: false }`), never
  a list of strings.
- **A response code** is `rcode`, a number, with its mnemonic beside it in `rcodeName`
  (`'NXDOMAIN'`).
- **A point in time** is a `Date` (`timestamp`, `receivedAt`). **A duration** is in
  milliseconds (`elapsed`, `timeout`, `totalTimeout`).
- **A field inside a record** stays as the wire defines it: a TTL in seconds, an RRSIG's
  inception and expiration in seconds since 1970, DNSKEY flags as a number.
- **Answers and results are plain data**: no methods, so they can be copied, cached and
  sent as they are. Functions that read them stand alone (`toDig(answer)`).
- **Problems carry codes**: a validation problem carries a code and its values; an error is
  told apart by its class (and `name`), and carries `retryable`, and `rcode` with
  `rcodeName` when a response caused it. English is in messages and in the docs, not
  something to match on.
