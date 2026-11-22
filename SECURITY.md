# Security

## Reporting a vulnerability

Report it privately, through GitHub's private vulnerability reporting: on
[the repository](https://github.com/aoxborrow/dns), **Security** → **Report a
vulnerability**. Please don't open a public issue for it.

Say what is affected, how to reproduce it, and what an attacker gains. A recorded response
or a test that shows it helps most.

## What counts

The library reads responses from servers it does not control, so anything a response can
do to it is in scope, for example:

- DNSSEC validation that calls an answer `secure` when it is not
- an answer accepted for a question it does not answer, or from the wrong source
- a response that crashes the process, hangs a query past its timeout, or costs memory or
  CPU out of proportion to its size
- a proxy or TLS setting that is silently ignored

## Supported versions

Fixes go into the latest release. During the 1.0 beta that is the newest
`1.0.0-beta` version.
