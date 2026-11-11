// record the responses behind the offline DNSSEC tests into test/fixtures/dnssec.json.
//
//   yarn run -T tsx scripts/record-dnssec.ts
//
// every zone in test/support/dnssec-cases.ts is analyzed against live DNS through
// transports that keep each response. One clock is used for all of them and saved with the
// responses: signatures are valid for a window of time, so a replay judges them against
// the moment they were recorded, not against today
import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyze } from '../src/dnssec/index';
import { createTransports } from '../src/transports/index';
import type { Transports } from '../src/transports/index';
import type { Transport, TransportName } from '../src/transports/types';
import { ALIAS_INTO_BROKEN_ZONE, DNSSEC_CASES } from '../test/support/dnssec-cases';
import { queryKey } from '../test/support/replay-transports';
import type { RecordedExchange } from '../test/support/replay-transports';

const out = join(dirname(fileURLToPath(import.meta.url)), '..', 'test', 'fixtures', 'dnssec.json');

const live = createTransports();
const recorded = new Map<string, RecordedExchange>();

const recording = (name: TransportName): Transport => ({
  name,
  async send(request) {
    const key = queryKey(name, request.endpoint.host, request.query);
    const [, , query] = key.split(' ');
    const base = { transport: name, server: request.endpoint.host, query };
    // a question already answered gets the same answer again. Servers rotate the order of
    // their records, and the analysis picks a nameserver by that order: with a second
    // answer the recording would hold one path and a replay would take another
    const known = recorded.get(key)?.response;
    if (known !== undefined) {
      const bytes = Uint8Array.from(Buffer.from(known, 'base64'));
      bytes[0] = request.query[0];
      bytes[1] = request.query[1];
      return { bytes, transport: name };
    }
    try {
      const response = await live.get(name).send(request);
      recorded.set(key, { ...base, response: Buffer.from(response.bytes).toString('base64') });
      return response;
    } catch (error) {
      // a failure is kept only where the question never got an answer
      if (!recorded.get(key)?.response) {
        const timedOut = error instanceof Error && error.name === 'TimeoutError';
        recorded.set(key, { ...base, failure: timedOut ? 'timeout' : 'connection' });
      }
      throw error;
    }
  },
  close() {},
});
const transports: Transports = { get: recording, close() {} };

const recordedAt = new Date();
for (const dnssecCase of DNSSEC_CASES) {
  const report = await analyze(dnssecCase.name, { now: recordedAt, transports });
  const slugs = [...new Set(report.findings.map(finding => finding.slug))].join(' ');
  const verdict =
    report.overallStatus === dnssecCase.status ? 'as expected' : `EXPECTED ${dnssecCase.status}`;
  console.log(
    `${dnssecCase.id.padEnd(26)} ${report.overallStatus.padEnd(14)} ${verdict}  ${slugs}`
  );
}
// recorded for one test, not as a case with an expected verdict
const alias = await analyze(ALIAS_INTO_BROKEN_ZONE, { now: recordedAt, transports });
console.log(`${'(alias into a broken zone)'.padEnd(26)} ${alias.overallStatus}`);
live.close();

const exchanges = [...recorded.values()].sort((a, b) =>
  `${a.server} ${a.transport} ${a.query}`.localeCompare(`${b.server} ${b.transport} ${b.query}`)
);
const failures = exchanges.filter(exchange => exchange.response === undefined).length;
// one exchange per line keeps the file reviewable
writeFileSync(
  out,
  `{\n"recordedAt": ${JSON.stringify(recordedAt.toISOString())},\n"exchanges": [\n${exchanges
    .map(exchange => JSON.stringify(exchange))
    .join(',\n')}\n]\n}\n`
);
console.log(`\n${exchanges.length} exchanges (${failures} without an answer) written to ${out}`);
