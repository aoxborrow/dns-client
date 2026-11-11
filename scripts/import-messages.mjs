// build test/fixtures/messages.json: a corpus of real DNS responses for the codec tests.
//
//   node scripts/import-messages.mjs <directory of recordings>
//
// a recording is a JSON file with an `exchanges` array, each entry holding a base64 `query`
// and `outcomes` with base64 `response`s, as a wire-level recording harness writes it. Only the
// wire bytes are kept. Responses that are byte-identical apart from their ID are kept once.
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const source = process.argv[2];
if (!source) {
  console.error('usage: node scripts/import-messages.mjs <directory of recordings>');
  process.exit(1);
}
const out = resolve(
  dirname(fileURLToPath(import.meta.url)),
  '..',
  'test',
  'fixtures',
  'messages.json'
);

const seen = new Set();
const messages = [];
for (const file of readdirSync(source)
  .filter(name => name.endsWith('.json'))
  .sort()) {
  const recording = JSON.parse(readFileSync(join(source, file), 'utf8'));
  for (const exchange of recording.exchanges ?? []) {
    for (const outcome of exchange.outcomes ?? []) {
      if (!outcome.response) continue;
      const response = Buffer.from(outcome.response, 'base64');
      const key = response.subarray(2).toString('base64');
      if (seen.has(key)) continue;
      seen.add(key);
      messages.push({
        // where it came from, for a readable test failure
        label: `${file.replace(/\.json$/, '')}: ${exchange.transport} ${exchange.server} ${exchange.question}`,
        query: exchange.query,
        response: outcome.response,
      });
    }
  }
}

writeFileSync(out, `[\n${messages.map(message => JSON.stringify(message)).join(',\n')}\n]\n`);
console.log(`wrote ${messages.length} messages to ${out}`);
