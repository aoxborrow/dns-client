import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// the corpus of real DNS responses (test/fixtures/messages.json), as bytes

export interface CorpusMessage {
  label: string;
  query: Uint8Array;
  response: Uint8Array;
}

const file = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  'fixtures',
  'messages.json'
);

const fromBase64 = (text: string) => Uint8Array.from(Buffer.from(text, 'base64'));

export const CORPUS: CorpusMessage[] = (
  JSON.parse(readFileSync(file, 'utf8')) as { label: string; query: string; response: string }[]
).map(entry => ({
  label: entry.label,
  query: fromBase64(entry.query),
  response: fromBase64(entry.response),
}));

// a small deterministic random source, so a failing fuzz case can be reproduced
export function seededRandom(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state / 0x100000000;
  };
}
