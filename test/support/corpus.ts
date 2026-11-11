import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// the corpus of real DNS responses (test/fixtures/messages.json), as bytes

export interface CorpusMessage {
  label: string;
  query: Uint8Array;
  response: Uint8Array;
}

const fixtures = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'fixtures');

const fromBase64 = (text: string) => Uint8Array.from(Buffer.from(text, 'base64'));

function load(name: string): CorpusMessage[] {
  const entries = JSON.parse(readFileSync(path.join(fixtures, name), 'utf8')) as {
    label: string;
    query: string;
    response: string;
  }[];
  return entries.map(entry => ({
    label: entry.label,
    query: fromBase64(entry.query),
    response: fromBase64(entry.response),
  }));
}

// responses recorded from a resolver walking real delegations
export const CORPUS: CorpusMessage[] = load('messages.json');

// responses captured for the record types the corpus lacks (scripts/capture-messages.ts)
export const CAPTURED: CorpusMessage[] = load('captured.json');

// a small deterministic random source, so a failing fuzz case can be reproduced
export function seededRandom(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state / 0x100000000;
  };
}
