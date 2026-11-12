import captured from '../fixtures/captured.json';
import messages from '../fixtures/messages.json';

// the corpus of real DNS responses (test/fixtures/messages.json), as bytes. The fixtures
// are imported, not read from disk, so the same tests run where there is no file system

export interface CorpusMessage {
  label: string;
  query: Uint8Array;
  response: Uint8Array;
}

const fromBase64 = (text: string) => Uint8Array.from(Buffer.from(text, 'base64'));

function load(entries: { label: string; query: string; response: string }[]): CorpusMessage[] {
  return entries.map(entry => ({
    label: entry.label,
    query: fromBase64(entry.query),
    response: fromBase64(entry.response),
  }));
}

// responses recorded from a resolver walking real delegations
export const CORPUS: CorpusMessage[] = load(messages);

// responses captured for the record types the corpus lacks (scripts/capture-messages.ts)
export const CAPTURED: CorpusMessage[] = load(captured);

// a small deterministic random source, so a failing fuzz case can be reproduced
export function seededRandom(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state / 0x100000000;
  };
}
