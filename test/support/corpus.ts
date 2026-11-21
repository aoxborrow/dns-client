import messages from '../fixtures/messages.json';
import { typeCode } from '../../src/records/index';
import { decodeMessage } from '../../src/wire/index';

// the corpus of DNS responses (test/fixtures/messages.json), as bytes: real responses from
// public zones to the questions in test/fixtures/questions.json, and synthetic ones for the
// record types no public zone serves. scripts/capture-messages.ts writes it. The fixtures
// are imported, not read from disk, so the same tests run where there is no file system

export interface CorpusMessage {
  label: string;
  query: Uint8Array;
  response: Uint8Array;
}

const fromBase64 = (text: string) => Uint8Array.from(Buffer.from(text, 'base64'));

export const CORPUS: CorpusMessage[] = messages.map(entry => ({
  label: entry.label,
  query: fromBase64(entry.query),
  response: fromBase64(entry.response),
}));

// the first response in the corpus that answers this question with records
export function corpusAnswer(name: string, type: string): Uint8Array {
  const found = CORPUS.find(({ query, response }) => {
    const [question] = decodeMessage(query).questions;
    return (
      question.name === name &&
      question.type === typeCode(type) &&
      decodeMessage(response).answers.length > 0
    );
  });
  if (!found) throw new Error(`the corpus has no answer to ${name} ${type}`);
  return found.response;
}

// a small deterministic random source, so a failing fuzz case can be reproduced
export function seededRandom(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state / 0x100000000;
  };
}
