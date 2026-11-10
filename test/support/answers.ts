import { decodeMessage, encodeMessage } from '../../src/wire/index';
import type { EncodableMessage } from '../../src/wire/index';

// build the response a well-behaved server would give to a query: the question echoed
// back and one A record for it. `overrides` replaces any part of that

export const ANSWER_ADDRESS = Uint8Array.of(192, 0, 2, 1);

export function answerTo(query: Uint8Array, overrides: Partial<EncodableMessage> = {}): Uint8Array {
  const asked = decodeMessage(query);
  const [question] = asked.questions;
  return encodeMessage({
    id: asked.id,
    flags: { qr: true, aa: true, rd: asked.flags.rd },
    questions: asked.questions,
    answers: [
      {
        name: question.name,
        type: 1,
        class: 1,
        ttl: 300,
        rdata: ANSWER_ADDRESS,
        section: 'answer',
      },
    ],
    ...overrides,
  });
}

// the name a query asks about
export const askedName = (query: Uint8Array): string => decodeMessage(query).questions[0].name;

// the ID a query carries
export const queryId = (query: Uint8Array): number => (query[0] << 8) | query[1];
