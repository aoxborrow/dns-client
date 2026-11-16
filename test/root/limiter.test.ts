import { afterEach, describe, expect, it, vi } from 'vitest';
import { createPacer } from '../../src/resolvers/limiter';

// the gap the authoritative resolver keeps between queries to one server, and the servers
// it forgets once their turn has passed

afterEach(() => {
  vi.useRealTimers();
});

describe('createPacer', () => {
  it('spaces queries to one server by the gap', async () => {
    vi.useFakeTimers();
    const pace = createPacer(100);
    const started = Date.now();
    const times: number[] = [];
    const all = Promise.all(
      [1, 2, 3].map(() => pace('10.0.0.1').then(() => times.push(Date.now() - started)))
    );
    await vi.advanceTimersByTimeAsync(300);
    await all;
    expect(times).toEqual([0, 100, 200]);
  });

  it('forgets servers whose turn has passed', async () => {
    vi.useFakeTimers();
    const pace = createPacer(50);
    for (let index = 0; index < 1000; index++) await pace(`10.0.${index >> 8}.${index & 255}`);
    expect(pace.size).toBe(1000);
    await vi.advanceTimersByTimeAsync(60);
    await pace('10.9.9.9');
    expect(pace.size).toBe(1);
  });

  it('remembers nothing with no gap', async () => {
    const pace = createPacer(0);
    await pace('10.0.0.1');
    expect(pace.size).toBe(0);
  });
});
