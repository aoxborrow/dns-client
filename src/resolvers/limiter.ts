import { now } from '../transports/runtime';

// three ways a resolver holds itself back: a cap on how many queries are in flight at
// once, a cap on how many are in flight to any one server, and a minimum gap between
// queries to any one server. A query waiting its turn still answers to its caller: it
// stops waiting when its signal aborts, or when the time it was given runs out

// how long a query is willing to wait for its turn
export interface Wait {
  // stop waiting when this aborts, rejecting with its reason
  signal?: AbortSignal;
  // stop waiting at this time, on the clock `now()` reads, rejecting with what `expired`
  // returns
  deadline?: number;
  expired?: () => unknown;
}

export type Limiter = <T>(task: () => Promise<T>, wait?: Wait) => Promise<T>;

// the longest a timer can be set for; anything longer fires at once
const MAX_TIMER = 2_147_483_647;

// wait until `ready` is called, or until `wait` gives up. `enqueue` is handed the
// function that ends the wait, and `dequeue` takes it back when the wait gives up first
function waitFor(
  wait: Wait,
  enqueue: (ready: () => void) => void,
  dequeue: (ready: () => void) => void
): Promise<void> {
  const { signal, deadline, expired } = wait;
  if (signal?.aborted) return Promise.reject(signal.reason);
  const left = deadline === undefined ? Infinity : deadline - now();
  if (left <= 0) return Promise.reject(expired?.());
  return new Promise<void>((resolve, reject) => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const done = () => {
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
    };
    const ready = () => {
      done();
      resolve();
    };
    const giveUp = (reason: unknown) => {
      dequeue(ready);
      done();
      reject(reason);
    };
    const onAbort = () => giveUp(signal?.reason);
    enqueue(ready);
    signal?.addEventListener('abort', onAbort, { once: true });
    if (left <= MAX_TIMER) timer = setTimeout(() => giveUp(expired?.()), left);
  });
}

// a queue of waiting turns, each handed out in the order it came
function waitInLine(line: (() => void)[], wait: Wait | undefined): Promise<void> {
  return waitFor(
    wait ?? {},
    ready => line.push(ready),
    ready => {
      const at = line.indexOf(ready);
      if (at !== -1) line.splice(at, 1);
    }
  );
}

// run at most `max` tasks at a time; the rest wait their turn in the order they came
export function createLimiter(max: number): Limiter {
  if (!Number.isFinite(max) || max <= 0) return task => task();
  let running = 0;
  const waiting: (() => void)[] = [];

  return async (task, wait) => {
    if (running >= max) await waitInLine(waiting, wait);
    running++;
    try {
      return await task();
    } finally {
      running--;
      waiting.shift()?.();
    }
  };
}

export interface Pacer {
  (server: string, wait?: Wait): Promise<void>;
  // the servers it still remembers a time for
  readonly size: number;
}

// wait until `gap` milliseconds have passed since the last query to the same server. A
// burst of questions for one authoritative server then goes out spaced, not all at once.
// A server whose turn has passed is the same as one never asked, so it is forgotten: at
// most once a gap, the map is swept of them, and holds only the servers asked lately
export function createPacer(gap: number): Pacer {
  const next = new Map<string, number>();
  let swept = 0;
  const pace = async (server: string, wait: Wait = {}) => {
    if (gap <= 0) return;
    const now = Date.now();
    if (now - swept >= gap) {
      swept = now;
      for (const [key, at] of next) if (at <= now) next.delete(key);
    }
    const at = Math.max(now, next.get(server) ?? 0);
    next.set(server, at + gap);
    if (at <= now) return;
    let timer: ReturnType<typeof setTimeout> | undefined;
    await waitFor(
      wait,
      ready => (timer = setTimeout(ready, at - now)),
      () => clearTimeout(timer)
    );
  };
  return Object.defineProperty(pace, 'size', { get: () => next.size }) as Pacer;
}

export type KeyedLimiter = <T>(key: string, task: () => Promise<T>, wait?: Wait) => Promise<T>;

// run at most `max` tasks at a time under each key, a server's address. A key is
// forgotten once nothing is running or waiting under it, so the map holds only the
// servers being asked right now
export function createKeyedLimiter(max: number): KeyedLimiter {
  if (!Number.isFinite(max) || max <= 0) return (_key, task) => task();
  const queues = new Map<string, { running: number; waiting: (() => void)[] }>();

  return async (key, task, wait) => {
    let queue = queues.get(key);
    if (!queue) queues.set(key, (queue = { running: 0, waiting: [] }));
    if (queue.running >= max) await waitInLine(queue.waiting, wait);
    queue.running++;
    try {
      return await task();
    } finally {
      queue.running--;
      const next = queue.waiting.shift();
      if (next) next();
      else if (queue.running === 0) queues.delete(key);
    }
  };
}
