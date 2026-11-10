import { concatBytes } from '../wire/bytes';
import type { Connection } from './types';

// reading a connection a piece at a time, for the handshakes and the HTTP client: take
// exactly n bytes, or everything up to a marker, and leave the rest for whoever reads next

export class ConnectionClosedError extends Error {
  constructor(message = 'connection closed') {
    super(message);
    this.name = 'ConnectionClosedError';
  }
}

export class StreamReader {
  private readonly reader: ReadableStreamDefaultReader<Uint8Array>;
  private buffered: Uint8Array = new Uint8Array(0);
  private ended = false;
  // every byte that has arrived, taken or not
  received = 0;

  constructor(readable: ReadableStream<Uint8Array>) {
    this.reader = readable.getReader();
  }

  // how many bytes have arrived and not been taken
  get pending(): number {
    return this.buffered.length;
  }

  // pull one more chunk; false once the stream has ended
  private async fill(): Promise<boolean> {
    if (this.ended) return false;
    const { done, value } = await this.reader.read();
    if (done) {
      this.ended = true;
      return false;
    }
    if (value.length) {
      this.received += value.length;
      this.buffered = this.buffered.length ? concatBytes([this.buffered, value]) : value;
    }
    return true;
  }

  private take(length: number): Uint8Array {
    const out = this.buffered.subarray(0, length);
    this.buffered = this.buffered.subarray(length);
    return out;
  }

  // exactly `length` bytes
  async read(length: number): Promise<Uint8Array> {
    while (this.buffered.length < length) {
      if (!(await this.fill())) {
        throw new ConnectionClosedError(
          `connection closed after ${this.buffered.length} of ${length} bytes`
        );
      }
    }
    return this.take(length);
  }

  // everything up to and including `marker`. `limit` bounds how much is read looking
  // for it, so a peer that never sends the marker cannot fill memory
  async readUntil(marker: Uint8Array, limit: number): Promise<Uint8Array> {
    let from = 0;
    for (;;) {
      const at = indexOf(this.buffered, marker, from);
      if (at !== -1) return this.take(at + marker.length);
      if (this.buffered.length > limit) {
        throw new Error(`no end of header within ${limit} bytes`);
      }
      // the marker may straddle the next chunk, so step back by its length
      from = Math.max(0, this.buffered.length - marker.length + 1);
      if (!(await this.fill())) {
        throw new ConnectionClosedError(
          this.buffered.length
            ? 'connection closed in the middle of a header'
            : 'connection closed before any data arrived'
        );
      }
    }
  }

  // whatever arrives next, or undefined at the end of the stream
  async readSome(): Promise<Uint8Array | undefined> {
    if (!this.buffered.length && !(await this.fill())) return undefined;
    return this.take(this.buffered.length);
  }

  // everything until the stream ends
  async readAll(): Promise<Uint8Array> {
    while (await this.fill());
    return this.take(this.buffered.length);
  }

  // stop reading and hand the stream back, returning bytes that arrived but were not
  // taken
  release(): Uint8Array {
    this.reader.releaseLock();
    return this.take(this.buffered.length);
  }

  // give up on the stream altogether
  async cancel(): Promise<void> {
    await this.reader.cancel().catch(() => undefined);
  }
}

function indexOf(haystack: Uint8Array, needle: Uint8Array, from: number): number {
  outer: for (let i = from; i <= haystack.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}

// write one chunk to a connection without holding its writer afterwards
export async function writeBytes(connection: Connection, bytes: Uint8Array): Promise<void> {
  const writer = connection.writable.getWriter();
  try {
    await writer.write(bytes);
  } finally {
    writer.releaseLock();
  }
}

export async function closeQuietly(connection: Connection): Promise<void> {
  try {
    await connection.close();
  } catch {
    // already gone
  }
}
