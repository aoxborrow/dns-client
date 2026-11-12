// capture real DNS responses into test/fixtures/captured.json, for the record types the
// main corpus does not happen to contain.
//
//   yarn capture <name> <type> [<name> <type> ...]
//
// each question goes to a public resolver with recursion and the DO bit on; a truncated
// UDP answer is asked again over TCP. A response with no answer records is not kept.
import dgram from 'node:dgram';
import { readFileSync, writeFileSync } from 'node:fs';
import net from 'node:net';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decodeMessage, encodeQuery, rcodeName, typeName } from '../src/index';

const RESOLVER = '1.1.1.1';
const TIMEOUT_MS = 4000;
const file = resolve(
  dirname(fileURLToPath(import.meta.url)),
  '..',
  'test',
  'fixtures',
  'captured.json'
);

function overUdp(query: Uint8Array): Promise<Uint8Array> {
  return new Promise((done, fail) => {
    const socket = dgram.createSocket('udp4');
    const timer = setTimeout(() => {
      socket.close();
      fail(new Error('timed out'));
    }, TIMEOUT_MS);
    socket.on('message', message => {
      clearTimeout(timer);
      socket.close();
      done(Uint8Array.from(message));
    });
    socket.send(query, 53, RESOLVER);
  });
}

function overTcp(query: Uint8Array): Promise<Uint8Array> {
  return new Promise((done, fail) => {
    const socket = net.connect({ host: RESOLVER, port: 53 });
    let buffered = Buffer.alloc(0);
    socket.setTimeout(TIMEOUT_MS, () => socket.destroy(new Error('timed out')));
    socket.on('error', fail);
    socket.on('connect', () => {
      const framed = Buffer.alloc(2 + query.length);
      framed.writeUInt16BE(query.length, 0);
      framed.set(query, 2);
      socket.write(framed);
    });
    socket.on('data', (chunk: Buffer) => {
      buffered = Buffer.concat([buffered, chunk]);
      if (buffered.length >= 2 && buffered.length >= 2 + buffered.readUInt16BE(0)) {
        socket.destroy();
        done(Uint8Array.from(buffered.subarray(2, 2 + buffered.readUInt16BE(0))));
      }
    });
  });
}

interface Captured {
  label: string;
  query: string;
  response: string;
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length === 0 || args.length % 2 !== 0) {
    console.error('usage: yarn capture <name> <type> [<name> <type> ...]');
    process.exit(1);
  }
  let captured: Captured[] = [];
  try {
    captured = JSON.parse(readFileSync(file, 'utf8')) as Captured[];
  } catch {
    // first capture: no file yet
  }

  for (let i = 0; i < args.length; i += 2) {
    const [name, type] = [args[i], args[i + 1].toUpperCase()];
    // ID 0: the fixtures are keyed without it
    const query = encodeQuery({
      id: 0,
      name,
      type,
      recursionDesired: true,
      edns: { dnssecOk: true },
    });
    try {
      let response = await overUdp(query);
      if (decodeMessage(response).flags.tc) response = await overTcp(query);
      const message = decodeMessage(response);
      const answers = message.answers.map(record => typeName(record.type));
      if (answers.length === 0) {
        console.log(`skipped  ${name} ${type}: ${rcodeName(message.rcode)}, no answers`);
        continue;
      }
      const label = `captured: ${name} ${type}`;
      captured = captured.filter(entry => entry.label !== label);
      captured.push({
        label,
        query: Buffer.from(query).toString('base64'),
        response: Buffer.from(response).toString('base64'),
      });
      console.log(`captured ${name} ${type}: ${answers.join(' ')}`);
    } catch (error) {
      console.log(`failed   ${name} ${type}: ${String(error)}`);
    }
  }

  captured.sort((a, b) => a.label.localeCompare(b.label));
  writeFileSync(file, `[\n${captured.map(entry => JSON.stringify(entry)).join(',\n')}\n]\n`);
}

void main();
