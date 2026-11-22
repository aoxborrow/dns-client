// capture real DNS responses into test/fixtures/messages.json, the corpus the codec and
// record tests run over. The questions are about public zones (the root, top-level
// domains, the example domains, the IANA, ISC, IETF and CZ.NIC zones, test zones kept
// broken on purpose) and are listed in test/fixtures/questions.json. Record types no
// public zone serves are built here in code, as synthetic messages.
//
//   yarn capture             ask every question again and rewrite the corpus
//   yarn capture <text> ...  ask again only the questions whose label contains one of the
//                            texts, keeping every other message as it is
//
// questions.json is a list of question groups. Each group asks every combination of its
// names, types and servers:
//
//   {
//     "note": "what the group is for",   optional, not read
//     "server": "198.41.0.4",            an IP address, or a list of them
//     "transport": "tcp",                "tcp" (the default) or "udp"
//     "flags": ["do", "nsid"],           optional, any of:
//                                          rd      recursion desired: for a resolver
//                                          cd      checking disabled
//                                          do      DNSSEC OK: ask for the signatures
//                                          nsid    ask for the server's identifier
//                                          noedns  send no OPT record at all
//     "name": "example.com",             a name, or a list of them
//     "type": ["A", "DS"]                a type, or a list of them
//   }
//
// a question's label is `<transport> <server> <name> <type>` and its flags, as in
// `tcp 198.41.0.4 example.com A +do +nsid`; labels must be unique. Every response is kept,
// whatever its code, and a truncated UDP response is kept as it came. A question that
// gets no response keeps the message it had, if any. Responses that are byte-identical
// are kept once
import dgram from 'node:dgram';
import { readFileSync, writeFileSync } from 'node:fs';
import net from 'node:net';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { ResourceRecord } from '../src/index';
import { decodeMessage, encodeMessage, encodeName, encodeQuery } from '../src/wire/index';
import { nsidOption, rcodeName, typeCode } from '../src/records/index';

const TIMEOUT_MS = 5000;
const FLAGS = ['rd', 'cd', 'do', 'nsid', 'noedns'] as const;
type Flag = (typeof FLAGS)[number];

const fixtures = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'test', 'fixtures');
const questionsFile = resolve(fixtures, 'questions.json');
const messagesFile = resolve(fixtures, 'messages.json');

interface QuestionGroup {
  note?: string;
  server: string | string[];
  transport?: 'udp' | 'tcp';
  flags?: Flag[];
  name: string | string[];
  type: string | string[];
}

interface Question {
  label: string;
  server: string;
  transport: 'udp' | 'tcp';
  flags: Flag[];
  name: string;
  type: string;
}

interface Entry {
  label: string;
  query: string;
  response: string;
}

const list = <T>(value: T | T[]): T[] => (Array.isArray(value) ? value : [value]);
const base64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64');

function readQuestions(): Question[] {
  const groups = JSON.parse(readFileSync(questionsFile, 'utf8')) as QuestionGroup[];
  const questions: Question[] = [];
  const labels = new Set<string>();
  for (const group of groups) {
    const transport = group.transport ?? 'tcp';
    const flags = group.flags ?? [];
    if (transport !== 'udp' && transport !== 'tcp') throw new Error(`bad transport ${transport}`);
    for (const flag of flags) if (!FLAGS.includes(flag)) throw new Error(`bad flag ${flag}`);
    for (const server of list(group.server)) {
      if (!net.isIP(server)) throw new Error(`a server is an IP address: ${server}`);
      for (const name of list(group.name)) {
        for (const type of list(group.type)) {
          typeCode(type);
          const label = [transport, server, name, type, ...flags.map(flag => `+${flag}`)].join(' ');
          if (labels.has(label)) throw new Error(`asked twice: ${label}`);
          labels.add(label);
          questions.push({ label, server, transport, flags, name, type });
        }
      }
    }
  }
  return questions;
}

// ID 0, so a capture asked again differs only where the zone did
function queryFor(question: Question): Uint8Array {
  const flags = new Set(question.flags);
  return encodeQuery({
    id: 0,
    name: question.name,
    type: question.type,
    recursionDesired: flags.has('rd'),
    checkingDisabled: flags.has('cd'),
    edns: flags.has('noedns')
      ? false
      : {
          udpPayloadSize: 1232,
          dnssecOk: flags.has('do'),
          options: flags.has('nsid') ? [nsidOption()] : [],
        },
  });
}

function overUdp(server: string, query: Uint8Array): Promise<Uint8Array> {
  return new Promise((done, fail) => {
    const socket = dgram.createSocket(net.isIPv6(server) ? 'udp6' : 'udp4');
    const timer = setTimeout(() => {
      socket.close();
      fail(new Error('timed out'));
    }, TIMEOUT_MS);
    socket.on('message', message => {
      clearTimeout(timer);
      socket.close();
      done(Uint8Array.from(message));
    });
    socket.send(query, 53, server);
  });
}

function overTcp(server: string, query: Uint8Array): Promise<Uint8Array> {
  return new Promise((done, fail) => {
    const socket = net.connect({ host: server, port: 53 });
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

async function ask(question: Question): Promise<Entry> {
  const query = queryFor(question);
  const send = question.transport === 'udp' ? overUdp : overTcp;
  let response: Uint8Array;
  try {
    response = await send(question.server, query);
  } catch {
    // one more try: a dropped packet or a busy server is not worth losing the question to
    response = await send(question.server, query);
  }
  return { label: question.label, query: base64(query), response: base64(response) };
}

// ---------------------------------------------------------------------------
// synthetic messages: types no public zone serves, built from hand-written record data

const hex = (text: string) => Uint8Array.from(Buffer.from(text.replace(/\s+/g, ''), 'hex'));
const name = (text: string) => Buffer.from(encodeName(text)).toString('hex');
const u16 = (value: number) => value.toString(16).padStart(4, '0');
const u32 = (value: number) => value.toString(16).padStart(8, '0');
// stand-in key and signature bytes: 0x01, 0x02, ... as many as asked for
const filler = (length: number) =>
  Array.from({ length }, (_, index) => ((index + 1) & 0xff).toString(16).padStart(2, '0')).join('');

interface Synthetic {
  name: string;
  type: string;
  note: string;
  answers?: Omit<ResourceRecord, 'section'>[];
  additionals?: Omit<ResourceRecord, 'section'>[];
}

const record = (owner: string, type: string, rdata: string, ttl = 3600, cls = 1) => ({
  name: owner,
  type: typeCode(type),
  class: cls,
  ttl,
  rdata: hex(rdata),
});

const A = record('example.org', 'A', 'c0000201', 300);

const SYNTHETIC: Synthetic[] = [
  {
    name: 'example.org',
    type: 'RP',
    note: 'a responsible person (RFC 1183)',
    answers: [
      record('example.org', 'RP', name('hostmaster.example.org') + name('contact.example.org')),
    ],
  },
  {
    name: 'www.old.example.org',
    type: 'A',
    note: 'a DNAME and the CNAME a server synthesizes from it (RFC 6672)',
    answers: [
      record('old.example.org', 'DNAME', name('example.net')),
      record('www.old.example.org', 'CNAME', name('www.example.net'), 0),
    ],
  },
  {
    name: 'example.org',
    type: 'KEY',
    note: 'a KEY record, the DNSKEY layout before DNSSEC split it off (RFC 2535)',
    answers: [record('example.org', 'KEY', '0200 03 0d' + filler(64))],
  },
  {
    name: 'example.org',
    type: 'CERT',
    note: 'a PKIX certificate record (RFC 4398)',
    answers: [record('example.org', 'CERT', u16(1) + u16(0) + '00' + '3003020100')],
  },
  {
    name: 'c93f1e400f26708f98cb19d936620da35eec8f72e57f9eec01c1afd6._openpgpkey.example.org',
    type: 'OPENPGPKEY',
    note: 'an OpenPGP key (RFC 7929)',
    answers: [
      record(
        'c93f1e400f26708f98cb19d936620da35eec8f72e57f9eec01c1afd6._openpgpkey.example.org',
        'OPENPGPKEY',
        '9833 04' + filler(48)
      ),
    ],
  },
  {
    name: 'example.org',
    type: 'A',
    note: 'a response signed with a transaction signature (RFC 8945)',
    answers: [A],
    additionals: [
      record(
        'key.example.org',
        'TSIG',
        name('hmac-sha256') +
          u16(0) +
          u32(1_800_000_000) +
          u16(300) +
          u16(32) +
          filler(32) +
          u16(0) +
          u16(0) +
          u16(0),
        0,
        255
      ),
    ],
  },
  {
    name: 'example.org',
    type: 'AAAA',
    note: 'a response signed with SIG(0) (RFC 2931)',
    answers: [record('example.org', 'AAAA', '20010db8000000000000000000000001', 300)],
    additionals: [
      record(
        '.',
        'SIG',
        u16(0) +
          '0d 00' +
          u32(0) +
          u32(1_800_000_300) +
          u32(1_800_000_000) +
          u16(12345) +
          name('example.org') +
          filler(64),
        0,
        255
      ),
    ],
  },
];

function synthetic(message: Synthetic): Entry {
  const query = encodeQuery({ id: 0, name: message.name, type: message.type, edns: false });
  const response = encodeMessage({
    id: 0,
    flags: { qr: true, aa: true },
    questions: [{ name: message.name, type: typeCode(message.type), class: 1 }],
    answers: (message.answers ?? []).map(rr => ({ ...rr, section: 'answer' as const })),
    additionals: (message.additionals ?? []).map(rr => ({ ...rr, section: 'additional' as const })),
  });
  // a stray decoding error belongs here, not in the tests
  decodeMessage(response);
  return {
    label: `synthetic: ${message.name} ${message.type}, ${message.note}`,
    query: base64(query),
    response: base64(response),
  };
}

// ---------------------------------------------------------------------------

async function main() {
  const filters = process.argv.slice(2);
  const questions = readQuestions();
  let previous = new Map<string, Entry>();
  try {
    const entries = JSON.parse(readFileSync(messagesFile, 'utf8')) as Entry[];
    previous = new Map(entries.map(entry => [entry.label, entry]));
  } catch {
    // first capture: no file yet
  }

  const entries: Entry[] = [];
  for (const question of questions) {
    const old = previous.get(question.label);
    if (filters.length > 0 && !filters.some(text => question.label.includes(text))) {
      if (old) entries.push(old);
      continue;
    }
    try {
      const entry = await ask(question);
      const message = decodeMessage(Buffer.from(entry.response, 'base64'));
      const counts = [message.answers, message.authorities, message.additionals]
        .map(section => section.length)
        .join('/');
      console.log(`${rcodeName(message.rcode).padEnd(8)} ${counts.padEnd(8)} ${question.label}`);
      entries.push(entry);
    } catch (error) {
      console.log(
        `failed   ${question.label}: ${String(error)}${old ? ' (kept the old one)' : ''}`
      );
      if (old) entries.push(old);
    }
  }
  entries.push(...SYNTHETIC.map(synthetic));

  // a response identical to one already kept adds nothing
  const seen = new Set<string>();
  const unique = entries.filter(entry => {
    if (seen.has(entry.response)) return false;
    seen.add(entry.response);
    return true;
  });

  // two-space JSON, which is also how prettier writes it
  writeFileSync(messagesFile, `${JSON.stringify(unique, null, 2)}\n`);
  console.log(`wrote ${unique.length} messages to ${messagesFile}`);
}

void main();
