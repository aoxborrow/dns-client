import packet from 'dns-packet';
import type { Answer as PacketRecord, Packet } from 'dns-packet';
import type { Responder } from './fixture-server';

// a small zone served by the fixture server: one name per kind of record `node:dns` can
// ask for, and names that fail in each way a server can fail. Built with dns-packet, an
// encoder independent of the library, so a test against it does not check the library
// with itself

export const ZONE = 'example.test';

const SOA = {
  name: ZONE,
  type: 'SOA',
  ttl: 3600,
  data: {
    mname: `ns1.${ZONE}`,
    rname: `hostmaster.${ZONE}`,
    serial: 2026111601,
    refresh: 7200,
    retry: 900,
    expire: 1209600,
    minimum: 300,
  },
} as const;

export const RECORDS: PacketRecord[] = [
  SOA as PacketRecord,
  { name: ZONE, type: 'NS', ttl: 3600, data: `ns1.${ZONE}` },
  { name: ZONE, type: 'NS', ttl: 3600, data: `ns2.${ZONE}` },
  { name: ZONE, type: 'A', ttl: 300, data: '192.0.2.10' },
  { name: ZONE, type: 'MX', ttl: 300, data: { preference: 10, exchange: `mail.${ZONE}` } },
  { name: ZONE, type: 'MX', ttl: 300, data: { preference: 20, exchange: `mail2.${ZONE}` } },
  { name: ZONE, type: 'TXT', ttl: 300, data: ['v=spf1 -all'] },
  { name: ZONE, type: 'TXT', ttl: 300, data: ['first string', 'second string'] },
  { name: ZONE, type: 'CAA', ttl: 300, data: { flags: 0, tag: 'issue', value: 'ca.example' } },
  {
    name: ZONE,
    type: 'CAA',
    ttl: 300,
    data: { flags: 128, tag: 'iodef', value: 'mailto:security@example.test' },
  },
  { name: `www.${ZONE}`, type: 'A', ttl: 300, data: '192.0.2.1' },
  { name: `www.${ZONE}`, type: 'A', ttl: 200, data: '192.0.2.2' },
  { name: `www.${ZONE}`, type: 'AAAA', ttl: 300, data: '2001:db8::1' },
  { name: `alias.${ZONE}`, type: 'CNAME', ttl: 60, data: `www.${ZONE}` },
  { name: `dangling.${ZONE}`, type: 'CNAME', ttl: 60, data: `gone.${ZONE}` },
  { name: `v4only.${ZONE}`, type: 'A', ttl: 300, data: '192.0.2.4' },
  { name: `v6only.${ZONE}`, type: 'AAAA', ttl: 300, data: '2001:db8::6' },
  // the address the end-to-end tests connect to
  { name: `app.${ZONE}`, type: 'A', ttl: 300, data: '127.0.0.1' },
  {
    name: `_sip._tcp.${ZONE}`,
    type: 'SRV',
    ttl: 300,
    data: { priority: 10, weight: 5, port: 5060, target: `sip.${ZONE}` },
  },
  {
    name: `naptr.${ZONE}`,
    type: 'NAPTR',
    ttl: 300,
    data: {
      order: 100,
      preference: 10,
      flags: 'S',
      services: 'SIP+D2U',
      regexp: '',
      replacement: `_sip._udp.${ZONE}`,
    },
  },
  {
    name: `_443._tcp.www.${ZONE}`,
    type: 'TLSA',
    ttl: 300,
    data: {
      usage: 3,
      selector: 1,
      matchingType: 1,
      certificate: Buffer.from(
        '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
        'hex'
      ),
    },
  } as PacketRecord,
  { name: '1.2.0.192.in-addr.arpa', type: 'PTR', ttl: 300, data: `www.${ZONE}` },
  {
    name: '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa',
    type: 'PTR',
    ttl: 300,
    data: `www.${ZONE}`,
  },
  { name: `ptr.${ZONE}`, type: 'PTR', ttl: 300, data: `www.${ZONE}` },
];

// names that fail: the label at the front says how
const RCODE_BY_LABEL: Record<string, number> = {
  servfail: 2,
  refused: 5,
  formerr: 1,
  notimp: 4,
};

const lower = (name: string) => name.toLowerCase().replace(/\.$/, '');

const inZone = (name: string) => name === ZONE || name.endsWith(`.${ZONE}`);

const reverseZone = (name: string) => name.endsWith('.arpa');

// what the zone's server answers to a question
export function answerQuestion(
  name: string,
  type: string
): Pick<Packet, 'answers' | 'authorities'> & { rcode: number } {
  const asked = lower(name);
  const at = (owner: string) => RECORDS.filter(record => lower(record.name) === owner);
  const answers: PacketRecord[] = [];
  let owner = asked;
  // follow aliases, as a recursive resolver does
  for (let step = 0; step < 8; step++) {
    const here = at(owner);
    if (type === 'ANY') {
      answers.push(...here);
      break;
    }
    const alias = here.find(record => record.type === 'CNAME');
    if (alias && type !== 'CNAME') {
      answers.push(alias);
      owner = lower((alias as { data: string }).data);
      continue;
    }
    answers.push(...here.filter(record => record.type === type));
    break;
  }
  const exists =
    at(owner).length > 0 || RECORDS.some(record => lower(record.name).endsWith(`.${owner}`));
  const rcode = answers.length > 0 || exists ? 0 : 3;
  return { rcode, answers, authorities: answers.length > 0 ? [] : [SOA as PacketRecord] };
}

// the responder for the fixture server
export const zoneResponder: Responder = ({ query }) => {
  const asked = packet.decode(Buffer.from(query));
  const question = asked.questions?.[0];
  if (!question) return undefined;
  const name = lower(question.name);
  const label = name.split('.')[0];
  const flags = packet.RECURSION_DESIRED | packet.RECURSION_AVAILABLE;
  const base = { id: asked.id, type: 'response' as const, questions: asked.questions };

  if (label === 'silent') return undefined;
  if (label === 'garbage')
    return { response: Uint8Array.of(0, 0, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 7) };
  if (label in RCODE_BY_LABEL) {
    return { response: packet.encode({ ...base, flags: flags | RCODE_BY_LABEL[label] }) };
  }
  if (!inZone(name) && !reverseZone(name)) {
    return {
      response: packet.encode({ ...base, flags: flags | 3, authorities: [SOA as PacketRecord] }),
    };
  }
  const { rcode, answers, authorities } = answerQuestion(name, question.type);
  return {
    response: packet.encode({
      ...base,
      flags: flags | packet.AUTHORITATIVE_ANSWER | rcode,
      answers,
      authorities,
    }),
  };
};
