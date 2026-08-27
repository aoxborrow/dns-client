import { DnsClient, type DnsRecordType } from '../src/index';

// process command line arguments
const args = process.argv.slice(2);
const query = args[0] || 'one.com';
const recordType = args[1] || 'A';
// const recordType = args[1] || 'NS';
// const recordType = args[1] || 'CNAME';
const server = args[2] || undefined; // use default server
// const server = args[2] || '1.1.1.1'; // Cloudflare
// const server = args[2] || '8.8.8.8'; // Google
// const server = args[2] || 'k.root-servers.net'; // root
// const server = args[2] || 'k.gtld-servers.net'; // .com TLD

async function main() {
  console.log(`%%% dns-client::main()`, query, recordType, server);
  const tool = new DnsClient();
  const results = await tool.query({
    query,
    types: [recordType as DnsRecordType],
    server,
    // transport: DNS_TRANSPORT_UDP,
    // transport: DNS_TRANSPORT_TCP,
    // transport: DNS_TRANSPORT_DOH,
    // flags: ['RD', 'DO'],
  });
  console.log(`%%% dns-client::results`, JSON.stringify(results, null, 2));
}

void main();
