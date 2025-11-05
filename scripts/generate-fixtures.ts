#!/usr/bin/env tsx

/**
 * Generates JSON fixture files for DNS integration tests using UDP transport.
 * Usage: npx tsx scripts/generate-fixtures.ts [server]
 *
 * Examples:
 *   npx tsx scripts/generate-fixtures.ts            # All servers, all domains
 *   npx tsx scripts/generate-fixtures.ts cloudflare # Cloudflare server, all domains
 *   npx tsx scripts/generate-fixtures.ts google     # Google server, all domains
 *
 * Servers: cloudflare, google
 * Outputs to test/fixtures/{server}/{domain}.json with normalized TTL=69.
 * Automatically enables DNSSEC for RRSIG, DNSKEY, NSEC, DS, and related record types.
 */

import { writeFileSync, mkdirSync } from 'fs';
import { join } from 'path';
import { DnsClient, getRecords } from '../src/index.js';
import {
  DNS_TEST_DOMAINS,
  DNS_TEST_SERVER_IPS,
  DNS_TEST_SERVERS,
} from '../test/dns-test-helpers.js';
import type { DnsRecordType } from '../src/types.js';
import { sortObjectKeys } from '../src/utils.js';
import { DNS_TRANSPORT_UDP } from '../src/constants.js';

// fixed TTL value for consistent test fixtures
const TEST_FIXED_TTL = 69;

// process command line arguments
const args = process.argv.slice(2);

// Parse arguments: node generate-fixtures.ts [server]
// server: 'cloudflare' or 'google' (optional, defaults to all UDP servers)

const server = args[0] || '';

// get available UDP servers from test helpers
const availableServers = DNS_TEST_SERVERS.udp;

// validate server parameter if provided
if (server && !availableServers.includes(server)) {
  console.error(`%%% Invalid server '${server}'`);
  console.error(`%%% Valid servers: ${availableServers.join(', ')}`);
  process.exit(1);
}

// determine which servers to process
const serversToProcess = server ? [server] : availableServers;

// always process all domains
const domains = Object.keys(DNS_TEST_DOMAINS);

// determine fixtures directory based on server
function getFixturesDir(serverName: string): string {
  const baseDir = join(process.cwd(), 'test', 'fixtures');
  return join(baseDir, serverName);
}

async function main() {
  console.log(`%%% generate-fixtures::main() - processing domains:`, domains);
  console.log(`%%% using transport: UDP with servers: ${serversToProcess.join(', ')}`);

  // track errors to fail at the end if any critical errors occurred
  let hasErrors = false;
  const errorMessages: string[] = [];

  for (const currentServer of serversToProcess) {
    console.log(`\n%%% processing server: ${currentServer}`);

    // determine target directory
    const fixturesDir = getFixturesDir(currentServer);

    // create fixtures directory if it doesn't exist
    mkdirSync(fixturesDir, { recursive: true });

    for (const domain of domains) {
      try {
        console.log(`%%% processing domain: ${domain} for server: ${currentServer}`);

        // gather all records organized by query type
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const recordsByQueryType: Record<string, any[]> = {};

        // get record types for this specific domain
        const recordTypesForDomain = DNS_TEST_DOMAINS[domain] || [];

        // DNSSEC record types that need dnssec flag
        const dnssecRecordTypes = [
          'RRSIG',
          'NSEC',
          'NSEC3',
          'NSEC3PARAM',
          'CDS',
          'CDNSKEY',
          'DNSKEY',
          'DS',
        ];

        for (const recordType of recordTypesForDomain) {
          try {
            console.log(`%%% querying ${recordType} records for ${domain} using ${currentServer}`);

            // determine if DNSSEC is needed for this record type
            const needsDnssec = dnssecRecordTypes.includes(recordType);

            // get server IP address
            const serverValue = DNS_TEST_SERVER_IPS[currentServer];

            // create DnsClient with appropriate configuration
            const client = new DnsClient({
              transport: DNS_TRANSPORT_UDP,
              server: serverValue,
              flags: needsDnssec ? ['RD', 'DO'] : ['RD'],
              cache: false, // no caching for fixture generation
            });

            // execute query
            const answers = await client.query({
              query: domain,
              types: [recordType as DnsRecordType],
            });

            // initialize array for this query type
            recordsByQueryType[recordType] = [];

            // extract records from answers
            if (answers && answers.length > 0) {
              // check for errors
              const firstAnswer = answers[0];
              if (firstAnswer.error) {
                const errorMsg = `Query error for ${recordType} on ${domain} (${currentServer}): ${firstAnswer.error.message}`;
                console.error(`%%% ERROR: ${errorMsg}`);
                errorMessages.push(errorMsg);
                hasErrors = true;
              } else {
                // extract all records
                const allRecords = getRecords(answers);

                // filter to only records of the requested type
                const recordsOfType = allRecords?.filter(r => r.type === recordType) || [];

                if (recordsOfType.length > 0) {
                  // normalize TTL values for consistent fixtures
                  const normalizedRecords = recordsOfType.map(record => {
                    const normalizedRecord = {
                      ...record,
                      ttl: record.ttl !== undefined ? TEST_FIXED_TTL : undefined,
                    };
                    // sort the fields in each record
                    return sortObjectKeys(normalizedRecord);
                  });
                  recordsByQueryType[recordType].push(...normalizedRecords);
                  console.log(`%%% found ${normalizedRecords.length} ${recordType} records`);
                } else {
                  console.log(`%%% no ${recordType} records found for ${domain}`);
                }
              }
            } else {
              console.log(`%%% no answers returned for ${recordType} on ${domain}`);
            }

            // small delay between record type queries to avoid rate limiting
            await new Promise(resolve => setTimeout(resolve, 100));
          } catch (error) {
            const errorMsg = `Failed to query ${recordType} for ${domain} (${currentServer}): ${error instanceof Error ? error.message : String(error)}`;
            console.error(`%%% ERROR: ${errorMsg}`);
            errorMessages.push(errorMsg);
            hasErrors = true;
            // initialize empty array for failed queries
            recordsByQueryType[recordType] = [];
          }
        }

        // count total records across all query types
        const totalRecords = Object.values(recordsByQueryType).reduce(
          (sum, records) => sum + records.length,
          0
        );

        // convert domain to filename (replace dots with hyphens)
        const filename = domain.replace(/\./g, '-') + '.json';
        const filepath = join(fixturesDir, filename);

        // write records to JSON file organized by query type
        writeFileSync(filepath, JSON.stringify(recordsByQueryType, null, 2));
        console.log(
          `%%% wrote ${totalRecords} records across ${Object.keys(recordsByQueryType).length} query types to ${filepath}`
        );
      } catch (error) {
        const errorMsg = `Error processing domain ${domain} for server ${currentServer}: ${error instanceof Error ? error.message : String(error)}`;
        console.error(`%%% ERROR: ${errorMsg}`);
        errorMessages.push(errorMsg);
        hasErrors = true;
      }
    }
  }

  console.log(`\n%%% generate-fixtures::main() - completed`);

  if (hasErrors) {
    console.error(`\n%%% FIXTURE GENERATION FAILED WITH ${errorMessages.length} ERRORS:`);
    errorMessages.forEach((msg, i) => console.error(`  ${i + 1}. ${msg}`));
    process.exit(1);
  }
}

// run main function
main().catch(error => {
  console.error('%%% Fatal error:', error);
  process.exit(1);
});
