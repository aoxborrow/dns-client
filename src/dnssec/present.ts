import { decodeRecord } from '../records/decode';
import { formatRecord } from '../records/format';
import type { ResourceRecord } from '../wire/message';

// a record in zone-file presentation format, for the text of a denial proof. Data that
// does not decode is shown in RFC 3597 unknown-type form
export function presentRecord(rr: ResourceRecord): string {
  return formatRecord(decodeRecord(rr));
}
