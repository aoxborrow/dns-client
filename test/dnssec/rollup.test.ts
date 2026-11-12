import { DnssecEngine } from '../../src/dnssec/engine';
import type { DnssecStatus, DnssecZone } from '../../src/dnssec/types';
import { replayTransports } from '../support/replay-transports';

// a name the walk could not ask about leaves a secure verdict in doubt only when it is
// below the zone the verdict is for. A name asked of a zone higher up the walk, which
// then delegated a deeper zone itself, is not on the path that validated.
//
// no recorded zone has a label between two zone cuts that is not a cut itself, so the
// walk's zone-cut step and rollup are reached past `private`, over transports that
// answer nothing

interface Walk {
  discoverZoneCut(
    candidate: string,
    parent: { name: string; serverIps: string[] },
    parentHosts: Record<string, string>
  ): Promise<unknown>;
  rollup(chain: DnssecZone[]): DnssecStatus;
}

const zone = (name: string): DnssecZone => ({ zone: name, status: 'secure' }) as DnssecZone;
const chain = [zone('.'), zone('example'), zone('deep.middle.example')];

function walk(): Walk {
  return new DnssecEngine({
    crossCheck: false,
    transports: replayTransports([]),
  }) as unknown as Walk;
}

describe('the rollup, and names nobody answered about', () => {
  it('keeps a zone secure when the unanswered name was asked of a zone above it', async () => {
    const engine = walk();
    // example's servers did not answer for middle.example, then delegated deep.middle.example
    await engine.discoverZoneCut(
      'middle.example',
      { name: 'example', serverIps: ['192.0.2.1'] },
      {}
    );
    expect(engine.rollup(chain)).toBe('secure');
  });

  it('takes a secure verdict back when the unanswered name is below the zone', async () => {
    const engine = walk();
    await engine.discoverZoneCut(
      'www.deep.middle.example',
      { name: 'deep.middle.example', serverIps: ['192.0.2.1'] },
      {}
    );
    expect(engine.rollup(chain)).toBe('indeterminate');
  });
});
