import { examples, run } from '../support/docs';

// the examples in the README and docs/ that ask real servers (fenced ```ts network): each
// runs to the end without throwing. What they show of an answer (TTLs, addresses, which
// server answered) changes from run to run, so it is not compared
it('runs every example that needs the network', async () => {
  expect(
    await run(
      examples().filter(example => example.network),
      false
    )
  ).toEqual([]);
}, 600_000);
