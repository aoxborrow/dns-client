import { describe, expect, it } from 'vitest';
import { DnsError, TimeoutError } from '../src/errors';

describe('DnsError', () => {
  it('writes failures as plain data, though the error is one of them', () => {
    const error = new TimeoutError('no answer from 192.0.2.1', {
      server: '192.0.2.1',
      query: 'example.com',
    });
    const other = new DnsError('refused', { server: '192.0.2.2', rcode: 5 });
    error.failures = [
      { server: '192.0.2.2', error: other },
      { server: '192.0.2.1', error },
    ];
    const data = JSON.parse(JSON.stringify(error));
    expect(data).toMatchObject({
      name: 'TimeoutError',
      message: 'no answer from 192.0.2.1',
      retryable: true,
      server: '192.0.2.1',
      query: 'example.com',
      failures: [
        { server: '192.0.2.2', name: 'DnsError', message: 'refused', rcode: 5 },
        { server: '192.0.2.1', name: 'TimeoutError', message: 'no answer from 192.0.2.1' },
      ],
    });
  });
});
