import { describe, it, expect } from '@jest/globals';
import { HttpException } from '@nestjs/common';
import {
  ADDRESS_LIMIT,
  AddressThrottlerGuard,
} from './address-throttler.guard';

// covers: spec 0002 AC-18 (120 a minute per caller address, OAuth shaped answer)
describe('AddressThrottlerGuard', () => {
  // The guard's two overrides don't use the injected options, so build it bare.
  const guard = Object.create(AddressThrottlerGuard.prototype) as {
    getTracker(req: Record<string, unknown>): Promise<string>;
    throwThrottlingException(): Promise<void>;
  };

  it('allows 120 requests per minute', () => {
    expect(ADDRESS_LIMIT).toMatchObject({ ttl: 60_000, limit: 120 });
  });

  it('counts per caller address', async () => {
    await expect(guard.getTracker({ ip: '10.0.0.7' })).resolves.toBe(
      '10.0.0.7',
    );
  });

  it('falls back to one shared bucket when the address is unknown', async () => {
    await expect(guard.getTracker({})).resolves.toBe('unknown');
  });

  it('answers 429 in the OAuth error body', () => {
    let caught: unknown;
    try {
      void guard.throwThrottlingException();
    } catch (e) {
      caught = e;
    }

    expect(caught).toBeInstanceOf(HttpException);
    expect((caught as HttpException).getStatus()).toBe(429);
    expect((caught as HttpException).getResponse()).toMatchObject({
      error: 'rate_limited',
    });
  });
});
