import { jest } from '@jest/globals';
import type { CodeService } from '../codes/code.service';

/**
 * A code service for unit tests that don't look at codes: every issue answers sent, every check
 * a right code (running `onRight`), and nothing is live.
 */
export function fakeCodes(): CodeService {
  return {
    issue: jest.fn(() =>
      Promise.resolve({
        kind: 'sent',
        id: 'code-1',
        expiresAt: new Date(Date.now() + 600_000),
        resendAfter: 60,
      }),
    ),
    check: jest.fn(),
    retireAll: jest.fn(() => Promise.resolve()),
    retire: jest.fn(() => Promise.resolve()),
    liveCode: jest.fn(() => Promise.resolve(null)),
  } as unknown as CodeService;
}
