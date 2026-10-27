import { describe, it, expect } from '@jest/globals';
import { OptionalJwtAuthGuard } from './optional-jwt-auth.guard';

describe('OptionalJwtAuthGuard', () => {
  const guard = new OptionalJwtAuthGuard();
  const admin = { sub: 'admin-1', email: 'admin@welinc.com' };

  // covers: AC-20 (RESET_SENT only when a valid admin token is sent)
  it('returns the caller when the token was valid', () => {
    expect(guard.handleRequest(null, admin)).toBe(admin);
  });

  it('returns null instead of rejecting when no token was sent', () => {
    expect(guard.handleRequest(null, false)).toBeNull();
  });

  it('returns null instead of throwing when the token was invalid or expired', () => {
    const error = new Error('jwt expired');

    expect(() => guard.handleRequest(error, false)).not.toThrow();
    expect(guard.handleRequest(error, false)).toBeNull();
  });
});
