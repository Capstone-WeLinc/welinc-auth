import { describe, it, expect } from '@jest/globals';
import type { Request } from 'express';
import { bearerToken } from './request-authenticator';

const req = (authorization?: unknown) =>
  ({ headers: { authorization } }) as unknown as Request;

describe('bearerToken', () => {
  it('returns the token after Bearer', () => {
    expect(bearerToken(req('Bearer abc.def.ghi'))).toBe('abc.def.ghi');
  });

  it('accepts any casing of the scheme and surrounding spaces', () => {
    expect(bearerToken(req('  bearer abc  '))).toBe('abc');
  });

  it.each([undefined, '', 'Bearer', 'Bearer ', 'Basic abc', 'Bearer a b', 42])(
    'returns null for %p',
    (header) => {
      expect(bearerToken(req(header))).toBeNull();
    },
  );
});
