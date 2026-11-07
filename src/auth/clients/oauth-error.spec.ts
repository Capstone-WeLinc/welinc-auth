import { describe, it, expect } from '@jest/globals';
import { HttpStatus } from '@nestjs/common';
import { invalidClient, oauthError } from './oauth-error';

// covers: spec 0002 AC-15 (one answer for every refused assertion)
describe('oauth errors', () => {
  it('shapes the body as an RFC 6749 error with a description', () => {
    const error = oauthError(HttpStatus.BAD_REQUEST, 'invalid_scope', 'No');

    expect(error.getStatus()).toBe(400);
    expect(error.getResponse()).toEqual({
      error: 'invalid_scope',
      error_description: 'No',
    });
  });

  it('answers invalid_client with 401 and the same body every time', () => {
    const first = invalidClient();
    const second = invalidClient();

    expect(first.getStatus()).toBe(401);
    expect(first.getResponse()).toEqual({
      error: 'invalid_client',
      error_description: 'Client authentication failed',
    });
    expect(second.getResponse()).toEqual(first.getResponse());
  });
});
