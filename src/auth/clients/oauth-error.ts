import { HttpException, HttpStatus } from '@nestjs/common';

/** The OAuth error body `/auth/token` answers with (spec 0001 section 11, RFC 6749). */
export function oauthError(
  status: HttpStatus,
  error: string,
  description: string,
): HttpException {
  return new HttpException({ error, error_description: description }, status);
}

/** The one answer for every refused assertion, so a caller can't tell which check failed (AC-15). */
export const invalidClient = () =>
  oauthError(
    HttpStatus.UNAUTHORIZED,
    'invalid_client',
    'Client authentication failed',
  );
