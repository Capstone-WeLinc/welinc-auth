import { HttpException, HttpStatus } from '@nestjs/common';

const ERROR_NAMES: Partial<Record<number, string>> = {
  [HttpStatus.BAD_REQUEST]: 'Bad Request',
  [HttpStatus.UNAUTHORIZED]: 'Unauthorized',
  [HttpStatus.FORBIDDEN]: 'Forbidden',
  [HttpStatus.CONFLICT]: 'Conflict',
  [HttpStatus.TOO_MANY_REQUESTS]: 'Too Many Requests',
  [HttpStatus.SERVICE_UNAVAILABLE]: 'Service Unavailable',
};

/**
 * Nest's usual error body plus a stable `code` clients branch on (spec 0001 section 11):
 * `{ statusCode, message, error, code }`.
 */
export function coded(
  status: HttpStatus,
  code: string,
  message: string,
  /** Extra facts a client shows, such as `ROLE_IN_USE`'s holder count (suite spec 0018). */
  details?: Record<string, unknown>,
) {
  return new HttpException(
    {
      statusCode: status,
      message,
      error: ERROR_NAMES[status] ?? 'Error',
      code,
      ...(details ? { details } : {}),
    },
    status,
  );
}
