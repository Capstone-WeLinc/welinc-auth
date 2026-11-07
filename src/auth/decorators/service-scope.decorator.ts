import { SetMetadata } from '@nestjs/common';

export const SERVICE_SCOPE_KEY = 'serviceScope';

/**
 * Lets a service token with this scope (and `aud: AUTH`) into the route, besides the user tokens
 * the route already accepts (spec 0002, AC-19). Routes without it answer a service token with
 * 403 `WRONG_TOKEN_USE`.
 */
export const ServiceScope = (scope: string) =>
  SetMetadata(SERVICE_SCOPE_KEY, scope);
