import { HttpStatus, Injectable } from '@nestjs/common';
import { ThrottlerGuard } from '@nestjs/throttler';
import type { Request } from 'express';
import { oauthError } from './oauth-error';

/** 120 a minute per caller address, before any other check on `/auth/token` (AC-18). */
export const ADDRESS_LIMIT = { name: 'default', ttl: 60_000, limit: 120 };

/**
 * The address limit on `/auth/token`, keyed by `req.ip` (the real caller once `trust proxy` is
 * set from `TRUST_PROXY_HOPS`). Answers in the OAuth body; the throttler sets `Retry-After`.
 */
@Injectable()
export class AddressThrottlerGuard extends ThrottlerGuard {
  protected getTracker(req: Record<string, unknown>): Promise<string> {
    return Promise.resolve((req as unknown as Request).ip ?? 'unknown');
  }

  protected throwThrottlingException(): Promise<void> {
    throw oauthError(
      HttpStatus.TOO_MANY_REQUESTS,
      'rate_limited',
      'Too many token requests from this address. Try again later.',
    );
  }
}
