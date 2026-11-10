import { HttpStatus } from '@nestjs/common';
import type { ThrottlerStorage } from '@nestjs/throttler';
import type { Request, Response } from 'express';
import { oauthError } from '../clients/oauth-error';
import { coded } from '../errors';
import { PUBLIC_CODE_LIMIT } from './code-config';

/** AC-6 keys: the three old setup and reset routes, and the four sign in step routes. */
export type CodeLimitKey = 'code-public' | 'code-signin';

/**
 * AC-6: 10 calls a minute per client address, counted before any other work (the
 * `mobile.controller.ts` pattern). `req.ip` is the real caller behind the gateway (spec 0008).
 * Over it: 429 with `Retry-After`, coded `RATE_LIMITED`, or `{ "error": "rate_limited" }` on the
 * mobile routes (contract 0001 section 12).
 */
export async function countCodeCall(
  storage: ThrottlerStorage,
  key: CodeLimitKey,
  req: Request,
  res: Response,
  shape: 'coded' | 'mobile' = 'coded',
): Promise<void> {
  const hit = await storage.increment(
    `${key}:${req.ip ?? 'unknown'}`,
    PUBLIC_CODE_LIMIT.ttlMs,
    PUBLIC_CODE_LIMIT.limit,
    0,
    key,
  );
  if (hit.totalHits <= PUBLIC_CODE_LIMIT.limit) return;
  res.setHeader(
    'Retry-After',
    String(Math.max(1, Math.ceil(hit.timeToExpire))),
  );
  const message =
    'Too many code requests from this address. Wait a minute and try again.';
  throw shape === 'mobile'
    ? oauthError(HttpStatus.TOO_MANY_REQUESTS, 'rate_limited', message)
    : coded(HttpStatus.TOO_MANY_REQUESTS, 'RATE_LIMITED', message);
}
