import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import * as Sentry from '@sentry/nestjs';
import type { Response } from 'express';
import { coded } from '../errors';

// Spec 0009 error answers (contract 0001 section 11).

/** AC-4: a wrong code with tries left. */
export function invalidCode(attemptsLeft: number): HttpException {
  return new HttpException(
    {
      ...(coded(
        HttpStatus.BAD_REQUEST,
        'INVALID_CODE',
        "That code isn't right",
      ).getResponse() as object),
      attemptsLeft,
    },
    HttpStatus.BAD_REQUEST,
  );
}

/** AC-4, AC-9: an unknown, used, retired or expired code or ticket. */
export const codeExpired = () =>
  coded(
    HttpStatus.BAD_REQUEST,
    'CODE_EXPIRED',
    'That code has expired. Ask for a new one.',
  );

/**
 * AC-5, AC-8: inside the 60 s wait or over 5 sends an hour. Thrown by services; the filter below
 * turns it into 429 `CODE_SEND_LIMIT` with `Retry-After`.
 */
export class CodeSendLimitError extends Error {
  constructor(readonly retryAfter: number) {
    super('code send limit');
  }
}

/** AC-5: the email could not be sent; nothing was kept. 503 `MAIL_FAILED` through the filter. */
export class MailFailedError extends Error {
  constructor() {
    super('mail failed');
  }
}

/**
 * Maps the two errors above for every controller (registered as an app filter in AuthModule).
 * Nest runs this instead of Sentry's catch all filter for them, so the 503 reports itself
 * (VRMS spec 0025, AC-1); the 429 is expected and never reported (AC-2).
 */
@Catch(CodeSendLimitError, MailFailedError)
export class CodeErrorFilter implements ExceptionFilter {
  catch(error: CodeSendLimitError | MailFailedError, host: ArgumentsHost) {
    const res = host.switchToHttp().getResponse<Response>();
    if (error instanceof CodeSendLimitError) {
      const minutes = Math.max(1, Math.ceil(error.retryAfter / 60));
      res
        .status(HttpStatus.TOO_MANY_REQUESTS)
        .setHeader('Retry-After', String(error.retryAfter))
        .json(
          coded(
            HttpStatus.TOO_MANY_REQUESTS,
            'CODE_SEND_LIMIT',
            `Too many codes sent. Try again in ${minutes} minute${minutes === 1 ? '' : 's'}.`,
          ).getResponse(),
        );
      return;
    }
    Sentry.captureException(error, {
      mechanism: { handled: false, type: 'auto.http.nestjs.code_error_filter' },
    });
    res
      .status(HttpStatus.SERVICE_UNAVAILABLE)
      .json(
        coded(
          HttpStatus.SERVICE_UNAVAILABLE,
          'MAIL_FAILED',
          "We couldn't send your code. Try again in a minute.",
        ).getResponse(),
      );
  }
}
