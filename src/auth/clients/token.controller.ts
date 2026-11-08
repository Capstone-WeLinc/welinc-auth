import {
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { oauthError } from './oauth-error';
import { AddressThrottlerGuard } from './address-throttler.guard';
import {
  AddressRateLimitedError,
  ClientRateLimitedError,
  TokenEndpointService,
} from './token-endpoint.service';

/**
 * `POST /auth/token` (spec 0002, AC-14). Reads the request through `@Req()`, never a DTO, so the
 * global ValidationPipe doesn't touch it and every error here uses the OAuth body.
 */
@Controller('auth')
export class TokenController {
  constructor(private readonly endpoint: TokenEndpointService) {}

  @Post('token')
  @HttpCode(HttpStatus.OK)
  @UseGuards(AddressThrottlerGuard)
  async token(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    res.setHeader('Cache-Control', 'no-store');
    if (!req.is('application/x-www-form-urlencoded')) {
      throw oauthError(
        HttpStatus.BAD_REQUEST,
        'invalid_request',
        'Send the request as application/x-www-form-urlencoded',
      );
    }
    const form =
      typeof req.body === 'object' && req.body !== null
        ? (req.body as Record<string, unknown>)
        : {};
    try {
      return await this.endpoint.grant(
        form,
        req.ip ?? '',
        req.headers['x-welinc-user-address'],
      );
    } catch (error) {
      if (error instanceof ClientRateLimitedError) {
        res.setHeader('Retry-After', String(error.retryAfterSeconds));
        throw oauthError(
          HttpStatus.TOO_MANY_REQUESTS,
          'rate_limited',
          error instanceof AddressRateLimitedError
            ? 'Too many token requests from this address. Try again later.'
            : 'Too many token requests for this client. Try again later.',
        );
      }
      throw error;
    }
  }
}
