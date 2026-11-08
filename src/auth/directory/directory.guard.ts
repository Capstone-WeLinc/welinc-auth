import {
  HttpStatus,
  Injectable,
  UnauthorizedException,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';
import {
  InjectThrottlerStorage,
  type ThrottlerStorage,
} from '@nestjs/throttler';
import type { Request, Response } from 'express';
import { PrismaService } from '../../shared/prisma.service';
import { coded } from '../errors';
import { bearerToken } from '../guards/request-authenticator';
import {
  TokenRejectedError,
  TokenService,
  type VerifiedToken,
} from '../tokens/token.service';
import type { DirectoryView } from './directory-user';

/** Spec 0005, AC-8: 120 calls a minute per client, counted after the token check. */
export const DIRECTORY_LIMIT = { limit: 120, ttlMs: 60_000 };

export const DIRECTORY_READ = 'directory.read';
export const DIRECTORY_CONTACT = 'directory.contact';

export type DirectoryRequest = Request & { directory?: DirectoryView };

const forbidden = (message: string) =>
  coded(HttpStatus.FORBIDDEN, 'FORBIDDEN', message);

/**
 * The directory routes accept only a backend's own service token (`aud: AUTH`) holding
 * `directory.read` (spec 0005, AC-8). A person's token, an admin's included, gets 403. The
 * caller's system is its client's `system`, read on each request.
 */
@Injectable()
export class DirectoryGuard implements CanActivate {
  constructor(
    private readonly tokens: TokenService,
    private readonly prisma: PrismaService,
    @InjectThrottlerStorage() private readonly storage: ThrottlerStorage,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const http = context.switchToHttp();
    const request = http.getRequest<DirectoryRequest>();
    const response = http.getResponse<Response>();

    const raw = bearerToken(request);
    if (!raw) throw new UnauthorizedException();

    let token: VerifiedToken;
    try {
      token = await this.tokens.verify(raw);
    } catch (error) {
      if (error instanceof TokenRejectedError && error.expired) {
        throw coded(
          HttpStatus.UNAUTHORIZED,
          'TOKEN_EXPIRED',
          'The access token has expired',
        );
      }
      if (error instanceof TokenRejectedError) {
        throw new UnauthorizedException();
      }
      throw error;
    }

    if (token.tokenUse !== 'service') {
      throw forbidden('The directory is for system backends only');
    }
    if (!token.scopes.includes(DIRECTORY_READ)) {
      throw forbidden(`This token does not hold ${DIRECTORY_READ}`);
    }

    const client = await this.prisma.oAuthClient.findUnique({
      where: { id: token.clientId },
      select: { isActive: true, system: true },
    });
    if (!client || !client.isActive) throw new UnauthorizedException();
    if (!client.system) {
      throw forbidden('This client does not act for a system');
    }

    const hit = await this.storage.increment(
      `directory:${token.clientId}`,
      DIRECTORY_LIMIT.ttlMs,
      DIRECTORY_LIMIT.limit,
      0,
      'directory',
    );
    if (hit.totalHits > DIRECTORY_LIMIT.limit) {
      response.setHeader(
        'Retry-After',
        String(Math.max(1, Math.ceil(hit.timeToExpire))),
      );
      throw coded(
        HttpStatus.TOO_MANY_REQUESTS,
        'RATE_LIMITED',
        'Too many directory calls from this client. Try again later.',
      );
    }

    request.directory = {
      system: client.system,
      canSeePhone: token.scopes.includes(DIRECTORY_CONTACT),
    };
    return true;
  }
}
