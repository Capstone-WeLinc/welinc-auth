import {
  HttpStatus,
  Injectable,
  UnauthorizedException,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';
import type { SystemType } from '@prisma/client';
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

/** Spec 0013, AC-26: 120 calls a minute per client, like the directory. */
export const PERMISSIONS_READ_LIMIT = { limit: 120, ttlMs: 60_000 };

export const PERMISSIONS_READ = 'permissions.read';

export type PermissionsReadRequest = Request & {
  permissionsClient?: { system: SystemType };
};

const forbidden = (message: string) =>
  coded(HttpStatus.FORBIDDEN, 'FORBIDDEN', message);

/**
 * `GET /auth/permissions/:system` accepts only a system backend's own service token holding
 * `permissions.read` (spec 0013, AC-26). A person's token gets 403. The caller's system is its
 * client's `system`, read on each request; the route then refuses any other system.
 */
@Injectable()
export class PermissionsReadGuard implements CanActivate {
  constructor(
    private readonly tokens: TokenService,
    private readonly prisma: PrismaService,
    @InjectThrottlerStorage() private readonly storage: ThrottlerStorage,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const http = context.switchToHttp();
    const request = http.getRequest<PermissionsReadRequest>();
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
      if (error instanceof TokenRejectedError)
        throw new UnauthorizedException();
      throw error;
    }

    if (token.tokenUse !== 'service') {
      throw forbidden('The permission matrix is for system backends only');
    }
    if (!token.scopes.includes(PERMISSIONS_READ)) {
      throw forbidden(`This token does not hold ${PERMISSIONS_READ}`);
    }

    const client = await this.prisma.oAuthClient.findUnique({
      where: { id: token.clientId },
      select: { isActive: true, system: true },
    });
    if (!client || !client.isActive) throw new UnauthorizedException();
    if (!client.system)
      throw forbidden('This client does not act for a system');

    const hit = await this.storage.increment(
      `permissions:${token.clientId}`,
      PERMISSIONS_READ_LIMIT.ttlMs,
      PERMISSIONS_READ_LIMIT.limit,
      0,
      'permissions',
    );
    if (hit.totalHits > PERMISSIONS_READ_LIMIT.limit) {
      response.setHeader(
        'Retry-After',
        String(Math.max(1, Math.ceil(hit.timeToExpire))),
      );
      throw coded(
        HttpStatus.TOO_MANY_REQUESTS,
        'RATE_LIMITED',
        'Too many permission matrix calls from this client. Try again later.',
      );
    }

    request.permissionsClient = { system: client.system };
    return true;
  }
}
