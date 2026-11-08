import {
  HttpStatus,
  Injectable,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Request } from 'express';
import { coded } from '../errors';
import { SERVICE_SCOPE_KEY } from '../decorators/service-scope.decorator';
import { RequestAuthenticator, type Caller } from './request-authenticator';

/**
 * Requires a valid access token (spec 0002, AC-8, AC-9). A person's token always passes on to
 * the route; a service token only where the route carries `@ServiceScope()` and the token holds
 * that scope.
 */
@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(
    private readonly authenticator: RequestAuthenticator,
    private readonly reflector: Reflector,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context
      .switchToHttp()
      .getRequest<Request & { user?: Caller }>();
    // Already authenticated by a controller wide JwtAuthGuard: `@SystemAdmin()` on a method adds
    // its own, and the token and session are checked once per request
    if (request.user) return true;
    const caller = await this.authenticator.authenticate(request);

    if (caller.kind === 'service') {
      const scope = this.reflector.getAllAndOverride<string | undefined>(
        SERVICE_SCOPE_KEY,
        [context.getHandler(), context.getClass()],
      );
      if (!scope || !caller.scopes.includes(scope)) {
        throw coded(
          HttpStatus.FORBIDDEN,
          'WRONG_TOKEN_USE',
          'This route does not accept this service token',
        );
      }
    }

    request.user = caller;
    return true;
  }
}
