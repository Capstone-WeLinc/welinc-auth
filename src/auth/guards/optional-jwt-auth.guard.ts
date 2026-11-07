import {
  Injectable,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';
import type { Request } from 'express';
import { RequestAuthenticator, type UserCaller } from './request-authenticator';

/**
 * Reads a bearer token when one is sent and valid, and never rejects: `req.user` is the person
 * or null. A token that fails any check, or a service token, counts as no token at all (spec
 * 0002, AC-8). For public routes that act differently for a signed in admin (spec 0009, AC-20).
 */
@Injectable()
export class OptionalJwtAuthGuard implements CanActivate {
  constructor(private readonly authenticator: RequestAuthenticator) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context
      .switchToHttp()
      .getRequest<Request & { user?: UserCaller | null }>();
    request.user = null;
    try {
      const caller = await this.authenticator.authenticate(request);
      if (caller.kind === 'user') request.user = caller;
    } catch {
      // No token, a bad one, or an account that can't sign in: treat the caller as anonymous
    }
    return true;
  }
}
