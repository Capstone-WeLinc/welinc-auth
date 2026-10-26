import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

/**
 * Reads a bearer token when one is sent and valid, and never rejects: `req.user` is the caller or
 * null. For public routes that act differently for a signed in admin (spec 0009, AC-20).
 */
@Injectable()
export class OptionalJwtAuthGuard extends AuthGuard('jwt') {
  handleRequest<TUser>(_err: unknown, user: TUser | false): TUser | null {
    return user || null;
  }
}
