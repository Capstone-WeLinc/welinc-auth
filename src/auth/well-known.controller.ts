import { Controller, Get, Header, Inject } from '@nestjs/common';
import type { SigningKeyRing } from './keys/signing-keys';
import {
  SIGNING_KEY_RING,
  TOKEN_SETTINGS,
  type TokenSettings,
} from './tokens/token-config';

import { ApiTags } from '@nestjs/swagger';
import { ApiGenericErrors } from '../openapi/decorators';
/** Public discovery routes: no token needed (spec 0002, AC-3, AC-4). */
@ApiTags('Discovery')
@ApiGenericErrors()
@Controller('auth/.well-known')
export class WellKnownController {
  constructor(
    @Inject(SIGNING_KEY_RING) private readonly ring: SigningKeyRing,
    @Inject(TOKEN_SETTINGS) private readonly settings: TokenSettings,
  ) {}

  /** The public part of every `current`, `next` and `retired` key. */
  @Get('jwks.json')
  @Header('Cache-Control', 'public, max-age=300')
  jwks() {
    return this.ring.publicSet;
  }

  /** RFC 8414 metadata, with the code flow of spec 0003. */
  @Get('oauth-authorization-server')
  metadata() {
    const issuer = this.settings.issuer;
    return {
      issuer,
      authorization_endpoint: `${issuer}/authorize`,
      token_endpoint: `${issuer}/token`,
      jwks_uri: `${issuer}/.well-known/jwks.json`,
      grant_types_supported: [
        'authorization_code',
        'refresh_token',
        'client_credentials',
      ],
      response_types_supported: ['code'],
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['private_key_jwt'],
      token_endpoint_auth_signing_alg_values_supported: ['ES256'],
    };
  }
}
