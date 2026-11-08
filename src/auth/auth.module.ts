import { Module } from '@nestjs/common';
import { ThrottlerModule } from '@nestjs/throttler';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { WellKnownController } from './well-known.controller';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { RolesGuard } from './guards/roles.guard';
import { OptionalJwtAuthGuard } from './guards/optional-jwt-auth.guard';
import { RequestAuthenticator } from './guards/request-authenticator';
import { TokenService } from './tokens/token.service';
import {
  signingKeyRingProvider,
  tokenSettingsProvider,
} from './tokens/token-config';
import SharedModule from '../shared/shared.module';
import {
  AddressThrottlerGuard,
  ADDRESS_LIMIT,
} from './clients/address-throttler.guard';
import { TokenController } from './clients/token.controller';
import { TokenEndpointService } from './clients/token-endpoint.service';
import { sessionSettingsProvider } from './sessions/session-config';
import { SessionService } from './sessions/session.service';
import { UserGrantsService } from './sessions/user-grants.service';
import { AuthorizeService } from './sessions/authorize.service';
import { PortalCsrfGuard } from './sessions/csrf';
import { SsoController } from './sessions/sso.controller';

@Module({
  // The throttler guards /auth/token only, never globally (spec 0002, AC-18)
  imports: [
    SharedModule,
    ThrottlerModule.forRoot({ throttlers: [ADDRESS_LIMIT] }),
  ],
  providers: [
    tokenSettingsProvider,
    signingKeyRingProvider,
    TokenService,
    RequestAuthenticator,
    AuthService,
    JwtAuthGuard,
    OptionalJwtAuthGuard,
    RolesGuard,
    TokenEndpointService,
    AddressThrottlerGuard,
    sessionSettingsProvider,
    SessionService,
    UserGrantsService,
    AuthorizeService,
    PortalCsrfGuard,
  ],
  controllers: [
    AuthController,
    SsoController,
    WellKnownController,
    TokenController,
  ],
})
export default class AuthModule {}
