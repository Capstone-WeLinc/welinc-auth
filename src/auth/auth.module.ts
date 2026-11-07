import { Module } from '@nestjs/common';
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

@Module({
  imports: [SharedModule],
  providers: [
    tokenSettingsProvider,
    signingKeyRingProvider,
    TokenService,
    RequestAuthenticator,
    AuthService,
    JwtAuthGuard,
    OptionalJwtAuthGuard,
    RolesGuard,
  ],
  controllers: [AuthController, WellKnownController],
})
export default class AuthModule {}
