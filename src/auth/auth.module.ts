import { Module } from '@nestjs/common';
import { APP_FILTER } from '@nestjs/core';
import { ScheduleModule } from '@nestjs/schedule';
import { ThrottlerModule } from '@nestjs/throttler';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { WellKnownController } from './well-known.controller';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { SystemAdminGuard } from './guards/system-admin.guard';
import { CatalogService } from './roles/catalog.service';
import { SystemsController } from './roles/systems.controller';
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
import { LauncherService } from './sessions/launcher';
import { SessionEndController } from './sessions/session-end.controller';
import { MobileController } from './sessions/mobile.controller';
import { SessionsController } from './sessions/sessions.controller';
import { SessionSweeper } from './sessions/session-sweeper';
import { DirectoryController } from './directory/directory.controller';
import { DirectoryGuard } from './directory/directory.guard';
import { DirectoryService } from './directory/directory.service';
import { CodeService } from './codes/code.service';
import { CodeErrorFilter } from './codes/code-errors';
import { SignInStepService } from './codes/sign-in-step.service';
import { AccountEventsService } from './events/account-events.service';
import { GeoService } from './events/geo.service';
import { ActivityController } from './events/activity.controller';
import { PasswordCheckService } from './reauth/password-check.service';
import { DeletionService } from './deletion/deletion.service';
import { DeletionController } from './deletion/deletion.controller';

@Module({
  // The throttler guards /auth/token only, never globally (spec 0002, AC-18)
  imports: [
    SharedModule,
    ThrottlerModule.forRoot({ throttlers: [ADDRESS_LIMIT] }),
    // The hourly session sweep (spec 0003, AC-37)
    ScheduleModule.forRoot(),
  ],
  providers: [
    tokenSettingsProvider,
    signingKeyRingProvider,
    TokenService,
    RequestAuthenticator,
    AuthService,
    JwtAuthGuard,
    OptionalJwtAuthGuard,
    SystemAdminGuard,
    CatalogService,
    TokenEndpointService,
    AddressThrottlerGuard,
    sessionSettingsProvider,
    SessionService,
    UserGrantsService,
    LauncherService,
    AuthorizeService,
    PortalCsrfGuard,
    SessionSweeper,
    DirectoryService,
    DirectoryGuard,
    // Spec 0009: the one code service, the sign in step, and 429/503 for their errors
    CodeService,
    SignInStepService,
    // Spec 0011: the one writer of account_events
    AccountEventsService,
    GeoService,
    // Spec 0012: the password recheck, reauth tokens and deletion requests
    PasswordCheckService,
    DeletionService,
    { provide: APP_FILTER, useClass: CodeErrorFilter },
  ],
  controllers: [
    AuthController,
    SsoController,
    SessionEndController,
    MobileController,
    SessionsController,
    WellKnownController,
    SystemsController,
    TokenController,
    DirectoryController,
    ActivityController,
    DeletionController,
  ],
})
export default class AuthModule {}
