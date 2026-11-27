import { describe, it, afterEach } from '@jest/globals';
import type {
  CanActivate,
  ExecutionContext,
  INestApplication,
  Type,
} from '@nestjs/common';
import { ValidationPipe } from '@nestjs/common';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { Test } from '@nestjs/testing';
import { ThrottlerModule } from '@nestjs/throttler';
import request from 'supertest';
import { PrismaService } from '../shared/prisma.service';
import { AdminStandingService } from '../auth/admin/admin-standing.service';
import { AuthController } from '../auth/auth.controller';
import { AuthService } from '../auth/auth.service';
import {
  ADDRESS_LIMIT,
  AddressThrottlerGuard,
} from '../auth/clients/address-throttler.guard';
import { TokenController } from '../auth/clients/token.controller';
import { TokenEndpointService } from '../auth/clients/token-endpoint.service';
import { SignInStepService } from '../auth/codes/sign-in-step.service';
import { DeletionService } from '../auth/deletion/deletion.service';
import { DirectoryController } from '../auth/directory/directory.controller';
import { DirectoryGuard } from '../auth/directory/directory.guard';
import { DirectoryService } from '../auth/directory/directory.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { OptionalJwtAuthGuard } from '../auth/guards/optional-jwt-auth.guard';
import { SystemAdminGuard } from '../auth/guards/system-admin.guard';
import { MatrixService } from '../auth/permissions/matrix.service';
import { PermissionsController } from '../auth/permissions/permissions.controller';
import { PermissionsReadGuard } from '../auth/permissions/permissions-read.guard';
import { CatalogService } from '../auth/roles/catalog.service';
import { SystemsController } from '../auth/roles/systems.controller';
import { AuthorizeService } from '../auth/sessions/authorize.service';
import { PortalCsrfGuard } from '../auth/sessions/csrf';
import { LauncherService } from '../auth/sessions/launcher';
import { MobileController } from '../auth/sessions/mobile.controller';
import { SESSION_SETTINGS } from '../auth/sessions/session-config';
import { SessionService } from '../auth/sessions/session.service';
import { SsoController } from '../auth/sessions/sso.controller';
import { UserGrantsService } from '../auth/sessions/user-grants.service';
import { TokenService } from '../auth/tokens/token.service';
import { WellKnownController } from '../auth/well-known.controller';
import { SIGNING_KEY_RING, TOKEN_SETTINGS } from '../auth/tokens/token-config';
import {
  TEST_SETTINGS,
  testRing,
  testSigningJwk,
} from '../auth/testing/test-keys';
import { expectReplyMatches } from './expect-reply';

// covers: VRMS spec 0026 AC-6. Each integration route (AC-5) runs through a testing module with
// its real controller, its guards passed and its services faked with a reply shaped like the real
// service's, and the reply must match the route's schema in the committed docs/openapi.json.

const ID = '6f1c2a3b-4d5e-4f60-8a71-92b3c4d5e6f7';
const ISO = '2026-11-16T08:00:00.000Z';

/** A guard that lets the request through, after setting what the real guard would. */
const pass = (set?: (req: Record<string, unknown>) => void): CanActivate => ({
  canActivate(context: ExecutionContext) {
    set?.(context.switchToHttp().getRequest());
    return true;
  },
});

interface Setup {
  controller: Type<unknown>;
  providers: { provide: unknown; useValue: unknown }[];
  guards?: [Type<unknown>, CanActivate][];
}

let app: INestApplication | undefined;

afterEach(async () => {
  await app?.close();
  app = undefined;
});

/** The controller in a testing module, with the real app's strict pipe. */
async function start({ controller, providers, guards = [] }: Setup) {
  let builder = Test.createTestingModule({
    imports: [ThrottlerModule.forRoot({ throttlers: [ADDRESS_LIMIT] })],
    controllers: [controller],
    providers: providers as never[],
  });
  for (const [guard, fake] of guards) {
    builder = builder.overrideGuard(guard).useValue(fake);
  }
  const moduleRef = await builder.compile();
  const nest = moduleRef.createNestApplication<NestExpressApplication>();
  nest.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );
  await nest.init();
  app = nest;
  return request(nest.getHttpServer());
}

const GRANT_USER = {
  id: ID,
  name: 'VRMS Admin',
  email: 'admin@welinc.com',
  roles: [{ role: 'ADMIN', system: 'VRMS' }],
  systems: ['VRMS'],
  systemRoles: [{ system: 'VRMS', roles: ['ADMIN'] }],
  suiteAdmin: false,
};

/** A user grant answer, as `UserGrantsService.finish` builds it (a web session). */
const USER_TOKENS = {
  access_token: 'access',
  token_type: 'Bearer',
  expires_in: 900,
  refresh_token: 'refresh',
  sid: ID,
  session_expires_at: ISO,
  session_absolute_expires_at: ISO,
  user: GRANT_USER,
};

const DIRECTORY_USER = {
  id: ID,
  name: 'VRMS Admin',
  email: 'admin@welinc.com',
  phone: null,
  picture: null,
  isActive: true,
  deleted: false,
  erased: false,
  roles: ['ADMIN'],
  temporaryRoles: [],
  updatedAt: ISO,
};

describe('the discovery replies', () => {
  const setup = async () => ({
    controller: WellKnownController,
    providers: [
      {
        provide: SIGNING_KEY_RING,
        useValue: await testRing(
          await testSigningJwk('auth-a', 'current'),
          await testSigningJwk('auth-b', 'next'),
        ),
      },
      { provide: TOKEN_SETTINGS, useValue: TEST_SETTINGS },
    ],
  });

  it('GET /auth/.well-known/jwks.json', async () => {
    const res = await (
      await start(await setup())
    )
      .get('/auth/.well-known/jwks.json')
      .expect(200);
    expectReplyMatches(res.body, 'GET /auth/.well-known/jwks.json', 200);
  });

  it('GET /auth/.well-known/oauth-authorization-server', async () => {
    const res = await (
      await start(await setup())
    )
      .get('/auth/.well-known/oauth-authorization-server')
      .expect(200);
    expectReplyMatches(
      res.body,
      'GET /auth/.well-known/oauth-authorization-server',
      200,
    );
  });
});

describe('POST /auth/token reply', () => {
  it('matches for the authorization_code grant', async () => {
    const http = await start({
      controller: TokenController,
      providers: [
        AddressThrottlerGuard as never,
        {
          provide: TokenEndpointService,
          useValue: { grant: () => Promise.resolve(USER_TOKENS) },
        },
      ],
    });
    const res = await http
      .post('/auth/token')
      .type('form')
      .send({
        grant_type: 'authorization_code',
        client_id: 'vrms-web',
        code: 'code',
        redirect_uri: 'http://localhost:3000/vrms/session/callback',
        code_verifier: 'v'.repeat(43),
      })
      .expect(200);
    expectReplyMatches(res.body, 'POST /auth/token', 200);
  });
});

describe('the mobile login replies', () => {
  const STEP = {
    status: 'EMAIL_VERIFICATION_REQUIRED',
    challengeId: 'c'.repeat(43),
    email: 'admin@welinc.com',
    resendAfter: 60,
  };
  const USER = {
    id: ID,
    name: 'VRMS Admin',
    email: 'admin@welinc.com',
    profilePicture: null,
    emailVerified: true,
  };
  const CLIENT = {
    id: 'vmms-mobile',
    system: 'VMMS',
    grants: ['mobile_login'],
  };
  const GRANT = {
    client: CLIENT,
    aud: 'VMMS',
    roles: [],
    grant: { systems: [], systemRoles: [], suiteAdmin: false },
  };

  const setup = (emailVerified: boolean): Setup => ({
    controller: MobileController,
    providers: [
      {
        provide: AuthService,
        useValue: {
          checkCredentials: () =>
            Promise.resolve({ user: { ...USER, emailVerified } }),
          assertCanSignIn: () => Promise.resolve(USER),
          withSignInCheck: (
            _id: string,
            _meta: unknown,
            check: () => Promise<unknown>,
          ) => check(),
        },
      },
      {
        provide: TokenEndpointService,
        useValue: { publicClient: () => Promise.resolve(CLIENT) },
      },
      {
        provide: UserGrantsService,
        useValue: {
          checkMobileGrant: () => Promise.resolve(GRANT),
          startMobile: () =>
            Promise.resolve({
              ...USER_TOKENS,
              session_absolute_expires_at: undefined,
            }),
        },
      },
      {
        provide: SignInStepService,
        useValue: {
          start: () => Promise.resolve(STEP),
          verify: async (
            _c: string,
            _code: string,
            pre: (id: string) => Promise<void>,
          ) => {
            await pre(ID);
            return ID;
          },
        },
      },
    ],
  });

  const login = {
    email: 'admin@welinc.com',
    password: 'password',
    clientId: 'vmms-mobile',
    deviceName: 'Pixel 8',
  };

  it('POST /auth/mobile/login, signed in', async () => {
    const res = await (
      await start(setup(true))
    )
      .post('/auth/mobile/login')
      .send(login)
      .expect(200);
    expectReplyMatches(res.body, 'POST /auth/mobile/login', 200);
  });

  it('POST /auth/mobile/login, the email code step', async () => {
    const res = await (
      await start(setup(false))
    )
      .post('/auth/mobile/login')
      .send(login)
      .expect(200);
    expectReplyMatches(res.body, 'POST /auth/mobile/login', 200);
  });

  it('POST /auth/mobile/login/verify-email', async () => {
    const res = await (
      await start(setup(false))
    )
      .post('/auth/mobile/login/verify-email')
      .send({
        challengeId: STEP.challengeId,
        code: '123456',
        clientId: 'vmms-mobile',
        deviceName: 'Pixel 8',
      })
      .expect(200);
    expectReplyMatches(res.body, 'POST /auth/mobile/login/verify-email', 200);
  });
});

describe('GET /auth/session reply', () => {
  it('matches for a live session', async () => {
    const none = { useValue: {} };
    const http = await start({
      controller: SsoController,
      providers: [
        { provide: AuthService, ...none },
        {
          provide: SessionService,
          useValue: {
            live: () =>
              Promise.resolve({
                id: ID,
                idleExpiresAt: new Date(ISO),
                absoluteExpiresAt: null,
                endedAt: null,
                user: {
                  id: ID,
                  name: 'VRMS Admin',
                  email: 'admin@welinc.com',
                },
              }),
          },
        },
        { provide: AuthorizeService, ...none },
        {
          provide: TokenService,
          useValue: {
            verify: () =>
              Promise.resolve({ tokenUse: 'user', sid: ID, sub: ID }),
          },
        },
        {
          provide: PrismaService,
          useValue: {
            session: {
              findUnique: () =>
                Promise.resolve({
                  userId: ID,
                  user: { isActive: true, deletedAt: null },
                }),
            },
          },
        },
        { provide: LauncherService, ...none },
        { provide: SignInStepService, ...none },
        { provide: AdminStandingService, ...none },
        { provide: SESSION_SETTINGS, ...none },
      ],
      guards: [[PortalCsrfGuard, pass()]],
    });
    const res = await http
      .get('/auth/session')
      .set('Authorization', 'Bearer token')
      .expect(200);
    expectReplyMatches(res.body, 'GET /auth/session', 200);
  });
});

describe('GET /auth/systems reply', () => {
  it('matches the 200 body', async () => {
    const http = await start({
      controller: SystemsController,
      providers: [
        {
          provide: CatalogService,
          useValue: {
            systems: () =>
              Promise.resolve([
                {
                  code: 'VRMS',
                  name: 'Vehicle Repair Management',
                  description: 'Repairs',
                  maxRolesPerUser: null,
                  roles: [
                    {
                      code: 'ADMIN',
                      name: 'Admin',
                      description: 'Runs the system',
                      isSystemAdmin: true,
                    },
                  ],
                },
                {
                  code: 'BMS',
                  name: 'Booking Management',
                  description: 'Bookings',
                  maxRolesPerUser: 1,
                  roles: [],
                },
              ]),
          },
        },
        {
          provide: PrismaService,
          useValue: {
            oAuthClient: {
              findMany: () =>
                Promise.resolve([
                  { system: 'VRMS', webAddress: 'http://localhost:8001' },
                ]),
            },
          },
        },
      ],
    });
    const res = await http.get('/auth/systems').expect(200);
    expectReplyMatches(res.body, 'GET /auth/systems', 200);
  });
});

describe('GET /auth/me reply', () => {
  it('matches for a signed in person', async () => {
    const none = { useValue: {} };
    const http = await start({
      controller: AuthController,
      providers: [
        {
          provide: AuthService,
          useValue: {
            getCurrentUser: () =>
              Promise.resolve({
                id: ID,
                name: 'VRMS Admin',
                email: 'admin@welinc.com',
                emailVerified: true,
                passwordSet: true,
                contact: null,
                profilePicture: null,
                isActive: true,
                isLocked: false,
                lockedAt: null,
                createdAt: ISO,
                updatedAt: ISO,
                roles: [{ role: 'ADMIN', system: 'VRMS' }],
                pendingEmail: null,
              }),
          },
        },
        { provide: DeletionService, ...none },
      ],
      guards: [
        [JwtAuthGuard, pass((req) => (req.user = { sub: ID, system: 'VRMS' }))],
        [SystemAdminGuard, pass()],
        [OptionalJwtAuthGuard, pass()],
      ],
    });
    const res = await http.get('/auth/me').expect(200);
    expectReplyMatches(res.body, 'GET /auth/me', 200);
  });
});

describe('the directory replies', () => {
  const setup: Setup = {
    controller: DirectoryController,
    providers: [
      {
        provide: DirectoryService,
        useValue: {
          listUsers: () =>
            Promise.resolve({
              users: [DIRECTORY_USER, { ...DIRECTORY_USER, phone: '0917' }],
              next: null,
              changesCursor: 'cursor-1',
            }),
          lookup: () =>
            Promise.resolve({ users: [DIRECTORY_USER], missing: [ID] }),
          changes: () =>
            Promise.resolve({
              changes: [
                {
                  cursor: 'cursor-2',
                  type: 'roles_changed',
                  at: ISO,
                  user: DIRECTORY_USER,
                },
              ],
              next: 'cursor-2',
              hasMore: false,
            }),
        },
      },
    ],
    guards: [
      [DirectoryGuard, pass((req) => (req.directory = { system: 'VRMS' }))],
    ],
  };

  it('GET /auth/directory/users', async () => {
    const res = await (
      await start(setup)
    )
      .get('/auth/directory/users')
      .expect(200);
    expectReplyMatches(res.body, 'GET /auth/directory/users', 200);
  });

  it('POST /auth/directory/users/lookup', async () => {
    const res = await (
      await start(setup)
    )
      .post('/auth/directory/users/lookup')
      .send({ ids: [ID] })
      .expect(200);
    expectReplyMatches(res.body, 'POST /auth/directory/users/lookup', 200);
  });

  it('GET /auth/directory/changes', async () => {
    const res = await (
      await start(setup)
    )
      .get('/auth/directory/changes')
      .expect(200);
    expectReplyMatches(res.body, 'GET /auth/directory/changes', 200);
  });
});

describe('GET /auth/permissions/{system} reply', () => {
  it('matches the 200 body', async () => {
    const http = await start({
      controller: PermissionsController,
      providers: [
        {
          provide: MatrixService,
          useValue: {
            version: () => Promise.resolve(3),
            systemMatrix: () =>
              Promise.resolve({
                system: 'VRMS',
                version: 3,
                permissions: [
                  { key: 'repairs.approve', lockedRoles: ['ADMIN'] },
                ],
                grants: { ADMIN: ['repairs.approve'], MECHANIC: [] },
              }),
          },
        },
      ],
      guards: [
        [
          PermissionsReadGuard,
          pass((req) => (req.permissionsClient = { system: 'VRMS' })),
        ],
      ],
    });
    const res = await http.get('/auth/permissions/vrms').expect(200);
    expectReplyMatches(res.body, 'GET /auth/permissions/{system}', 200);
  });
});
