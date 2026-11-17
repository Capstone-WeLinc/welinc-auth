import { afterEach, describe, expect, it, jest } from '@jest/globals';
import type { ExecutionContext, INestApplication } from '@nestjs/common';
import { ValidationPipe } from '@nestjs/common';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { Test } from '@nestjs/testing';
import { ThrottlerModule } from '@nestjs/throttler';
import request from 'supertest';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { ADDRESS_LIMIT } from './clients/address-throttler.guard';
import { DeletionService } from './deletion/deletion.service';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { OptionalJwtAuthGuard } from './guards/optional-jwt-auth.guard';
import { SystemAdminGuard } from './guards/system-admin.guard';

// covers: S17 (shared services scope). POST /auth/profile/picture answered 500 for a wrong file
// type (the filter passed a plain Error) and for a request with no file (the service read
// `originalname` on undefined). Both must answer 400 and never reach the service.

const ID = '6f1c2a3b-4d5e-4f60-8a71-92b3c4d5e6f7';
const pass = (set?: (req: Record<string, unknown>) => void) => ({
  canActivate(context: ExecutionContext) {
    set?.(context.switchToHttp().getRequest());
    return true;
  },
});

let app: INestApplication | undefined;
afterEach(async () => {
  await app?.close();
  app = undefined;
});

async function start() {
  const upload = jest.fn(() => Promise.resolve({ id: ID }));
  const moduleRef = await Test.createTestingModule({
    imports: [ThrottlerModule.forRoot({ throttlers: [ADDRESS_LIMIT] })],
    controllers: [AuthController],
    providers: [
      { provide: AuthService, useValue: { uploadProfilePicture: upload } },
      { provide: DeletionService, useValue: {} },
    ],
  })
    .overrideGuard(JwtAuthGuard)
    .useValue(pass((req) => (req.user = { sub: ID, system: 'VRMS' })))
    .overrideGuard(SystemAdminGuard)
    .useValue(pass())
    .overrideGuard(OptionalJwtAuthGuard)
    .useValue(pass())
    .compile();
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
  return { http: request(nest.getHttpServer()), upload };
}

describe('POST /auth/profile/picture', () => {
  it('answers 400 for a file that is not an image', async () => {
    const { http, upload } = await start();
    await http
      .post('/auth/profile/picture')
      .attach('file', Buffer.from('hello'), 'notes.txt')
      .expect(400);
    expect(upload).not.toHaveBeenCalled();
  });

  it('answers 400 for a file with no extension', async () => {
    const { http, upload } = await start();
    await http
      .post('/auth/profile/picture')
      .attach('file', Buffer.from('hello'), 'picture')
      .expect(400);
    expect(upload).not.toHaveBeenCalled();
  });

  it('answers 400 when no file is sent', async () => {
    const { http, upload } = await start();
    await http.post('/auth/profile/picture').expect(400);
    expect(upload).not.toHaveBeenCalled();
  });

  it('passes an image through to the service', async () => {
    const { http, upload } = await start();
    await http
      .post('/auth/profile/picture')
      .attach('file', Buffer.from([0x89, 0x50, 0x4e, 0x47]), 'me.PNG')
      .expect(201);
    expect(upload).toHaveBeenCalledTimes(1);
  });
});
