import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { ValidationPipe } from '@nestjs/common';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { Test } from '@nestjs/testing';
import { ThrottlerModule } from '@nestjs/throttler';
import request from 'supertest';
import {
  ADDRESS_LIMIT,
  AddressThrottlerGuard,
} from './address-throttler.guard';
import { TokenController } from './token.controller';
import {
  ClientRateLimitedError,
  TokenEndpointService,
} from './token-endpoint.service';

// covers: spec 0002 AC-14 (form only, outside the ValidationPipe), AC-18 (per address limit by the
// real caller behind the gateway, 429 with Retry-After and the OAuth body)
describe('POST /auth/token', () => {
  let app: NestExpressApplication;
  let seen: { form: Record<string, unknown>; address: string }[];
  let limited: boolean;

  beforeEach(async () => {
    seen = [];
    limited = false;
    const endpoint = {
      grant: (form: Record<string, unknown>, address: string) => {
        seen.push({ form, address });
        if (limited) return Promise.reject(new ClientRateLimitedError(42));
        return Promise.resolve({
          access_token: 't',
          token_type: 'Bearer',
          expires_in: 300,
          scope: 'directory.read',
        });
      },
    };
    const moduleRef = await Test.createTestingModule({
      imports: [ThrottlerModule.forRoot({ throttlers: [ADDRESS_LIMIT] })],
      controllers: [TokenController],
      providers: [
        AddressThrottlerGuard,
        { provide: TokenEndpointService, useValue: endpoint },
      ],
    }).compile();
    app = moduleRef.createNestApplication<NestExpressApplication>();
    app.set('trust proxy', 1);
    // The real app's strict pipe; it must not touch this route
    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        forbidNonWhitelisted: true,
        transform: true,
      }),
    );
    await app.init();
  });

  afterEach(() => app.close());

  const post = (forwardedFor = '203.0.113.7') =>
    request(app.getHttpServer())
      .post('/auth/token')
      .set('X-Forwarded-For', forwardedFor)
      .type('form');

  it('passes the form and the real caller address on, with no-store', async () => {
    const res = await post().send({
      grant_type: 'client_credentials',
      anything: 'kept for the service to ignore',
    });
    expect(res.status).toBe(200);
    expect(res.headers['cache-control']).toBe('no-store');
    expect(seen[0]).toEqual({
      form: {
        grant_type: 'client_credentials',
        anything: 'kept for the service to ignore',
      },
      address: '203.0.113.7',
    });
  });

  it('refuses JSON with invalid_request', async () => {
    const res = await request(app.getHttpServer())
      .post('/auth/token')
      .send({ grant_type: 'client_credentials' });
    expect(res.status).toBe(400);
    expect(res.body).toEqual({
      error: 'invalid_request',
      error_description: expect.any(String),
    });
    expect(seen).toHaveLength(0);
  });

  it('answers the 121st request a minute from one address with 429 and Retry-After, before any check', async () => {
    for (let i = 0; i < 120; i++)
      expect((await post().send('a=1')).status).toBe(200);
    const res = await post().send('a=1');
    expect(res.status).toBe(429);
    expect(Number(res.headers['retry-after'])).toBeGreaterThan(0);
    expect(res.body).toEqual({
      error: 'rate_limited',
      error_description: expect.any(String),
    });
    expect(seen).toHaveLength(120);
    // Another caller behind the same gateway has its own count
    expect((await post('198.51.100.9').send('a=1')).status).toBe(200);
  });

  it("answers a client's used up limit with 429, Retry-After and the OAuth body", async () => {
    limited = true;
    const res = await post().send('a=1');
    expect(res.status).toBe(429);
    expect(res.headers['retry-after']).toBe('42');
    expect((res.body as { error: string }).error).toBe('rate_limited');
  });
});
