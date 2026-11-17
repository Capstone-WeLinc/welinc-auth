import { Controller, HttpStatus, Module, Post } from '@nestjs/common';
import { APP_FILTER } from '@nestjs/core';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { Test } from '@nestjs/testing';
import * as Sentry from '@sentry/nestjs';
import request from 'supertest';
import {
  CodeErrorFilter,
  CodeSendLimitError,
  MailFailedError,
} from '../auth/codes/code-errors';
import { MonitoringModule } from './monitoring.module';

// covers: VRMS spec 0025 AC-1, AC-2 (the filter order AppModule relies on)

jest.mock('@sentry/nestjs', () => ({
  ...jest.requireActual<object>('@sentry/nestjs'),
  captureException: jest.fn(),
}));

@Controller('auth/probe')
class ProbeController {
  @Post('mail')
  mail(): never {
    throw new MailFailedError();
  }

  @Post('limit')
  limit(): never {
    throw new CodeSendLimitError(60);
  }
}

@Module({
  controllers: [ProbeController],
  providers: [{ provide: APP_FILTER, useClass: CodeErrorFilter }],
})
class ProbeModule {}

describe('MonitoringModule before AuthModule', () => {
  let app: NestExpressApplication;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [MonitoringModule, ProbeModule],
    }).compile();
    app = moduleRef.createNestApplication<NestExpressApplication>();
    await app.init();
  });

  afterAll(() => app.close());
  beforeEach(() => jest.clearAllMocks());

  it('keeps CodeErrorFilter answering MAIL_FAILED, and reports it once', async () => {
    const res = await request(app.getHttpServer()).post('/auth/probe/mail');
    expect(res.status).toBe(HttpStatus.SERVICE_UNAVAILABLE);
    expect(res.body).toMatchObject({ code: 'MAIL_FAILED' });
    expect(Sentry.captureException).toHaveBeenCalledTimes(1);
  });

  it('answers the send limit 429 and reports nothing', async () => {
    const res = await request(app.getHttpServer()).post('/auth/probe/limit');
    expect(res.status).toBe(HttpStatus.TOO_MANY_REQUESTS);
    expect(Sentry.captureException).not.toHaveBeenCalled();
  });
});
