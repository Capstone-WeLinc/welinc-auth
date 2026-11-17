import { Module } from '@nestjs/common';
import { APP_FILTER } from '@nestjs/core';
import { SentryModule } from '@sentry/nestjs/setup';
import { SentryExceptionFilter } from './sentry-exception.filter';

/**
 * VRMS spec 0025: Sentry's request scope and the catch all filter. Sentry itself starts in
 * src/instrument.ts; with no DSN both stay in place and send nothing (AC-14). AppModule imports
 * this before AuthModule, so a more specific app filter (`CodeErrorFilter`) still wins.
 */
@Module({
  imports: [SentryModule.forRoot()],
  providers: [{ provide: APP_FILTER, useClass: SentryExceptionFilter }],
})
export class MonitoringModule {}
