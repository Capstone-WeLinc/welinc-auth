import { NestFactory } from '@nestjs/core';
import { Logger, ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { NestExpressApplication } from '@nestjs/platform-express';
import { resolve } from 'path';
import type { ServerResponse } from 'http';
import type { Request, Response, NextFunction } from 'express';
import cookieParser from 'cookie-parser';
import { AppModule } from './app.module';
import { envWarnings, type Env } from './config/env';
import { mountDocs } from './openapi/docs';

function isLocalDevOrigin(origin: string): boolean {
  return /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin);
}

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);
  const config = app.get<ConfigService<Env, true>>(ConfigService);

  // Spec 0010, AC-5: the environment the app runs in, and each optional service that is off
  const envLog = new Logger('Env');
  envLog.log(`Environment: ${config.get('NODE_ENV', { infer: true })}`);
  envWarnings((key) => config.get(key, { infer: true })).forEach((line) =>
    envLog.warn(line),
  );

  // Proxy hops in front of welinc-auth (spec 0002, AC-18): 1 locally (nginx), 2 hosted (the
  // Container Apps ingress plus nginx). 0 trusts none, so a forged X-Forwarded-For is ignored.
  app.set('trust proxy', config.get('TRUST_PROXY_HOPS', { infer: true }));
  // The portal's SSO cookie (spec 0003, AC-11); unsigned, it holds an opaque handle
  app.use(cookieParser());

  // The same folder the profile upload writes to (relative to the working directory, /app)
  app.useStaticAssets(resolve('uploads'), {
    prefix: '/uploads/',
    setHeaders: (res: ServerResponse) => {
      res.setHeader('Cache-Control', 'public, max-age=86400');
    },
  });

  app.use((_: Request, res: Response, next: NextFunction) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader(
      'Permissions-Policy',
      'camera=(), microphone=(), geolocation=()',
    );
    next();
  });

  app.useGlobalPipes(
    new ValidationPipe({
      forbidNonWhitelisted: true,
      transform: true,
      whitelist: true,
    }),
  );

  // Browser origins allowed besides local development ones (each a bare origin, spec 0010)
  const corsOrigins = config.get('CORS_ORIGINS', { infer: true });

  app.enableCors({
    origin: (origin, callback) => {
      if (!origin) {
        callback(null, true);
        return;
      }
      callback(null, corsOrigins.includes(origin) || isLocalDevOrigin(origin));
    },
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Authorization', 'Content-Type'],
    credentials: true,
  });

  // VRMS spec 0026: /auth/docs, on locally and on staging, never in production
  mountDocs(app, config);

  await app.listen(config.get('PORT', { infer: true }));
}
void bootstrap();
