import type { INestApplication } from '@nestjs/common';
import {
  DocumentBuilder,
  SwaggerModule,
  type OpenAPIObject,
} from '@nestjs/swagger';
import { readFileSync } from 'fs';
import { resolve } from 'path';

/** `info.version`: the repo's package.json, read from the working directory (the repo root, /app hosted). */
function packageVersion(): string {
  const raw = readFileSync(resolve('package.json'), 'utf8');
  return (JSON.parse(raw) as { version: string }).version;
}

/** The five security schemes of VRMS spec 0026, AC-8; routes name them through `decorators.ts`. */
export const SECURITY = {
  userToken: 'userToken',
  serviceToken: 'serviceToken',
  ssoCookie: 'ssoCookie',
  vrmsSession: 'vrmsSession',
  clientAssertion: 'clientAssertion',
} as const;

const DESCRIPTION = [
  'The shared WeLinc auth service: sign in, sessions, tokens, people, roles and the permission matrix.',
  '',
  'These docs are generated from the code and show the shapes of each route. On behavior (which',
  'errors come when, lifetimes, the rules behind each route) the shared services contract wins:',
  '[contract 0001](https://github.com/Capstone-WeLinc/welinc-workspace/blob/main/docs/specs/_root/0001-shared-services-contract/index.md).',
].join('\n');

/** Sorts an object's keys, so two builds of the same code write the same bytes (AC-9). */
function sortKeys<T extends object>(value: T): T {
  return Object.fromEntries(
    Object.entries(value).sort(([a], [b]) => a.localeCompare(b, 'en')),
  ) as T;
}

/** The OpenAPI document for the app, in a stable order (spec 0026, `src/openapi/document.ts`). */
export function buildDocument(app: INestApplication): OpenAPIObject {
  const config = new DocumentBuilder()
    .setTitle('WeLinc auth API')
    .setVersion(packageVersion())
    .setDescription(DESCRIPTION)
    .addServer('/')
    .addBearerAuth(
      {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        description:
          'A user access token (`token_use: user`), from the `/auth/token` code exchange or refresh.',
      },
      SECURITY.userToken,
    )
    .addBearerAuth(
      {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        description:
          'A service token (`aud: AUTH`, with `scope`), from the `/auth/token` client credentials grant.',
      },
      SECURITY.serviceToken,
    )
    .addCookieAuth(
      'welinc_sso',
      {
        type: 'apiKey',
        in: 'cookie',
        description:
          "welinc-auth's SSO cookie, set by `/auth/login` (`__Secure-welinc_sso` when hosted).",
      },
      SECURITY.ssoCookie,
    )
    .addCookieAuth(
      'vrms_rt',
      {
        type: 'apiKey',
        in: 'cookie',
        description:
          "The VRMS web session's refresh cookie, on `/vrms/session`.",
      },
      SECURITY.vrmsSession,
    )
    .addSecurity(SECURITY.clientAssertion, {
      type: 'apiKey',
      in: 'query',
      name: 'client_assertion',
      description:
        'A `private_key_jwt` client assertion, sent in the form body of `/auth/token` with ' +
        '`client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer` ' +
        '(OpenAPI has no form body scheme, so it is listed here as a named field).',
    })
    .build();

  const doc = SwaggerModule.createDocument(app, config);
  doc.paths = sortKeys(doc.paths);
  for (const path of Object.keys(doc.paths)) {
    doc.paths[path] = sortKeys(doc.paths[path]);
  }
  doc.tags = [...(doc.tags ?? [])].sort((a, b) =>
    a.name.localeCompare(b.name, 'en'),
  );
  if (doc.components?.schemas) {
    doc.components.schemas = sortKeys(doc.components.schemas);
  }
  return doc;
}
