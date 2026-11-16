import { generateKeyPairSync } from 'crypto';
import { testEnv } from './env';

/**
 * The environment `npm run openapi` builds the app in (VRMS spec 0026, AC-9): the test values, which
 * override any real env, plus a throwaway signing key made in memory, because the key ring is built
 * when the app is created. The key is never written anywhere and signs nothing.
 */
const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const jwk = privateKey.export({ format: 'jwk' });

Object.assign(process.env, testEnv, {
  AUTH_SIGNING_KEYS: JSON.stringify({
    keys: [{ ...jwk, kid: 'openapi-build', alg: 'ES256', status: 'current' }],
  }),
});
