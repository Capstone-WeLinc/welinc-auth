import type { ConfigService } from '@nestjs/config';
import { testEnv, validateEnv, type Env } from './env';

/**
 * A `ConfigService<Env, true>` stand in for unit tests (spec 0010 allows fakes): the checked
 * `testEnv` plus `overrides`, so every value has the type and default the app would see.
 */
export function fakeConfig(
  overrides: Record<string, string | undefined> = {},
): ConfigService<Env, true> {
  const env = validateEnv({ ...testEnv, ...overrides });
  return {
    get: (key: keyof Env) => env[key],
  } as unknown as ConfigService<Env, true>;
}
