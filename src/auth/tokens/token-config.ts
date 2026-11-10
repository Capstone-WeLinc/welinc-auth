import { Logger, type Provider } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { SigningKeyRing } from '../keys/signing-keys';
import type { Env } from '../../config/env';

/** Systems a user token may name as its `aud` (spec 0002, AC-8). */
export const USER_AUDIENCES = ['VRMS', 'VMMS', 'BMS'] as const;
export type UserAudience = (typeof USER_AUDIENCES)[number];

/** The audience of a service token for welinc-auth itself. Not a `SystemType`. */
export const AUTH_AUDIENCE = 'AUTH';

/** Every audience welinc-auth knows, checked in code against one list (spec 0002, Data model). */
export const KNOWN_AUDIENCES = [...USER_AUDIENCES, AUTH_AUDIENCE] as const;

/** Clock leeway for every time check, in seconds (spec 0002, Decisions). */
export const CLOCK_LEEWAY_SECONDS = 5;

export type TokenSettings = {
  /** `AUTH_ISSUER`: an identifier compared character for character, never fetched. */
  issuer: string;
  accessTokenMinutes: number;
  serviceTokenMinutes: number;
};

export const TOKEN_SETTINGS = Symbol('TOKEN_SETTINGS');
export const SIGNING_KEY_RING = Symbol('SIGNING_KEY_RING');

/** Values arrive checked, trimmed and defaulted by the boot check (spec 0010). */
export function readTokenSettings(
  config: ConfigService<Env, true>,
): TokenSettings {
  return {
    issuer: config.get('AUTH_ISSUER', { infer: true }),
    accessTokenMinutes: config.get('ACCESS_TOKEN_MINUTES', { infer: true }),
    serviceTokenMinutes: config.get('SERVICE_TOKEN_MINUTES', { infer: true }),
  };
}

export const tokenSettingsProvider: Provider = {
  provide: TOKEN_SETTINGS,
  inject: [ConfigService],
  useFactory: readTokenSettings,
};

/** Loads and self tests the signing keys before the app listens, so a bad set stops startup (AC-2). */
export const signingKeyRingProvider: Provider = {
  provide: SIGNING_KEY_RING,
  inject: [ConfigService],
  useFactory: async (config: ConfigService<Env, true>) => {
    const ring = await SigningKeyRing.load(
      config.get('AUTH_SIGNING_KEYS', { infer: true }),
    );
    const logger = new Logger('SigningKeys');
    for (const key of ring.keys) {
      logger.log(`signing key ${key.kid} is ${key.status}`);
    }
    return ring;
  },
};
