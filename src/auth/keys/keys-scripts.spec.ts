import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { spawnSync } from 'child_process';
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { importJWK } from 'jose';
import { EnvFile } from '../../../scripts/env-file';
import { newKeyPair } from '../../../scripts/keys';

const ROOT = join(__dirname, '../../..');

function run(script: string, args: string[]) {
  const result = spawnSync(
    join(ROOT, 'node_modules/.bin/ts-node'),
    [join(ROOT, 'scripts', script), ...args],
    { cwd: ROOT, encoding: 'utf8' },
  );
  return {
    code: result.status,
    out: result.stdout,
    err: result.stderr,
    all: result.stdout + result.stderr,
  };
}

// covers: spec 0002 AC-23 (keys:dev), AC-24 (keys:client, keys:rotate): never print a key
type KeySet = { keys: { d?: string; status?: string; alg?: string }[] };
const parse = (raw: string | undefined) => JSON.parse(raw as string) as KeySet;

describe('newKeyPair', () => {
  it('makes a matching ES256 pair with kid, alg and use on both halves', async () => {
    const pair = await newKeyPair('auth');

    expect(pair.kid).toMatch(/^auth-\d{8}-[0-9a-f]{6}$/);
    for (const jwk of [pair.privateJwk, pair.publicJwk]) {
      expect(jwk).toMatchObject({ kid: pair.kid, alg: 'ES256', use: 'sig' });
    }
    expect(pair.privateJwk.d).toBeDefined();
    expect(pair.publicJwk.d).toBeUndefined();
    expect(pair.privateJwk.x).toBe(pair.publicJwk.x);
    await expect(importJWK(pair.privateJwk, 'ES256')).resolves.toBeDefined();
  });
});

describe('key scripts', () => {
  jest.setTimeout(60_000);
  let dir: string;
  let authEnv: string;
  let vrmsEnv: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'keys-'));
    authEnv = join(dir, 'auth.env');
    vrmsEnv = join(dir, 'vrms.env');
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it('keys:dev writes both sides, keeps other lines and prints no key', () => {
    writeFileSync(authEnv, '# mine\nPORT=3001\n');

    const result = run('keys-dev.ts', [
      '--auth-env',
      authEnv,
      '--vrms-env',
      vrmsEnv,
    ]);

    expect(result.code).toBe(0);
    const auth = EnvFile.read(authEnv);
    const vrms = EnvFile.read(vrmsEnv);
    const signing = parse(auth.get('AUTH_SIGNING_KEYS'));
    expect(signing.keys[0]).toMatchObject({ status: 'current', alg: 'ES256' });
    expect(parse(auth.get('CLIENT_VRMS_JWKS')).keys[0].d).toBeUndefined();
    expect(
      (
        JSON.parse(vrms.get('AUTH_CLIENT_PRIVATE_KEY') as string) as {
          d?: string;
        }
      ).d,
    ).toBeDefined();
    expect(auth.get('AUTH_ISSUER')).toBe('http://localhost:3000/auth');
    expect(readFileSync(authEnv, 'utf8')).toContain('# mine\nPORT=3001\n');
    expect(result.all).not.toContain(signing.keys[0].d);
  });

  it('keys:dev refuses to replace existing keys without --force', () => {
    writeFileSync(authEnv, "AUTH_SIGNING_KEYS='{}'\n");

    const result = run('keys-dev.ts', [
      '--auth-env',
      authEnv,
      '--vrms-env',
      vrmsEnv,
    ]);

    expect(result.code).toBe(1);
    expect(result.err).toMatch(/Already set: AUTH_SIGNING_KEYS/);
    expect(readFileSync(authEnv, 'utf8')).toBe("AUTH_SIGNING_KEYS='{}'\n");
  });

  it('keys:client refuses an unknown client id', () => {
    const result = run('keys-client.ts', ['nope', vrmsEnv, authEnv]);

    expect(result.code).toBe(1);
    expect(result.err).toMatch(/Unknown client "nope"/);
  });

  it('keys:client prints usage when arguments are missing', () => {
    const result = run('keys-client.ts', ['vrms-backend']);

    expect(result.code).toBe(1);
    expect(result.err).toMatch(/Usage: npm run keys:client/);
  });

  it('keys:rotate rejects a missing or unknown step', () => {
    const result = run('keys-rotate.ts', [authEnv, 'explode']);

    expect(result.code).toBe(1);
    expect(result.err).toMatch(/Usage: npm run keys:rotate/);
  });

  it('keys:rotate says add has no --now and remove --now needs a kid', () => {
    expect(run('keys-rotate.ts', [authEnv, 'add', '--now']).err).toMatch(
      /add has no --now/,
    );
    expect(run('keys-rotate.ts', [authEnv, 'remove', '--now']).err).toMatch(
      /needs the kid/,
    );
  });

  it('keys:rotate refuses to promote when there is no key set yet', () => {
    const result = run('keys-rotate.ts', [authEnv, 'promote']);

    expect(result.code).toBe(1);
    expect(result.err).toBeTruthy();
    expect(existsSync(authEnv)).toBe(false);
  });
});
