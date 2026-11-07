/**
 * `npm run keys:dev [-- --force] [--auth-env <file>] [--vrms-env <file>]` (spec 0002, AC-23).
 * Writes a fresh signing key and a VRMS client key pair into the local `.env` files. Prints
 * only the new key ids, never a key.
 */
import { resolve } from 'path';
import { EnvFile, option } from './env-file';
import { newKeyPair } from './keys';

const LOCAL_ISSUER = 'http://localhost:3000/auth';

async function main() {
  const args = process.argv.slice(2);
  const force = args.includes('--force');
  const auth = EnvFile.read(resolve(option(args, 'auth-env') ?? '.env'));
  const vrms = EnvFile.read(
    resolve(option(args, 'vrms-env') ?? '../welinc-backend-vrms/.env'),
  );

  const taken = [
    ...['AUTH_SIGNING_KEYS', 'CLIENT_VRMS_JWKS']
      .filter((key) => auth.has(key))
      .map((key) => `${key} in ${auth.path}`),
    ...(vrms.has('AUTH_CLIENT_PRIVATE_KEY')
      ? [`AUTH_CLIENT_PRIVATE_KEY in ${vrms.path}`]
      : []),
  ];
  if (taken.length > 0 && !force) {
    console.error(
      `Already set: ${taken.join(', ')}.\nRun again with --force to replace them (everyone signs in again).`,
    );
    process.exit(1);
  }

  const signing = await newKeyPair('auth');
  const client = await newKeyPair('vrms');

  auth.set(
    'AUTH_SIGNING_KEYS',
    JSON.stringify({
      keys: [
        {
          ...signing.privateJwk,
          status: 'current',
          addedAt: new Date().toISOString(),
        },
      ],
    }),
  );
  auth.set('CLIENT_VRMS_JWKS', JSON.stringify({ keys: [client.publicJwk] }));
  vrms.set('AUTH_CLIENT_PRIVATE_KEY', JSON.stringify(client.privateJwk));
  for (const file of [auth, vrms]) {
    if (!file.has('AUTH_ISSUER')) file.set('AUTH_ISSUER', LOCAL_ISSUER);
  }

  auth.save();
  vrms.save();
  console.log(`Signing key ${signing.kid} (current) written to ${auth.path}`);
  console.log(
    `VRMS client key ${client.kid} written to ${vrms.path} (private) and ${auth.path} (public)`,
  );
  console.log(
    'Recreate the auth-service container, run `npm run seed:clients` in it, then recreate vrms-backend.',
  );
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
