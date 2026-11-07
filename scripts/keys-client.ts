/**
 * `npm run keys:client -- <client id> <private env file> <public env file> [--force]` (spec 0002,
 * AC-24). Makes a client key pair for staging and production: the private key goes into the
 * client's own secrets as AUTH_CLIENT_PRIVATE_KEY, the public key into welinc-auth's as
 * CLIENT_<ID>_JWKS. Prints only the new kid.
 */
import { resolve } from 'path';
import { CLIENTS, jwksEnvName } from '../prisma/seeds/clients.seed';
import { EnvFile } from './env-file';
import { newKeyPair } from './keys';

async function main() {
  const args = process.argv.slice(2);
  const force = args.includes('--force');
  const [clientId, privatePath, publicPath] = args.filter(
    (arg) => arg !== '--force',
  );
  if (!clientId || !privatePath || !publicPath) {
    console.error(
      'Usage: npm run keys:client -- <client id> <private env file> <public env file> [--force]',
    );
    process.exit(1);
  }
  if (!CLIENTS.some((client) => client.id === clientId)) {
    console.error(
      `Unknown client "${clientId}". Known: ${CLIENTS.map((c) => c.id).join(', ')}.`,
    );
    process.exit(1);
  }

  const privateFile = EnvFile.read(resolve(privatePath));
  const publicFile = EnvFile.read(resolve(publicPath));
  if (privateFile.has('AUTH_CLIENT_PRIVATE_KEY') && !force) {
    console.error(
      `AUTH_CLIENT_PRIVATE_KEY is already set in ${privateFile.path}. Run again with --force to replace it.`,
    );
    process.exit(1);
  }

  // Keep the newest registered key beside the new one, so the client can move over without a gap
  const name = jwksEnvName(clientId);
  const existing = publicFile.get(name);
  const kept = existing
    ? ((JSON.parse(existing) as { keys?: unknown[] }).keys ?? []).slice(-1)
    : [];
  const pair = await newKeyPair(clientId);

  privateFile.set('AUTH_CLIENT_PRIVATE_KEY', JSON.stringify(pair.privateJwk));
  publicFile.set(name, JSON.stringify({ keys: [...kept, pair.publicJwk] }));
  privateFile.save();
  publicFile.save();

  console.log(`Client key ${pair.kid} for ${clientId}:`);
  console.log(`  private key → AUTH_CLIENT_PRIVATE_KEY in ${privateFile.path}`);
  console.log(
    `  public key → ${name} in ${publicFile.path}${kept.length ? ' (the previous key is kept beside it)' : ''}`,
  );
  console.log(
    'Next: apply both files with set-secrets.sh, run `npm run seed:clients` in welinc-auth, then deploy the client.',
  );
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
