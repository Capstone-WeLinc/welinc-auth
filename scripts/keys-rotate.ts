/**
 * `npm run keys:rotate -- <env file> <add|promote|remove> [--now] [<kid>]` (spec 0002, AC-24).
 * Edits the AUTH_SIGNING_KEYS line of an env style file (the spec 0008 private secrets file, or a
 * local .env), keeping every other line. Prints key ids and statuses only, never a key.
 */
import { resolve } from 'path';
import {
  rotate,
  RotationRefusedError,
  type RotationStep,
} from '../src/auth/keys/rotation';
import { EnvFile } from './env-file';

const STEPS: RotationStep[] = ['add', 'promote', 'remove'];
const USAGE =
  'Usage: npm run keys:rotate -- <env file> <add|promote|remove> [--now] [<kid>]';

function minutes(file: EnvFile, name: string, fallback: number): number {
  const value = Number(file.get(name) ?? fallback);
  return Number.isFinite(value) && value > 0 ? value : fallback;
}

async function main() {
  const args = process.argv.slice(2);
  const force = args.includes('--now');
  const [path, step, kid] = args.filter((arg) => arg !== '--now');
  if (!path || !STEPS.includes(step as RotationStep)) {
    console.error(USAGE);
    process.exit(1);
  }
  if (force && step === 'add') {
    console.error('add has no --now: it never waits.');
    process.exit(1);
  }
  if (force && step === 'remove' && !kid) {
    console.error('remove --now needs the kid to remove.\n' + USAGE);
    process.exit(1);
  }

  const file = EnvFile.read(resolve(path));
  const tokenMinutes = Math.max(
    minutes(file, 'ACCESS_TOKEN_MINUTES', 15),
    minutes(file, 'SERVICE_TOKEN_MINUTES', 5),
  );
  const { set, notes } = await rotate(
    file.get('AUTH_SIGNING_KEYS'),
    step as RotationStep,
    { now: new Date(), force, kid, tokenMinutes },
  );
  file.set('AUTH_SIGNING_KEYS', JSON.stringify(set));
  file.save();

  for (const line of notes) console.log(line);
  console.log(
    `\nWritten to ${file.path}. Apply it now (hosted: the workspace's infra/scripts/rotate-signing-keys.sh does it for you; locally: recreate the auth container): the waits count from the times just written.`,
  );
}

main().catch((error: unknown) => {
  if (error instanceof RotationRefusedError) {
    console.error(`Refused: ${error.message}`);
  } else {
    console.error(error instanceof Error ? error.message : error);
  }
  process.exit(1);
});
