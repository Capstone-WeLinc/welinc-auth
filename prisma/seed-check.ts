// `npm run seed:check -- <path>` (spec 0006, AC-13): is a system's copy of people.json current?
// Byte for byte, by SHA-256, so a reformatted copy counts as out of date too.
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { MANIFEST_PATH } from './seeds/manifest';

export function checkCopy(path: string, manifestPath = MANIFEST_PATH) {
  if (!existsSync(path)) return { ok: false, message: `No file at ${path}` };
  const sha = (p: string) =>
    createHash('sha256').update(readFileSync(p)).digest('hex');
  return sha(path) === sha(manifestPath)
    ? { ok: true, message: 'Matches people.json' }
    : {
        ok: false,
        message: `Out of date: copy welinc-auth/prisma/seeds/people.json over ${path}`,
      };
}

if (require.main === module) {
  const arg = process.argv[2];
  if (!arg) {
    console.error('Usage: npm run seed:check -- <path to a copy of people.json>');
    process.exit(1);
  }
  // npm runs scripts from the package folder; INIT_CWD is where the command was typed
  const path = resolve(process.env['INIT_CWD'] ?? process.cwd(), arg);
  const result = checkCopy(path);
  (result.ok ? console.log : console.error)(result.message);
  process.exit(result.ok ? 0 : 1);
}
