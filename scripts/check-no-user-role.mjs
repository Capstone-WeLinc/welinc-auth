// Spec 0004, AC-14: the build gate. The shared UserRole enum is gone; roles are catalog codes
// (RoleCode). Fails on any `UserRole` import from @prisma/client or "UserRole" in raw SQL under
// src/ and prisma/seeds/, so an old pattern can't come back unnoticed.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

const ROOTS = ['src', 'prisma/seeds'];
const PATTERNS = [
  [/import[^;]*\bUserRole\b[^;]*from\s+['"]@prisma\/client['"]/s, 'imports UserRole from @prisma/client'],
  [/"UserRole"/, 'names the dropped "UserRole" type in SQL'],
];

function* files(dir) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) yield* files(path);
    else if (path.endsWith('.ts')) yield path;
  }
}

const problems = [];
for (const root of ROOTS) {
  for (const path of files(root)) {
    const text = readFileSync(path, 'utf8');
    for (const [re, what] of PATTERNS) {
      if (re.test(text)) problems.push(`${path}: ${what}. Use RoleCode and the catalog (spec 0004).`);
    }
  }
}

if (problems.length > 0) {
  console.error(problems.join('\n'));
  process.exit(1);
}
