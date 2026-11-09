import type { Manifest, ManifestPerson } from './manifest';

// AC-12: the accounts a tester signs in with, grouped by system, then counts for the rest.

const LISTED_GROUPS = new Set(['office', 'multi', 'state']);
const SYSTEM_ORDER = ['VRMS', 'VMMS', 'BMS'];

function roleText(p: ManifestPerson) {
  return p.roles.map((r) => `${r.system} ${r.role}`).join(', ');
}

/** The system a person is listed under: their first system in suite order, or "Multi system". */
function heading(p: ManifestPerson) {
  if (p.group === 'multi') return 'Multi system';
  if (p.group === 'state') return 'Broken state accounts';
  const systems = new Set(p.roles.map((r) => r.system));
  return SYSTEM_ORDER.find((s) => systems.has(s)) ?? 'No system';
}

export function summaryLines(
  people: ManifestPerson[],
  manifest: Manifest,
  staging: boolean,
): string[] {
  const lines: string[] = [];
  const groups = new Map<string, ManifestPerson[]>();
  for (const p of people.filter((x) => LISTED_GROUPS.has(x.group))) {
    const h = heading(p);
    groups.set(h, [...(groups.get(h) ?? []), p]);
  }
  const order = [...SYSTEM_ORDER, 'Multi system', 'Broken state accounts'];
  for (const h of order) {
    const rows = groups.get(h);
    if (!rows) continue;
    lines.push(h);
    const width = Math.max(...rows.map((p) => p.email.length));
    for (const p of rows) {
      const state = p.state === 'active' ? '' : `  [${p.state}]`;
      lines.push(
        `  ${p.email.padEnd(width)}  ${manifest.passwords[p.password].padEnd(13)} ${p.name} (${roleText(p)})${state}`,
      );
    }
  }
  if (staging) {
    lines.push('Broken state accounts: skipped (SEED_ALLOW=staging)');
  }
  const count = (g: string) => people.filter((p) => p.group === g).length;
  lines.push(
    `Named mechanics: ${count('mechanic')} (mech.<first>@welinc.com, mechanic1234)`,
    `Bulk mechanics: ${count('bulk')} (first.lastN@welinc.com, mechanic1234)`,
    `BMS drivers: ${count('driver')} (driver.<first>@welinc.com, driver1234)`,
    `BMS helpers: ${count('helper')} (helper.<first>@welinc.com, helper1234)`,
  );
  return lines;
}

export function printSeedSummary(
  people: ManifestPerson[],
  manifest: Manifest,
  staging: boolean,
) {
  console.log('Auth database seeded. Sign in through the portal with:');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  for (const line of summaryLines(people, manifest, staging)) {
    console.log(line);
  }
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
}
