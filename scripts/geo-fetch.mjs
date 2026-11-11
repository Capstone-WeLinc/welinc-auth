/**
 * `npm run geo:fetch [-- --soft]` (spec 0011, AC-18). Downloads DB-IP's free Lite databases,
 * country and ASN, for this month (UTC), or last month's when this month's isn't out yet (404).
 * Each file is gunzipped to a temp file, opened once to prove it reads, then renamed to
 * `geo/dbip-country-lite.mmdb` and `geo/dbip-asn-lite.mmdb` (`geo/` is git ignored).
 *
 * Any failure exits 1; with `--soft` it warns and exits 0, so a Docker build or `setup.sh` never
 * fails over it (places just stay empty). Data: "IP data by DB-IP", CC BY 4.0, https://db-ip.com.
 */
import { createWriteStream } from 'node:fs';
import { mkdir, rename, rm } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { createGunzip } from 'node:zlib';
import maxmind from 'maxmind';

const BASE = 'https://download.db-ip.com/free';
const DIR = resolve('geo');
const FILES = [
  { name: 'dbip-country-lite', check: (r) => r.get('1.1.1.1')?.country?.iso_code },
  { name: 'dbip-asn-lite', check: (r) => r.get('1.1.1.1')?.autonomous_system_number },
];
const soft = process.argv.includes('--soft');

/** `YYYY-MM` for this month in UTC, then last month. */
function months(now = new Date()) {
  const ym = (d) => `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}`;
  const last = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 1, 1));
  return [ym(now), ym(last)];
}

async function fetchOne(name) {
  for (const month of months()) {
    const url = `${BASE}/${name}-${month}.mmdb.gz`;
    const response = await fetch(url);
    if (response.status === 404) continue;
    if (!response.ok || !response.body) {
      throw new Error(`${url} answered ${response.status}`);
    }
    const temp = join(DIR, `.${name}.${process.pid}.tmp`);
    try {
      await pipeline(Readable.fromWeb(response.body), createGunzip(), createWriteStream(temp));
      return { temp, month };
    } catch (error) {
      await rm(temp, { force: true });
      throw error;
    }
  }
  throw new Error(`${name}: no file for ${months().join(' or ')}`);
}

async function main() {
  await mkdir(DIR, { recursive: true });
  for (const file of FILES) {
    const { temp, month } = await fetchOne(file.name);
    try {
      // Prove it reads before it replaces a working file
      const reader = await maxmind.open(temp);
      if (!file.check(reader)) throw new Error(`${file.name} did not answer a test lookup`);
      await rename(temp, join(DIR, `${file.name}.mmdb`));
    } catch (error) {
      await rm(temp, { force: true });
      throw error;
    }
    console.log(`geo: ${file.name} ${month} saved to geo/${file.name}.mmdb`);
  }
  console.log('geo: IP data by DB-IP (https://db-ip.com), CC BY 4.0');
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  if (soft) {
    console.warn(`geo: skipped, places stay empty (${message})`);
    process.exit(0);
  }
  console.error(`geo: failed: ${message}`);
  process.exit(1);
});
