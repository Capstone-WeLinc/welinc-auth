import type { Client } from 'pg';

/**
 * Drops a throwaway test database once nothing is connected to it.
 *
 * `pool.end()` returns before the server has closed every connection. Dropping with FORCE right
 * then kills the stragglers, and a client that already left its pool has no error handler, so
 * Jest fails the whole suite with "terminating connection due to administrator command" even
 * though every test passed. Waiting for the connections to close first avoids that. FORCE stays
 * as the fallback if one never closes.
 */
export async function dropTestDatabase(
  admin: Client,
  database: string,
  waitMs = 5000,
): Promise<void> {
  const deadline = Date.now() + waitMs;
  while (Date.now() < deadline) {
    const { rows } = await admin.query<{ n: string }>(
      'SELECT count(*) AS n FROM pg_stat_activity WHERE datname = $1',
      [database],
    );
    if (Number(rows[0].n) === 0) break;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  await admin.query(`DROP DATABASE IF EXISTS "${database}" WITH (FORCE)`);
}
