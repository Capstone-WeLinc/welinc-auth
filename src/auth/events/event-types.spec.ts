import { describe, expect, it } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { AccountEventCategory, AccountEventType } from '@prisma/client';
import { EVENT_CATALOG, TYPE_CATEGORY } from './event-types';

// covers: spec 0011 Data model (the map, the catalog, the enums and the CHECK agree), AC-15
describe('event types', () => {
  const types = Object.values(AccountEventType).sort();

  it('maps every type, and only the enum types, to a category', () => {
    expect(Object.keys(TYPE_CATEGORY).sort()).toEqual(types);
  });

  it('lists every category and type in the catalog with a label and labelAdmin', () => {
    expect(EVENT_CATALOG.categories.map((c) => c.code).sort()).toEqual(
      Object.values(AccountEventCategory).sort(),
    );
    expect(EVENT_CATALOG.types.map((t) => t.code).sort()).toEqual(types);
    for (const t of EVENT_CATALOG.types) {
      expect(t.category).toBe(TYPE_CATEGORY[t.code]);
      expect(t.label.length).toBeGreaterThan(0);
      expect(t.labelAdmin.length).toBeGreaterThan(0);
    }
    const reasons = EVENT_CATALOG.reasons.map((r) => r.code);
    expect(new Set(reasons).size).toBe(reasons.length);
  });

  it('matches the CHECK constraint in the migration', () => {
    const sql = readFileSync(
      join(
        __dirname,
        '../../../prisma/migrations/20261114000000_account_events/migration.sql',
      ),
      'utf8',
    );
    for (const category of Object.values(AccountEventCategory)) {
      const match = new RegExp(
        `"category" = '${category}' AND "type" IN \\(([^)]*)\\)`,
      ).exec(sql);
      const inCheck = [...(match?.[1] ?? '').matchAll(/'([A-Z_]+)'/g)]
        .map((m) => m[1])
        .sort();
      const inMap = types.filter((t) => TYPE_CATEGORY[t] === category);
      expect(inCheck).toEqual(inMap);
    }
  });
});
