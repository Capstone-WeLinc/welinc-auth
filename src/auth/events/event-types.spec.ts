import { describe, expect, it } from '@jest/globals';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { AccountEventCategory, AccountEventType } from '@prisma/client';
import { EVENT_CATALOG, TYPE_CATEGORY } from './event-types';

// covers: spec 0011 Data model, spec 0012 AC-20 (new types) (the map, the catalog, the enums and the CHECK agree), AC-15
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

  it('matches the CHECK constraint in the latest migration that sets it', () => {
    // Spec 0012 rebuilt the CHECK, so the newest migration that adds it wins
    const dir = join(__dirname, '../../../prisma/migrations');
    const sql = readdirSync(dir)
      .filter((name) => /^\d{14}_/.test(name))
      .sort()
      .map((name) => {
        try {
          return readFileSync(join(dir, name, 'migration.sql'), 'utf8');
        } catch {
          return '';
        }
      })
      .filter(
        (text) =>
          text.includes(
            'ADD CONSTRAINT "account_events_type_category_check"',
          ) ||
          text.includes(
            'CONSTRAINT "account_events_type_category_check" CHECK',
          ),
      )
      .pop()!;
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
