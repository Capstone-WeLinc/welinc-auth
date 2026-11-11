import { describe, expect, it } from '@jest/globals';
import { HttpException } from '@nestjs/common';
import {
  ACTIVITY_DEFAULT_LIMIT,
  ACTIVITY_MAX_LIMIT,
  parseActivityQuery,
} from './activity-query';
import { encodeEventCursor } from './event-cursor';

const ID = '0b6f7a52-3c1e-4a8e-9d3b-1f2a3b4c5d6e';
const ALL = { type: true, dates: true, feed: true };

function failure(raw: Record<string, unknown>, route = ALL) {
  try {
    parseActivityQuery(raw, route);
  } catch (e) {
    return (e as HttpException).getResponse();
  }
  return null;
}
const validation = { statusCode: 400, code: 'VALIDATION_FAILED' };

// covers: AC-13, AC-14
describe('parseActivityQuery', () => {
  it('uses the default limit and no filters for an empty query', () => {
    const f = parseActivityQuery({});
    expect(f.limit).toBe(ACTIVITY_DEFAULT_LIMIT);
    expect(f.cursor).toBeNull();
    expect(f.categories).toBeUndefined();
  });

  describe('limit', () => {
    it('accepts 1 and the maximum', () => {
      expect(parseActivityQuery({ limit: '1' }).limit).toBe(1);
      expect(
        parseActivityQuery({ limit: String(ACTIVITY_MAX_LIMIT) }).limit,
      ).toBe(ACTIVITY_MAX_LIMIT);
    });

    it.each(['0', '101', '-1', 'abc', '1.5', '', '1000'])(
      'refuses limit=%p',
      (limit) => {
        expect(failure({ limit })).toMatchObject(validation);
      },
    );
  });

  it('refuses a parameter given twice', () => {
    expect(failure({ limit: ['1', '2'] })).toMatchObject(validation);
  });

  describe('category and type', () => {
    it('parses lists and drops duplicates', () => {
      const f = parseActivityQuery(
        { category: 'SIGN_IN,SESSION,SIGN_IN', type: 'SIGNED_IN,SIGNED_OUT' },
        ALL,
      );
      expect(f.categories).toEqual(['SIGN_IN', 'SESSION']);
      expect(f.types).toEqual(['SIGNED_IN', 'SIGNED_OUT']);
    });

    it('refuses an unknown category', () => {
      expect(failure({ category: 'NOPE' })).toMatchObject(validation);
    });

    it('refuses an empty list entry', () => {
      expect(failure({ category: 'SIGN_IN,' })).toMatchObject(validation);
    });

    it('refuses more than 20 values', () => {
      const many = Array.from({ length: 21 }, (_, i) => `X${i}`).join(',');
      expect(failure({ category: many })).toMatchObject(validation);
    });

    it('refuses a type outside the given categories', () => {
      expect(failure({ type: 'SIGNED_IN', category: 'CODE' })).toMatchObject(
        validation,
      );
    });

    it('ignores type on a route that does not take it', () => {
      expect(parseActivityQuery({ type: 'NOPE' }, {}).types).toBeUndefined();
    });
  });

  describe('dates (Asia/Manila days)', () => {
    it('reads from as the start of the Manila day', () => {
      const f = parseActivityQuery({ from: '2026-11-12' }, ALL);
      expect(f.from?.toISOString()).toBe('2026-11-11T16:00:00.000Z');
    });

    it('reads to as an exclusive bound at the next Manila midnight', () => {
      const f = parseActivityQuery({ to: '2026-11-11' }, ALL);
      expect(f.before?.toISOString()).toBe('2026-11-11T16:00:00.000Z');
    });

    it('keeps a 23:30 Manila row on the 11th inside to=11th and outside from=12th', () => {
      const row = new Date('2026-11-11T15:30:00.000Z');
      const to = parseActivityQuery({ to: '2026-11-11' }, ALL);
      const from = parseActivityQuery({ from: '2026-11-12' }, ALL);
      expect(row < (to.before as Date)).toBe(true);
      expect(row >= (from.from as Date)).toBe(false);
    });

    it('refuses from after to', () => {
      expect(failure({ from: '2026-11-13', to: '2026-11-12' })).toMatchObject(
        validation,
      );
    });

    it.each([
      '2026-02-30',
      '2026-13-01',
      '12-11-2026',
      'yesterday',
      '2026-1-1',
    ])('refuses the date %p', (from) => {
      expect(failure({ from })).toMatchObject(validation);
    });

    it('accepts a leap day', () => {
      expect(() =>
        parseActivityQuery({ from: '2028-02-29' }, ALL),
      ).not.toThrow();
    });

    it('ignores dates on a route that does not take them', () => {
      expect(parseActivityQuery({ from: 'junk' }, {}).from).toBeUndefined();
    });
  });

  describe('feed filters', () => {
    it('lowercases a userId', () => {
      expect(parseActivityQuery({ userId: ID.toUpperCase() }, ALL).userId).toBe(
        ID,
      );
    });

    it('refuses a userId that is not a UUID', () => {
      expect(failure({ userId: '123' })).toMatchObject(validation);
    });

    it('trims q and enforces 2 to 100 characters', () => {
      expect(parseActivityQuery({ q: '  multi ' }, ALL).q).toBe('multi');
      expect(failure({ q: ' a ' })).toMatchObject(validation);
      expect(failure({ q: 'x'.repeat(101) })).toMatchObject(validation);
    });

    it('normalises an address and refuses a non address', () => {
      expect(
        parseActivityQuery({ address: '::ffff:8.8.8.8' }, ALL).address,
      ).toBe('8.8.8.8');
      expect(failure({ address: 'nope' })).toMatchObject(validation);
    });

    it('ignores feed filters on a per person route', () => {
      const f = parseActivityQuery({ userId: 'junk', q: 'x' }, {});
      expect(f.userId).toBeUndefined();
      expect(f.q).toBeUndefined();
    });
  });

  describe('cursor', () => {
    it('decodes a cursor it handed out', () => {
      const cursor = encodeEventCursor({
        createdAt: new Date('2026-11-12T00:00:00.000Z'),
        id: ID,
      });
      expect(parseActivityQuery({ cursor }).cursor?.id).toBe(ID);
    });

    it('answers INVALID_CURSOR for a bad cursor', () => {
      expect(failure({ cursor: 'abc' })).toMatchObject({
        statusCode: 400,
        code: 'INVALID_CURSOR',
      });
    });

    it('answers VALIDATION_FAILED first when a filter and the cursor are both bad', () => {
      expect(failure({ cursor: 'abc', limit: '0' })).toMatchObject(validation);
    });
  });
});
