import { HttpException } from '@nestjs/common';
import { decodeDeletionCursor, encodeDeletionCursor } from './deletion-cursor';

// covers: spec 0012 AC-9 (keyset cursors for the pending and grace views)

const ID = '3f2b8c1e-5a4d-4e6f-9b0a-1c2d3e4f5a6b';
const AT = new Date('2026-11-12T08:30:15.123Z');

function expectInvalid(fn: () => unknown) {
  let error: HttpException | undefined;
  try {
    fn();
  } catch (e) {
    error = e as HttpException;
  }
  expect(error).toBeInstanceOf(HttpException);
  expect(error?.getStatus()).toBe(400);
  expect(error?.getResponse()).toMatchObject({ code: 'INVALID_CURSOR' });
}

const raw = (text: string) => Buffer.from(text, 'utf8').toString('base64url');

describe('deletion cursor', () => {
  it('round trips the time and id for the same view', () => {
    const cursor = encodeDeletionCursor('pending', AT, ID);
    expect(decodeDeletionCursor(cursor, 'pending')).toEqual({ at: AT, id: ID });
  });

  it('lowercases the id it hands back', () => {
    const cursor = encodeDeletionCursor('grace', AT, ID.toUpperCase());
    expect(decodeDeletionCursor(cursor, 'grace').id).toBe(ID);
  });

  it('produces a url safe string', () => {
    expect(encodeDeletionCursor('grace', AT, ID)).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it('rejects a cursor from the other view', () => {
    expectInvalid(() =>
      decodeDeletionCursor(encodeDeletionCursor('pending', AT, ID), 'grace'),
    );
    expectInvalid(() =>
      decodeDeletionCursor(encodeDeletionCursor('grace', AT, ID), 'pending'),
    );
  });

  it.each([
    ['empty', ''],
    ['not base64url characters', 'abc def!'],
    ['too long', 'a'.repeat(201)],
    ['without separators', raw('pending')],
    ['missing the id', raw(`pending|${AT.toISOString()}`)],
    ['carrying an extra part', raw(`pending|${AT.toISOString()}|${ID}|x`)],
    ['a date without milliseconds', raw(`pending|2026-11-12T08:30:15Z|${ID}`)],
    ['not a date', raw(`pending|yesterday|${ID}`)],
    ['an impossible date', raw(`pending|2026-13-45T99:99:99.000Z|${ID}`)],
    ['an id that is not a uuid', raw(`pending|${AT.toISOString()}|42`)],
  ])('rejects a cursor that is %s', (_label, cursor) => {
    expectInvalid(() => decodeDeletionCursor(cursor, 'pending'));
  });
});
