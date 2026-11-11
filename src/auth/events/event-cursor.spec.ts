import { describe, expect, it } from '@jest/globals';
import { HttpException } from '@nestjs/common';
import { decodeEventCursor, encodeEventCursor } from './event-cursor';

const ID = '0b6f7a52-3c1e-4a8e-9d3b-1f2a3b4c5d6e';
const AT = new Date('2026-11-12T07:30:15.123Z');
const raw = (s: string) => Buffer.from(s, 'utf8').toString('base64url');

function codeOf(fn: () => unknown): unknown {
  try {
    fn();
  } catch (e) {
    return (e as HttpException).getResponse();
  }
  return null;
}

// covers: AC-14 (INVALID_CURSOR on anything the route did not hand out)
describe('event cursor', () => {
  it('round trips a row position', () => {
    const back = decodeEventCursor(
      encodeEventCursor({ createdAt: AT, id: ID }),
    );
    expect(back.createdAt.getTime()).toBe(AT.getTime());
    expect(back.id).toBe(ID);
  });

  it('lowercases the id it decodes', () => {
    const cursor = raw(`${AT.toISOString()}|${ID.toUpperCase()}`);
    expect(decodeEventCursor(cursor).id).toBe(ID);
  });

  it.each([
    ['not base64url characters', 'abc!'],
    ['empty', ''],
    ['too long', 'a'.repeat(201)],
    ['plain garbage', 'abc'],
    ['no separator', raw(AT.toISOString())],
    ['an extra part', raw(`${AT.toISOString()}|${ID}|x`)],
    ['a bad time', raw(`2026-11-12|${ID}`)],
    ['a time without milliseconds', raw(`2026-11-12T07:30:15Z|${ID}`)],
    ['an impossible date', raw(`2026-13-45T07:30:15.123Z|${ID}`)],
    ['a bad id', raw(`${AT.toISOString()}|not-a-uuid`)],
  ])('refuses a cursor with %s', (_name, cursor) => {
    expect(codeOf(() => decodeEventCursor(cursor))).toMatchObject({
      statusCode: 400,
      code: 'INVALID_CURSOR',
    });
  });
});
