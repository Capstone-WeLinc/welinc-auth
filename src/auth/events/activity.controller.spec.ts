/* eslint-disable @typescript-eslint/require-await, @typescript-eslint/no-unused-vars, @typescript-eslint/no-unnecessary-type-assertion -- test doubles */
import { describe, expect, it, jest } from '@jest/globals';
import type { ThrottlerStorage } from '@nestjs/throttler';
import type { Request, Response } from 'express';
import type { AccountEventsService } from './account-events.service';
import { ActivityController, FEED_LIMIT } from './activity.controller';

const USER = {
  sub: '11111111-1111-4111-8111-111111111111',
  system: 'VRMS' as const,
};

function setup(totalHits = 1) {
  const feed = jest.fn(async (..._a: unknown[]) => ({
    data: [],
    nextCursor: null,
  }));
  const listOwn = jest.fn(async (..._a: unknown[]) => ({
    data: [],
    nextCursor: null,
  }));
  const events = { feed, listOwn } as unknown as AccountEventsService;
  const storage = {
    increment: jest.fn(async () => ({ totalHits, timeToExpire: 12 })),
  } as unknown as ThrottlerStorage;
  const headers: Record<string, string> = {};
  const status = jest.fn();
  const res = {
    setHeader: (k: string, v: string) => {
      headers[k] = v;
    },
    status,
    type: jest.fn(),
    send: jest.fn(),
    end: jest.fn(),
  };
  status.mockReturnValue(res);
  res.type.mockReturnValue(res);
  return {
    c: new ActivityController(events, storage),
    feed,
    listOwn,
    headers,
    res: res as unknown as Response,
    status,
  };
}

// covers: AC-13, AC-14, AC-15
describe('ActivityController', () => {
  it('reads the caller own events with the parsed query', async () => {
    const { c, listOwn } = setup();
    await c.ownActivity({ limit: '5' }, { user: USER } as never);
    expect(listOwn).toHaveBeenCalledWith(
      USER.sub,
      expect.objectContaining({ limit: 5 }),
    );
  });

  it('rejects a bad query with 400 before touching the service', () => {
    const { c, listOwn } = setup();
    expect(() =>
      c.ownActivity({ limit: '0' }, { user: USER } as never),
    ).toThrow();
    expect(listOwn).not.toHaveBeenCalled();
  });

  it('scopes the feed to the token system and sets no-store', async () => {
    const { c, feed, headers, res } = setup();
    await c.systemActivity({ q: 'multi' }, { user: USER } as never, res);
    expect(feed).toHaveBeenCalledWith(
      'VRMS',
      expect.objectContaining({ q: 'multi' }),
    );
    expect(headers['Cache-Control']).toBe('no-store');
  });

  it('answers 429 with Retry-After past the feed limit', async () => {
    const { c, feed, headers, res } = setup(FEED_LIMIT.limit + 1);
    await expect(
      c.systemActivity({}, { user: USER } as never, res),
    ).rejects.toMatchObject({ status: 429 });
    expect(headers['Retry-After']).toBe('12');
    expect(feed).not.toHaveBeenCalled();
  });

  it('still serves the 60th call in the minute', async () => {
    const { c, feed, res } = setup(FEED_LIMIT.limit);
    await c.systemActivity({}, { user: USER } as never, res);
    expect(feed).toHaveBeenCalled();
  });

  it('serves the catalog with an ETag and answers 304 on a match', () => {
    const first = setup();
    first.c.catalog({ headers: {} } as Request, first.res);
    const etag = first.headers['ETag'];
    expect(etag).toBeTruthy();
    expect(first.headers['Cache-Control']).toMatch(/public, max-age=300/);
    expect(first.status).toHaveBeenCalledWith(200);

    const second = setup();
    second.c.catalog(
      { headers: { 'if-none-match': etag } } as unknown as Request,
      second.res,
    );
    expect(second.status).toHaveBeenCalledWith(304);
  });
});
