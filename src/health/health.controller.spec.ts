import { describe, it, expect } from '@jest/globals';
import { HttpException } from '@nestjs/common';
import { HealthController, checkWithin } from './health.controller';
import type { PrismaService } from '../shared/prisma.service';

const controllerWith = (queryRaw: () => Promise<unknown>) =>
  new HealthController({
    $queryRaw: queryRaw,
  } as unknown as PrismaService);

describe('checkWithin', () => {
  it('is ok when the work settles in time', async () => {
    await expect(checkWithin(Promise.resolve(1), 50)).resolves.toBe('ok');
  });

  it('fails when the work throws', async () => {
    await expect(
      checkWithin(Promise.reject(new Error('down')), 50),
    ).resolves.toBe('failed');
  });

  it('fails when the work is slower than the limit', async () => {
    const slow = new Promise((resolve) => setTimeout(resolve, 200));
    await expect(checkWithin(slow, 20)).resolves.toBe('failed');
  });
});

describe('HealthController', () => {
  it('answers ok with the database check', async () => {
    await expect(
      controllerWith(() => Promise.resolve([{ '?column?': 1 }])).health(),
    ).resolves.toEqual({ status: 'ok', checks: { database: 'ok' } });
  });

  it('answers 503 with no error text when the database fails', async () => {
    const error = await controllerWith(() =>
      Promise.reject(new Error('password authentication failed')),
    )
      .health()
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(HttpException);
    const http = error as HttpException;
    expect(http.getStatus()).toBe(503);
    expect(http.getResponse()).toEqual({
      statusCode: 503,
      message: 'A health check failed',
      error: 'Service Unavailable',
      code: 'HEALTH_CHECK_FAILED',
      status: 'unavailable',
      checks: { database: 'failed' },
    });
    expect(JSON.stringify(http.getResponse())).not.toContain('password');
  });
});
