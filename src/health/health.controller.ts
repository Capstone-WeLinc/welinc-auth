import {
  Controller,
  Get,
  Header,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { PrismaService } from '../shared/prisma.service';

export type HealthCheck = 'ok' | 'failed';

/** How long a check may take before it counts as failed (spec 0008, AC-22). */
export const HEALTH_TIMEOUT_MS = 2000;

/**
 * `ok` when the work settles in time, `failed` when it throws or is slower than `ms`. This only
 * stops waiting: Prisma can't cancel a query that is already running.
 */
export async function checkWithin(
  work: PromiseLike<unknown>,
  ms: number,
): Promise<HealthCheck> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<HealthCheck>((resolve) => {
    timer = setTimeout(() => resolve('failed'), ms);
  });
  const outcome = Promise.resolve(work).then(
    (): HealthCheck => 'ok',
    (): HealthCheck => 'failed',
  );
  try {
    return await Promise.race([outcome, timeout]);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * The gateway and the host's probes call this (spec 0008, AC-22). Public, never rate limited, and
 * it shows only ok or failed, never the error behind a failure.
 */
@Controller('auth')
export class HealthController {
  constructor(private readonly prisma: PrismaService) {}

  @Get('health')
  @Header('Cache-Control', 'no-store')
  async health() {
    const database = await checkWithin(
      this.prisma.$queryRaw`SELECT 1`,
      HEALTH_TIMEOUT_MS,
    );
    const checks = { database };
    if (database !== 'ok') {
      throw new HttpException(
        {
          statusCode: HttpStatus.SERVICE_UNAVAILABLE,
          message: 'A health check failed',
          error: 'Service Unavailable',
          code: 'HEALTH_CHECK_FAILED',
          status: 'unavailable',
          checks,
        },
        HttpStatus.SERVICE_UNAVAILABLE,
      );
    }
    return { status: 'ok', checks };
  }
}
