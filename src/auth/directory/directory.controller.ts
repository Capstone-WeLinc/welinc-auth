import {
  Controller,
  Get,
  Header,
  HttpStatus,
  Query,
  Req,
  UseGuards,
} from '@nestjs/common';
import { coded } from '../errors';
import { InvalidCursorError } from './directory-cursor';
import { DirectoryGuard, type DirectoryRequest } from './directory.guard';
import { DirectoryService } from './directory.service';
import type { DirectoryView } from './directory-user';

export const DEFAULT_LIMIT = 100;
export const MAX_LIMIT = 500;

export const validationFailed = (message: string) =>
  coded(HttpStatus.BAD_REQUEST, 'VALIDATION_FAILED', message);

const invalidCursor = () =>
  coded(HttpStatus.BAD_REQUEST, 'INVALID_CURSOR', 'This cursor is not valid');

/** A query value that is a single string, or undefined when absent. */
function single(raw: unknown, name: string): string | undefined {
  if (raw === undefined) return undefined;
  if (typeof raw !== 'string')
    throw validationFailed(`${name} must be given once`);
  return raw;
}

/** AC-5: `limit` 1 to 500 on every directory route, 100 when absent. */
export function parseLimit(raw: unknown): number {
  const value = single(raw, 'limit');
  if (value === undefined) return DEFAULT_LIMIT;
  if (!/^\d{1,4}$/.test(value))
    throw validationFailed('limit must be a whole number');
  const limit = Number(value);
  if (limit < 1 || limit > MAX_LIMIT) {
    throw validationFailed(`limit must be between 1 and ${MAX_LIMIT}`);
  }
  return limit;
}

/** An empty cursor counts as a bad one, not as "from the start". */
function cursorParam(raw: unknown, name: string): string | undefined {
  const value = single(raw, name);
  if (value === '') throw invalidCursor();
  return value;
}

async function withCursor<T>(work: () => Promise<T>): Promise<T> {
  try {
    return await work();
  } catch (error) {
    if (error instanceof InvalidCursorError) throw invalidCursor();
    throw error;
  }
}

/**
 * The user directory for system backends (spec 0005, contract 0001 section 9). Every route
 * takes only a service token with `directory.read` (`DirectoryGuard`).
 */
@Controller('auth/directory')
@UseGuards(DirectoryGuard)
export class DirectoryController {
  constructor(private readonly directory: DirectoryService) {}

  @Get('users')
  @Header('Cache-Control', 'no-store')
  listUsers(
    @Query('cursor') cursor: unknown,
    @Query('limit') limit: unknown,
    @Req() req: DirectoryRequest,
  ) {
    const size = parseLimit(limit);
    const page = cursorParam(cursor, 'cursor');
    return withCursor(() => this.directory.listUsers(view(req), page, size));
  }

  @Get('changes')
  @Header('Cache-Control', 'no-store')
  changes(
    @Query('after') after: unknown,
    @Query('limit') limit: unknown,
    @Req() req: DirectoryRequest,
  ) {
    const size = parseLimit(limit);
    const from = cursorParam(after, 'after');
    return withCursor(() => this.directory.changes(view(req), from, size));
  }
}

function view(req: DirectoryRequest): DirectoryView {
  // Set by DirectoryGuard on every route here
  return req.directory!;
}
