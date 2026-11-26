import { describe, it, expect, jest } from '@jest/globals';
import { HttpException, HttpStatus } from '@nestjs/common';
import type { Response } from 'express';
import type { AuthService } from '../auth.service';
import type { AdminRequest } from '../admin/admin-session.guard';
import { AdminRolesController } from './admin-roles.controller';
import type { RolesAdminService } from './roles-admin.service';

// covers: suite spec 0018, child 0001 AC-17 (the read and history routes: no-store, who may read,
// what the service is asked for)

function request(standing: {
  suiteAdmin: boolean;
  adminOf: string[];
}): AdminRequest {
  return {
    ip: '127.0.0.1',
    headers: {},
    portalAdmin: {
      userId: 'u1',
      sid: 's1',
      user: {
        id: 'u1',
        name: 'Leonora',
        email: 'suite.admin@welinc.com',
        profilePicture: null,
      },
      standing,
      codeRequired: false,
      codePassed: true,
    },
  } as unknown as AdminRequest;
}

function setup() {
  const roles = {
    page: jest.fn<(...args: unknown[]) => Promise<unknown>>(() =>
      Promise.resolve({
        system: 'VRMS',
      }),
    ),
    history: jest.fn<(...args: unknown[]) => Promise<unknown>>(() =>
      Promise.resolve({
        items: [],
        next: null,
      }),
    ),
  };
  const headers: Record<string, string> = {};
  const res = {
    setHeader: (name: string, value: string) => {
      headers[name] = value;
    },
  } as unknown as Response;
  const controller = new AdminRolesController(
    roles as unknown as RolesAdminService,
    {} as AuthService,
  );
  return { controller, roles, res, headers };
}

async function refusal(run: () => unknown): Promise<HttpException> {
  try {
    await run();
  } catch (error) {
    return error as HttpException;
  }
  throw new Error('expected the call to be refused');
}

describe('AdminRolesController read routes (AC-17)', () => {
  it('lets a suite admin read any system, with canEdit true and no store', async () => {
    const { controller, roles, res, headers } = setup();
    await controller.read(
      'vrms',
      request({ suiteAdmin: true, adminOf: [] }),
      res,
    );
    expect(roles.page).toHaveBeenCalledWith('VRMS', true);
    expect(headers['Cache-Control']).toBe('no-store');
  });

  it('lets a system admin read their own system with canEdit false', async () => {
    const { controller, roles, res } = setup();
    await controller.read(
      'VRMS',
      request({ suiteAdmin: false, adminOf: ['VRMS'] }),
      res,
    );
    expect(roles.page).toHaveBeenCalledWith('VRMS', false);
  });

  it('refuses an admin of another system with 403 NOT_ADMIN_OF_SYSTEM', async () => {
    const { controller, roles, res } = setup();
    const error = await refusal(() =>
      controller.read(
        'VRMS',
        request({ suiteAdmin: false, adminOf: ['BMS'] }),
        res,
      ),
    );
    expect(error.getStatus()).toBe(HttpStatus.FORBIDDEN);
    expect(error.getResponse()).toMatchObject({ code: 'NOT_ADMIN_OF_SYSTEM' });
    expect(roles.page).not.toHaveBeenCalled();
  });

  it('answers 404 for a system that does not exist', async () => {
    const { controller, res } = setup();
    const error = await refusal(() =>
      controller.read('NOPE', request({ suiteAdmin: true, adminOf: [] }), res),
    );
    expect(error.getStatus()).toBe(HttpStatus.NOT_FOUND);
  });

  it('reads history with no store, the cursor and a numeric limit, and refuses a foreign admin', async () => {
    const { controller, roles, res, headers } = setup();
    await controller.history(
      'VRMS',
      'MECHANIC',
      { cursor: 'abc', limit: '25' },
      request({ suiteAdmin: false, adminOf: ['VRMS'] }),
      res,
    );
    expect(roles.history).toHaveBeenCalledWith('VRMS', 'MECHANIC', {
      cursor: 'abc',
      limit: 25,
    });
    expect(headers['Cache-Control']).toBe('no-store');
    const error = await refusal(() =>
      controller.history(
        'VRMS',
        'MECHANIC',
        {},
        request({ suiteAdmin: false, adminOf: ['BMS'] }),
        res,
      ),
    );
    expect(error.getResponse()).toMatchObject({ code: 'NOT_ADMIN_OF_SYSTEM' });
  });

  it('answers 404 for a role code that cannot exist', async () => {
    const { controller, res } = setup();
    const error = await refusal(() =>
      controller.history(
        'VRMS',
        'not a code!',
        {},
        request({ suiteAdmin: true, adminOf: [] }),
        res,
      ),
    );
    expect(error.getStatus()).toBe(HttpStatus.NOT_FOUND);
  });
});
