/* eslint-disable @typescript-eslint/require-await -- test doubles */
import { describe, expect, it, jest } from '@jest/globals';
import type { Response } from 'express';
import type { MatrixService, SystemMatrix } from './matrix.service';
import { PermissionsController } from './permissions.controller';
import type { PermissionsReadRequest } from './permissions-read.guard';

// Spec 0013, AC-26: GET /auth/permissions/:system.

const body: SystemMatrix = {
  system: 'VRMS',
  version: 4,
  permissions: [{ key: 'team.manage', lockedRoles: ['ADMIN'] }],
  grants: { ADMIN: ['team.manage'], MECHANIC: [] },
};

function setup(version = 4) {
  const matrix = {
    version: jest.fn(async () => version),
    systemMatrix: jest.fn(async () => body),
  };
  const controller = new PermissionsController(
    matrix as unknown as MatrixService,
  );
  const headers: Record<string, string> = {};
  const res = {
    setHeader: (name: string, value: string) => {
      headers[name] = value;
    },
    status: jest.fn(function (this: unknown) {
      return res;
    }),
    json: jest.fn(),
    end: jest.fn(),
  };
  return {
    controller,
    matrix,
    headers,
    res: res as unknown as Response & typeof res,
  };
}

function request(
  system: 'VRMS' | 'BMS',
  ifNoneMatch?: string,
): PermissionsReadRequest {
  return {
    permissionsClient: { system },
    headers: ifNoneMatch ? { 'if-none-match': ifNoneMatch } : {},
  } as unknown as PermissionsReadRequest;
}

describe('GET /auth/permissions/:system (AC-26)', () => {
  it('answers the matrix with ETag "v<version>"', async () => {
    const { controller, headers, res } = setup();
    await controller.read('VRMS', request('VRMS'), res);
    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith(body);
    expect(headers.ETag).toBe('"v4"');
  });

  it('answers 304 with no body read when If-None-Match is current', async () => {
    const { controller, matrix, res } = setup();
    await controller.read('vrms', request('VRMS', '"v4"'), res);
    expect(res.status).toHaveBeenCalledWith(304);
    expect(matrix.systemMatrix).not.toHaveBeenCalled();
  });

  it('answers 200 again when the tag is old (a restore counts too)', async () => {
    const { controller, res } = setup();
    await controller.read('VRMS', request('VRMS', '"v9"'), res);
    expect(res.status).toHaveBeenCalledWith(200);
  });

  it("refuses another system's matrix with 403 WRONG_SYSTEM", async () => {
    const { controller, res } = setup();
    await expect(
      controller.read('VRMS', request('BMS'), res),
    ).rejects.toMatchObject({
      response: expect.objectContaining({ code: 'WRONG_SYSTEM' }),
    });
  });

  it('answers 404 for a system that does not exist', async () => {
    const { controller, res } = setup();
    await expect(
      controller.read('XYZ', request('VRMS'), res),
    ).rejects.toMatchObject({ status: 404 });
  });
});
