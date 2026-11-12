import { describe, expect, it } from '@jest/globals';
import {
  fileProblems,
  IMPORTED_SYSTEM_ACTOR,
  planImport,
  type PermissionsExport,
} from './import-plan';

// Suite spec 0013, AC-28: the one time import of the VRMS matrix.

const file = (over: Partial<PermissionsExport> = {}): PermissionsExport => ({
  format: 'welinc-permissions-export',
  formatVersion: 1,
  system: 'VRMS',
  exportedAt: '2026-11-13T00:00:00.000Z',
  cells: [
    { role: 'CHIEF_MECHANIC', key: 'ticket.view', allowed: false },
    { role: 'ADMIN', key: 'team.manage', allowed: false },
    { role: 'CHIEF_MECHANIC', key: 'users.manage', allowed: true },
    { role: 'MECHANIC', key: 'permissions.manage', allowed: false },
  ],
  changes: [
    {
      role: 'CHIEF_MECHANIC',
      key: 'ticket.view',
      before: true,
      after: false,
      actorId: 'u-gone',
      actorName: 'Old Admin',
      actorEmail: 'old@example.com',
      note: 'x'.repeat(600),
      createdAt: '2026-11-01T08:00:00.000Z',
    },
    {
      role: 'ADMIN',
      key: 'ticket.view',
      before: null,
      after: true,
      actorId: null,
      actorName: null,
      actorEmail: null,
      note: null,
      createdAt: '2026-10-29T08:00:00.000Z',
    },
  ],
  ...over,
});

const current = {
  roles: ['ADMIN', 'CHIEF_MECHANIC', 'MECHANIC'],
  permissions: [
    { key: 'ticket.view', lockedRoles: [] },
    { key: 'team.manage', lockedRoles: ['ADMIN'] },
  ],
  cells: [
    { role: 'CHIEF_MECHANIC', key: 'ticket.view', allowed: true },
    { role: 'ADMIN', key: 'team.manage', allowed: true },
    { role: 'CHIEF_MECHANIC', key: 'team.manage', allowed: false },
  ],
  userIds: new Set<string>(),
};

describe('planImport (AC-28)', () => {
  it('sets known unlocked cells and carries users.manage onto team.manage', () => {
    const plan = planImport(file(), current);
    expect(plan.sets).toEqual([
      { role: 'CHIEF_MECHANIC', key: 'ticket.view', allowed: false },
      { role: 'CHIEF_MECHANIC', key: 'team.manage', allowed: true },
    ]);
  });

  it('skips locked cells and keys that left, listing why', () => {
    const plan = planImport(file(), current);
    expect(plan.skipped).toEqual([
      'ADMIN team.manage: locked, keeps its default',
      'MECHANIC permissions.manage: no such permission',
    ]);
  });

  it('keeps original times and names, drops unknown actor ids, cuts notes to 500', () => {
    const [kept, system] = planImport(file(), current).history;
    expect(kept).toMatchObject({
      actorId: null,
      actorName: 'Old Admin',
      createdAt: new Date('2026-11-01T08:00:00.000Z'),
    });
    expect(kept.note).toHaveLength(500);
    expect(system.actorName).toBe(IMPORTED_SYSTEM_ACTOR);
  });

  it('keeps an actor id that exists here', () => {
    const plan = planImport(file(), {
      ...current,
      userIds: new Set(['u-gone']),
    });
    expect(plan.history[0].actorId).toBe('u-gone');
  });
});

describe('fileProblems (AC-28)', () => {
  it('refuses another system or another format', () => {
    expect(fileProblems(file(), 'BMS')).toEqual([
      'The file is for VRMS, not BMS',
    ]);
    expect(fileProblems({ format: 'x' }, 'VRMS')).toHaveLength(1);
    expect(fileProblems(file(), 'VRMS')).toEqual([]);
  });
});
