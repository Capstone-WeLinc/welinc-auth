import type { SystemDefinition } from '../../src/auth/roles/catalog.types';

// VRMS roles (spec 0004). Order is display order and power order; never change a code once
// synced, add a new one instead.
export const vrms: SystemDefinition = {
  system: 'VRMS',
  name: 'Vehicle Repair Management System',
  maxRolesPerUser: 1,
  roles: [
    {
      code: 'ADMIN',
      name: 'Admin',
      description: 'Manages VRMS users, settings and every ticket',
      isSystemAdmin: true,
    },
    {
      code: 'CHIEF_MECHANIC',
      name: 'Chief Mechanic',
      description: 'Assigns work and verifies finished repairs',
    },
    {
      code: 'MECHANIC',
      name: 'Mechanic',
      description: 'Works the repair tickets assigned to them',
    },
  ],
};
