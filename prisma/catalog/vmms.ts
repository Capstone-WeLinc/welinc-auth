import type { SystemDefinition } from '../../src/auth/roles/catalog.types';

// VMMS roles (spec 0004), owned by the VMMS group: reword the descriptions freely. Order is
// display order and power order; never change a code once synced, add a new one instead.
export const vmms: SystemDefinition = {
  system: 'VMMS',
  name: 'Vehicle Maintenance Management System',
  description: 'Vehicles, maintenance and fleet upkeep',
  maxRolesPerUser: 1,
  roles: [
    {
      code: 'ADMIN',
      name: 'Admin',
      description: 'Manages VMMS users and settings',
      isSystemAdmin: true,
    },
    {
      code: 'OPERATIONS',
      name: 'Operations',
      description: 'Runs maintenance planning and schedules',
    },
    {
      code: 'CHIEF_MECHANIC',
      name: 'Chief Mechanic',
      description: 'Leads the maintenance mechanics',
    },
    {
      code: 'MECHANIC',
      name: 'Mechanic',
      description: 'Does scheduled maintenance work',
    },
  ],
};
