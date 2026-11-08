import type { SystemDefinition } from '../../src/auth/roles/catalog.types';

// BMS roles (spec 0004), owned by the BMS group: reword the descriptions freely. Order is
// display order and power order; never change a code once synced, add a new one instead.
export const bms: SystemDefinition = {
  system: 'BMS',
  name: 'Booking Management System',
  maxRolesPerUser: 1,
  roles: [
    {
      code: 'ADMIN',
      name: 'Admin',
      description: 'Manages BMS users and settings',
      isSystemAdmin: true,
    },
    {
      code: 'OPERATIONS',
      name: 'Operations',
      description: 'Plans trips and dispatch',
    },
    {
      code: 'CUSTOMER_SUPPORT',
      name: 'Customer Support',
      description: 'Handles bookings and customers',
    },
    {
      code: 'DRIVER',
      name: 'Driver',
      description: 'Drives assigned trips (BMS mobile)',
    },
    {
      code: 'HELPER',
      name: 'Helper',
      description: 'Assists drivers on trips (BMS mobile)',
    },
  ],
};
