import type { SystemDefinition } from '../../src/auth/roles/catalog.types';

/** One cell default per VRMS role, in role order. */
function defaults(admin: boolean, chief: boolean, mechanic: boolean) {
  return { ADMIN: admin, CHIEF_MECHANIC: chief, MECHANIC: mechanic };
}

// VRMS roles (spec 0004). Order is display order and power order; never change a code once
// synced, add a new one instead.
export const vrms: SystemDefinition = {
  system: 'VRMS',
  name: 'Vehicle Repair Management System',
  description: 'Repair tickets, mechanics and workshop work',
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
  // Spec 0013, AC-25: moved from backend-vrms's catalog.ts, minus users.manage and
  // permissions.manage (account and matrix editing live in welinc-auth now). VRMS keeps the
  // keys, modules and CASL rules; a key VRMS adds must be added here too, Admin on and the
  // other roles off unless its spec says otherwise. Never rename a synced key.
  permissions: [
    {
      key: 'ticket.view',
      label: 'See tickets assigned to you',
      group: 'Tickets',
      description: 'Open and list the repair tickets you are assigned to.',
      defaults: defaults(true, true, true),
    },
    {
      key: 'ticket.view_all',
      label: 'See every ticket',
      group: 'Tickets',
      description: 'Open and list every repair ticket, whoever is assigned.',
      defaults: defaults(true, true, false),
    },
    {
      key: 'ticket.create',
      label: 'Create tickets and pick mechanics',
      group: 'Tickets',
      description: 'Open new repair tickets and assign mechanics to them.',
      defaults: defaults(true, false, false),
    },
    {
      key: 'ticket.work',
      label: 'Work your assigned tickets (status, steps, knowledge link)',
      group: 'Tickets',
      description:
        'Start work and send for verification, tick steps and link known fixes on your own tickets.',
      defaults: defaults(false, true, true),
    },
    {
      key: 'ticket.administer',
      label: 'Cancel tickets and make work moves on any ticket',
      group: 'Tickets',
      description:
        'Cancel any open ticket, start work and send for verification on any ticket, and change its steps and known fixes.',
      defaults: defaults(true, false, false),
    },
    {
      key: 'ticket.verify',
      label: 'Verify or send back finished work',
      group: 'Tickets',
      description:
        'Close a ticket that is waiting for verification, or send it back with a comment. Never on a ticket you are assigned to.',
      defaults: defaults(true, true, false),
    },
    {
      key: 'ticket.costs.view',
      label: 'See costs',
      group: 'Tickets',
      description: 'See parts, labor and total costs on tickets and in history.',
      defaults: defaults(true, true, false),
    },
    {
      key: 'ticket.costs.edit',
      label: 'Encode costs',
      group: 'Tickets',
      description: 'Enter or change the costs of a ticket.',
      defaults: defaults(true, false, false),
    },
    {
      key: 'ticket.assign',
      label: 'Assign mechanics',
      group: 'Tickets',
      description: 'Add, remove or swap the in house mechanics on any open ticket.',
      defaults: defaults(true, true, false),
    },
    {
      // Suite spec 0018 child 0002, AC-33: the VRMS mechanic roster is everyone holding this
      key: 'ticket.assignable',
      label: 'Can be assigned tickets',
      group: 'Tickets',
      description:
        'Shows up in the mechanic list, so tickets can be assigned to you.',
      defaults: defaults(false, true, true),
    },
    {
      key: 'ticket.edit',
      label: 'Edit ticket details and issues',
      group: 'Tickets',
      description:
        'Fix the driver, odometer, priority and account of a ticket, and add, reword or remove its issues.',
      defaults: defaults(true, false, false),
    },
    {
      // VRMS spec 0030, AC-8: Admin and Chief Mechanic on by default
      key: 'ticket.due_date.edit',
      label: 'Change due dates',
      group: 'Tickets',
      description:
        "Set a ticket's due date by hand, or put it back to the automatic date.",
      defaults: defaults(true, true, false),
    },
    {
      key: 'ticket.unlock',
      label: 'Unlock closed tickets',
      group: 'Tickets',
      description: 'Reopen a closed or cancelled ticket for corrections.',
      defaults: defaults(true, false, false),
    },
    {
      key: 'ticket.checklist.edit',
      label: 'Edit ticket checklists',
      group: 'Tickets',
      description:
        "Add, reword, remove and reorder the steps on a ticket's issues. Without See every ticket, only on tickets assigned to you.",
      defaults: defaults(true, true, true),
    },
    {
      key: 'ticket.files.add',
      label: 'Add vehicle photos and proof',
      group: 'Tickets',
      description: 'Add vehicle photos and proof of completion on the tickets you can see.',
      defaults: defaults(true, true, true),
    },
    {
      key: 'ticket.documents.add',
      label: 'Add receipts and other documents',
      group: 'Tickets',
      description:
        'Add receipts and other documents on the tickets you can see. Needs See costs too.',
      defaults: defaults(true, true, false),
    },
    {
      key: 'ticket.files.remove_any',
      label: 'Remove anyone’s files',
      group: 'Tickets',
      description:
        'Remove photos, proof and documents that someone else added, on the tickets you can see.',
      defaults: defaults(true, true, false),
      lockedRoles: ['MECHANIC'],
    },
    {
      key: 'ai.use',
      label: 'Use AI diagnosis',
      group: 'Tickets',
      description: 'Run AI diagnoses on tickets you can read, and rate them.',
      defaults: defaults(true, true, true),
    },
    {
      // VRMS spec 0029, AC-11
      key: 'integration.respond',
      label: 'Answer other systems',
      group: 'Tickets',
      description:
        'Accept or reject VMMS referrals, answer BMS expedite requests, and retry failed deliveries.',
      defaults: defaults(true, false, false),
    },
    {
      key: 'audit.view',
      label: 'See the audit log',
      group: 'Records',
      description: 'Read the audit timeline of every ticket.',
      defaults: defaults(true, false, false),
    },
    {
      key: 'analytics.view',
      label: 'See the Analytics page',
      group: 'Records',
      description: 'Open the analytics dashboards and AI insights.',
      defaults: defaults(true, false, false),
    },
    {
      key: 'config.read',
      label: 'Read garages, vehicles, drivers and mechanics',
      group: 'Records',
      description: 'Read the garage, vehicle, driver and mechanic lists.',
      defaults: defaults(true, true, true),
    },
    {
      key: 'mechanics.view',
      label: "See the team's workload",
      group: 'Records',
      description:
        'See the Team section on the dashboard: who holds which tickets, and their open tickets.',
      defaults: defaults(true, true, false),
    },
    {
      key: 'vehicle.manage',
      label: 'Manage vehicles',
      group: 'Records',
      description: 'Set a vehicle type on each truck in Settings.',
      defaults: defaults(true, false, false),
    },
    {
      key: 'knowledge.view',
      label: 'Read the fix library',
      group: 'Knowledge',
      description: 'Read the active entries of the fix library.',
      defaults: defaults(true, true, true),
    },
    {
      key: 'knowledge.suggest',
      label: 'Suggest a fix library entry',
      group: 'Knowledge',
      description: 'Send a suggestion for a new or changed entry.',
      defaults: defaults(true, true, true),
    },
    {
      key: 'knowledge.edit',
      label: 'Edit the fix library and review suggestions',
      group: 'Knowledge',
      description: 'Write entries, see drafts and costs, and review suggestions.',
      defaults: defaults(true, true, false),
    },
    {
      key: 'team.manage',
      label: 'Manage the team',
      group: 'Admin',
      description:
        'See everyone in VRMS with their open work, and unassign or reassign their tickets.',
      defaults: defaults(true, false, false),
      // Admin always keeps it, so no matrix edit hides the team from every admin
      lockedRoles: ['ADMIN'],
    },
    {
      key: 'settings.manage',
      label: 'Change settings and modules',
      group: 'Admin',
      description:
        'Change thresholds, turn modules on or off, and read the change history.',
      defaults: defaults(true, false, false),
      // Admin always keeps it, so no matrix edit locks everyone out of Settings
      lockedRoles: ['ADMIN'],
    },
    {
      key: 'lookups.manage',
      label: 'Edit lookup lists',
      group: 'Admin',
      description:
        'Add, rename and deactivate issue categories, vehicle types and corporations.',
      defaults: defaults(true, true, false),
    },
  ],
};
