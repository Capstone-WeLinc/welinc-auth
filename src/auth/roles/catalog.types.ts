import type { SystemType } from '@prisma/client';

// Spec 0004: each system's roles, written in prisma/catalog/<system>.ts and copied into the
// `systems` and `system_roles` tables by `npm run catalog:sync`.

/** A role code as stored in `user_roles.role` and the token's `roles` claim. */
export type RoleCode = string;

export type RoleAssignment = { role: RoleCode; system: SystemType };

/** The shape every role code must have (AC-3, and the DTOs). */
export const ROLE_CODE_RE = /^[A-Z][A-Z0-9_]{1,39}$/;

export type RoleDefinition = {
  code: RoleCode;
  name: string;
  description: string;
  /** Exactly one role per system carries this: the system's admin (AC-14). */
  isSystemAdmin?: boolean;
};

export type SystemDefinition = {
  system: SystemType;
  name: string;
  /** One line for the portal launcher card, 1 to 200 characters (spec 0007, AC-5). */
  description: string;
  /** A whole number of at least 1, or null for no limit (AC-1). */
  maxRolesPerUser: number | null;
  /** Display order and power order: the first is the most powerful (AC-1). */
  roles: RoleDefinition[];
};
