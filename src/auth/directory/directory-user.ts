import type { SystemType } from '@prisma/client';

/** Contract 0001 section 9 (spec 0005, AC-7). */
export type DirectoryUser = {
  id: string;
  name: string;
  email: string;
  /** `users.contact` as stored, only for a token holding `directory.contact`. */
  phone: string | null;
  /** `profile_picture` as stored (an `/uploads` address). */
  picture: string | null;
  isActive: boolean;
  deleted: boolean;
  /** Spec 0012: the person's personal data was replaced by "Deleted user" (never undone). */
  erased: boolean;
  /** Role codes in the caller's system only. */
  roles: string[];
  /**
   * Spec 0013, AC-11: the codes in `roles` that are temporary access a suite admin gave
   * themselves. A system keeps them out of its pickers and rosters (VRMS skips them as mechanics).
   */
  temporaryRoles: string[];
  updatedAt: string;
};

export type DirectoryChangeType =
  | 'created'
  | 'updated'
  | 'roles_changed'
  | 'activated'
  | 'deactivated'
  | 'deleted';

export type DirectoryChange = {
  cursor: string;
  type: DirectoryChangeType;
  at: string;
  user: DirectoryUser;
};

/** What the caller may see: its system, and whether it may read phones. */
export type DirectoryView = { system: SystemType; canSeePhone: boolean };

/** The person as the feed trigger stores them (`directory_snapshot` in the migration). */
export type FeedSnapshot = {
  id: string;
  name: string;
  email: string;
  contact: string | null;
  profilePicture: string | null;
  isActive: boolean;
  deletedAt: string | null;
  /** Missing on snapshots written before spec 0012, which reads as not erased. */
  erasedAt?: string | null;
  updatedAt: string;
  /** `temporary` is missing on snapshots written before spec 0013, which reads as false. */
  roles: { system: string; role: string; temporary?: boolean }[];
};

/** A `users` row with its role rows, as Prisma reads it. */
export type UserRow = {
  id: string;
  name: string;
  email: string;
  contact: string | null;
  profilePicture: string | null;
  isActive: boolean;
  deletedAt: Date | null;
  erasedAt: Date | null;
  updatedAt: Date;
  roles: { system: string; role: string; temporaryGrantId: string | null }[];
};

type RoleIn = { system: string; role: string; temporary?: boolean };

/** Roles of one system, sorted so the same state always answers the same list. */
function rolesIn(
  roles: RoleIn[],
  system: SystemType,
  onlyTemporary = false,
): string[] {
  return roles
    .filter((assignment) => assignment.system === system)
    .filter((assignment) => !onlyTemporary || assignment.temporary === true)
    .map((assignment) => assignment.role)
    .sort();
}

export function fromUserRow(row: UserRow, view: DirectoryView): DirectoryUser {
  const roles = row.roles.map((assignment) => ({
    system: assignment.system,
    role: assignment.role,
    temporary: assignment.temporaryGrantId !== null,
  }));
  return {
    id: row.id,
    name: row.name,
    email: row.email,
    phone: view.canSeePhone ? row.contact : null,
    picture: row.profilePicture,
    isActive: row.isActive,
    deleted: row.deletedAt !== null,
    erased: row.erasedAt !== null,
    roles: rolesIn(roles, view.system),
    temporaryRoles: rolesIn(roles, view.system, true),
    updatedAt: row.updatedAt.toISOString(),
  };
}

export function fromSnapshot(
  snapshot: FeedSnapshot,
  view: DirectoryView,
): DirectoryUser {
  return {
    id: snapshot.id,
    name: snapshot.name,
    email: snapshot.email,
    phone: view.canSeePhone ? snapshot.contact : null,
    picture: snapshot.profilePicture,
    isActive: snapshot.isActive,
    deleted: snapshot.deletedAt !== null,
    erased: snapshot.erasedAt != null,
    roles: rolesIn(snapshot.roles, view.system),
    temporaryRoles: rolesIn(snapshot.roles, view.system, true),
    // Postgres writes `2026-11-09T10:00:00.123+00:00`; answer the same ISO form as the rows
    updatedAt: new Date(snapshot.updatedAt).toISOString(),
  };
}
