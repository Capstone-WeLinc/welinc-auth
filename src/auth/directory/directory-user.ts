import type { SystemType } from '@prisma/client';

/** Contract 0001 section 9 (spec 0005, AC-7). */
export type DirectoryUser = {
  id: string;
  name: string;
  email: string;
  /** `users.contact` as stored, only for a token holding `directory.contact`. */
  phone: string | null;
  /** False until S8 adds phone verification. */
  phoneVerified: boolean;
  /** `profile_picture` as stored (an `/uploads` address). */
  picture: string | null;
  isActive: boolean;
  deleted: boolean;
  /** Role codes in the caller's system only. */
  roles: string[];
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
  updatedAt: string;
  roles: { system: string; role: string }[];
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
  updatedAt: Date;
  roles: { system: string; role: string }[];
};

/** Roles of one system, sorted so the same state always answers the same list. */
function rolesIn(
  roles: { system: string; role: string }[],
  system: SystemType,
): string[] {
  return roles
    .filter((assignment) => assignment.system === system)
    .map((assignment) => assignment.role)
    .sort();
}

export function fromUserRow(row: UserRow, view: DirectoryView): DirectoryUser {
  return {
    id: row.id,
    name: row.name,
    email: row.email,
    phone: view.canSeePhone ? row.contact : null,
    phoneVerified: false,
    picture: row.profilePicture,
    isActive: row.isActive,
    deleted: row.deletedAt !== null,
    roles: rolesIn(row.roles, view.system),
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
    phoneVerified: false,
    picture: snapshot.profilePicture,
    isActive: snapshot.isActive,
    deleted: snapshot.deletedAt !== null,
    roles: rolesIn(snapshot.roles, view.system),
    // Postgres writes `2026-11-09T10:00:00.123+00:00`; answer the same ISO form as the rows
    updatedAt: new Date(snapshot.updatedAt).toISOString(),
  };
}
