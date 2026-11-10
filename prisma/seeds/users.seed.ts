import { Prisma, SystemType } from '@prisma/client';
import * as argon2 from 'argon2';
import {
  emailConflicts,
  stateFields,
  type Manifest,
  type ManifestPerson,
} from './manifest';

// Spec 0006: seed people come only from people.json. Each person is upserted by their fixed id,
// so every system links its own rows to the same ids, and users not in the manifest are never
// touched (outside a local --reset).

/** Each distinct password hashed once, before the transaction opens (argon2 is slow on purpose). */
export async function hashSeedPasswords(
  manifest: Manifest,
): Promise<Map<string, string>> {
  const hashes = new Map<string, string>();
  for (const [key, plain] of Object.entries(manifest.passwords)) {
    hashes.set(key, await argon2.hash(plain));
  }
  return hashes;
}

/**
 * AC-9: removes every user and what hangs off them, in foreign key order. Sessions go first
 * (their refresh tokens and login codes cascade). login_requests and directory_changes have no
 * user key and stay.
 */
export async function resetUsers(tx: Prisma.TransactionClient) {
  await tx.session.deleteMany({});
  await tx.userChange.deleteMany({});
  // Spec 0009, AC-16 (they also cascade with their users; cleared first to be explicit)
  await tx.verificationCode.deleteMany({});
  await tx.userRoleAssignment.deleteMany({});
  await tx.user.deleteMany({});
}

export class SeedConflictError extends Error {
  constructor(readonly problems: string[]) {
    super(
      `These manifest emails belong to other users:\n  ${problems.join('\n  ')}\n` +
        'Nothing was written. Free the emails, or run npm run seed -- --reset on a local database.',
    );
  }
}

export type UserBefore = {
  id: string;
  email: string;
  lockedAt: Date | null;
  deletedAt: Date | null;
};

/**
 * AC-7: the database as it was before the run, for the manifest's ids and emails. Read before a
 * --reset wipe too, so a recreated locked or deleted person keeps their old time and the
 * directory feed sees no change (AC-8).
 */
export async function readUsersBefore(
  tx: Prisma.TransactionClient,
  people: ManifestPerson[],
): Promise<UserBefore[]> {
  const ids = people.map((p) => p.id);
  return tx.user.findMany({
    where: {
      OR: [
        { id: { in: ids } },
        {
          email: {
            in: people.map((p) => p.email.toLowerCase()),
            mode: 'insensitive',
          },
        },
      ],
    },
    select: { id: true, email: true, lockedAt: true, deletedAt: true },
  });
}

/**
 * AC-7: upserts each manifest person by id and sets exactly their listed roles, inside the
 * caller's transaction. Refuses (throws, so the transaction rolls back) when a manifest email is
 * held by another id; after a --reset wipe nobody holds one, so pass `checkConflicts: false`.
 * `now` is the run's one clock (AC-5).
 */
export async function seedPeople(
  tx: Prisma.TransactionClient,
  people: ManifestPerson[],
  hashes: Map<string, string>,
  now: Date,
  before: UserBefore[],
  checkConflicts: boolean,
) {
  if (checkConflicts) {
    const conflicts = emailConflicts(people, before);
    if (conflicts.length > 0) throw new SeedConflictError(conflicts);
  }

  const existing = new Map(before.map((u) => [u.id, u]));
  for (const person of people) {
    const passwordHash = hashes.get(person.password);
    if (passwordHash === undefined) {
      throw new Error(`No password hash for key ${person.password}`);
    }
    const fields = {
      name: person.name,
      email: person.email.toLowerCase(),
      contact: person.contact,
      passwordHash,
      ...stateFields(person.state, existing.get(person.id), now),
    };
    await tx.user.upsert({
      where: { id: person.id },
      create: { id: person.id, ...fields },
      update: fields,
    });

    const listed = person.roles.map((r) => ({
      system: r.system as SystemType,
      role: r.role,
    }));
    await tx.userRoleAssignment.deleteMany({
      where: {
        userId: person.id,
        ...(listed.length > 0 ? { NOT: { OR: listed } } : {}),
      },
    });
    if (listed.length > 0) {
      await tx.userRoleAssignment.createMany({
        data: listed.map((r) => ({ userId: person.id, ...r })),
        skipDuplicates: true,
      });
    }
  }
}
