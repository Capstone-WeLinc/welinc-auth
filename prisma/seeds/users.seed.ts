import { Prisma, SystemType } from '@prisma/client';
import type { RoleAssignment } from '../../src/auth/roles/catalog.types';
import * as argon2 from 'argon2';
import {
  BULK_MECHANICS,
  CHIEF,
  NAMED_MECHANICS,
  SEED_IDS,
  SeedPerson,
  VRMS_ADMIN,
} from './shared-ids';

// Every seeded user gets a fixed id from shared-ids.ts, so the VRMS seed can link its
// Mechanic rows to the same ids (spec 0009, AC-22).
async function seedUser(
  prisma: Prisma.TransactionClient,
  person: SeedPerson,
  passwordHash: string,
  roles: RoleAssignment[],
) {
  const user = await prisma.user.upsert({
    where: { email: person.email },
    update: { emailVerified: true },
    create: {
      id: person.id,
      name: person.name,
      email: person.email,
      emailVerified: true,
      passwordHash,
    },
  });

  for (const { role, system } of roles) {
    await prisma.userRoleAssignment.upsert({
      where: { userId_role_system: { userId: user.id, role, system } },
      update: {},
      create: { userId: user.id, role, system },
    });
  }
  return user;
}

export type SeedPasswords = {
  admin: string;
  cs: string;
  ops: string;
  mechanic: string;
};

/** Hashed before the seed transaction opens, so it stays short (argon2 is slow on purpose). */
export async function hashSeedPasswords(): Promise<SeedPasswords> {
  return {
    admin: await argon2.hash('admin1234'),
    cs: await argon2.hash('cs1234'),
    ops: await argon2.hash('ops1234'),
    mechanic: await argon2.hash('mechanic1234'),
  };
}

export async function seedUsers(
  prisma: Prisma.TransactionClient,
  passwords: SeedPasswords,
) {
  console.log('Creating partitioned admin users...');

  const adminPasswordHash = passwords.admin;

  // 1. BMS Admin
  await seedUser(
    prisma,
    {
      id: SEED_IDS.bmsAdmin,
      email: 'bms.admin@welinc.com',
      name: 'Bernardo Mendoza',
    },
    adminPasswordHash,
    [{ role: 'ADMIN', system: SystemType.BMS }],
  );

  // 2. VRMS Admin
  await seedUser(prisma, VRMS_ADMIN, adminPasswordHash, [
    { role: 'ADMIN', system: SystemType.VRMS },
  ]);

  // 3. VMMS Admin
  await seedUser(
    prisma,
    {
      id: SEED_IDS.vmmsAdmin,
      email: 'vmms.admin@welinc.com',
      name: 'Valerio Mercado',
    },
    adminPasswordHash,
    [{ role: 'ADMIN', system: SystemType.VMMS }],
  );

  console.log('  Partitioned admin users created (BMS, VRMS, VMMS)');

  // 4. CS and Ops Users
  console.log('Creating Customer Service and Operations users...');
  const csPasswordHash = passwords.cs;
  const opsPasswordHash = passwords.ops;

  await seedUser(
    prisma,
    { id: SEED_IDS.csUser, email: 'cs.user@welinc.com', name: 'Clara Reyes' },
    csPasswordHash,
    [{ role: 'CUSTOMER_SUPPORT', system: SystemType.BMS }],
  );

  await seedUser(
    prisma,
    {
      id: SEED_IDS.opsUser,
      email: 'ops.user@welinc.com',
      name: 'Oscar Santos',
    },
    opsPasswordHash,
    [{ role: 'OPERATIONS', system: SystemType.BMS }],
  );

  // 5. Mechanics (VRMS and VMMS)
  console.log('Creating sample mechanics...');
  const mechanicPassword = passwords.mechanic;
  const mechanicRoles: RoleAssignment[] = [SystemType.VRMS, SystemType.VMMS].map(
    (system) => ({ role: 'MECHANIC', system }),
  );

  for (const m of NAMED_MECHANICS) {
    await seedUser(prisma, m, mechanicPassword, mechanicRoles);
  }

  // 5b. Chief mechanic (VRMS only)
  console.log('Creating chief mechanic...');
  await seedUser(prisma, CHIEF, mechanicPassword, [
    { role: 'CHIEF_MECHANIC', system: SystemType.VRMS },
  ]);

  // 6. Bulk seeding for pagination (60 users); their Mechanic rows are made by the VRMS seed
  console.log(
    'Generating 60 additional mechanics/users with realistic names...',
  );
  for (const m of BULK_MECHANICS) {
    await seedUser(prisma, m, mechanicPassword, mechanicRoles);
  }

  console.log('  All seed users and mechanics successfully processed.\n');
}
