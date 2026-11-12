import { Injectable } from '@nestjs/common';
import type { SystemType } from '@prisma/client';
import { PrismaService } from '../../shared/prisma.service';

// Spec 0013, AC-25 to AC-27: the central permission matrix. Cells live in role_permissions, keys
// in system_permissions (written by catalog:sync), and permission_matrices.version is the one
// number systems poll on.

/** AC-26: what a system backend reads, with `ETag: "v<version>"`. */
export type SystemMatrix = {
  system: SystemType;
  version: number;
  permissions: { key: string; lockedRoles: string[] }[];
  /** Every role of the system, with the keys it holds (an empty list when it holds none). */
  grants: Record<string, string[]>;
};

export function matrixEtag(version: number): string {
  return `"v${version}"`;
}

@Injectable()
export class MatrixService {
  constructor(private readonly prisma: PrismaService) {}

  /** The current version, or 1 when catalog:sync has not run for this system yet. */
  async version(system: SystemType): Promise<number> {
    const row = await this.prisma.permissionMatrix.findUnique({
      where: { system },
      select: { version: true },
    });
    return row?.version ?? 1;
  }

  /** AC-26, read in one snapshot so the version always matches the grants it is sent with. */
  async systemMatrix(system: SystemType): Promise<SystemMatrix> {
    return this.prisma.$transaction(
      async (tx) => {
        const [matrix, roles, permissions, cells] = await Promise.all([
          tx.permissionMatrix.findUnique({
            where: { system },
            select: { version: true },
          }),
          tx.systemRole.findMany({
            where: { system },
            select: { code: true },
            orderBy: { sortOrder: 'asc' },
          }),
          tx.systemPermission.findMany({
            where: { system },
            select: { key: true, lockedRoles: true },
            orderBy: { sortOrder: 'asc' },
          }),
          tx.rolePermission.findMany({
            where: { system, allowed: true },
            select: { role: true, key: true },
          }),
        ]);
        const order = new Map(permissions.map((p, i) => [p.key, i]));
        const grants: Record<string, string[]> = {};
        for (const role of roles) grants[role.code] = [];
        for (const cell of cells) grants[cell.role]?.push(cell.key);
        for (const keys of Object.values(grants)) {
          keys.sort((a, b) => (order.get(a) ?? 0) - (order.get(b) ?? 0));
        }
        return {
          system,
          version: matrix?.version ?? 1,
          permissions: permissions.map((p) => ({
            key: p.key,
            lockedRoles: p.lockedRoles ?? [],
          })),
          grants,
        };
      },
      { isolationLevel: 'RepeatableRead' },
    );
  }
}
