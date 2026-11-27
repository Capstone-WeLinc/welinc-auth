import { SystemType } from '@prisma/client';
import { CATALOG } from '../../../prisma/catalog';
import {
  CatalogService,
  type AdminRoles,
  type CatalogSystem,
} from '../roles/catalog.service';
import type { SystemDefinition } from '../roles/catalog.types';
import type { PrismaService } from '../../shared/prisma.service';

/** The catalog from in memory definitions (the real files by default), for unit tests. */
export class FakeCatalogService extends CatalogService {
  private readonly entries: CatalogSystem[];

  constructor(definitions: SystemDefinition[] = CATALOG) {
    super({} as PrismaService);
    this.entries = definitions.map((d) => ({
      code: d.system,
      name: d.name,
      description: d.description,
      maxRolesPerUser: d.maxRolesPerUser,
      roles: d.roles.map((r) => ({
        code: r.code,
        name: r.name,
        description: r.description,
        isSystemAdmin: r.isSystemAdmin === true,
        builtIn: true,
      })),
    }));
  }

  override systems(): Promise<CatalogSystem[]> {
    return Promise.resolve(this.entries);
  }

  override system(system: SystemType): Promise<CatalogSystem | null> {
    return Promise.resolve(this.entries.find((e) => e.code === system) ?? null);
  }

  override adminRoles(): Promise<AdminRoles> {
    return Promise.resolve(
      new Map(
        this.entries.flatMap((e) =>
          e.roles
            .filter((r) => r.isSystemAdmin)
            .map((r) => [e.code, r.code] as const),
        ),
      ),
    );
  }

  /** No row locks in unit tests: the same UNKNOWN_ROLE check against the fake catalog. */
  override async lockLiveRoles(
    _tx: unknown,
    system: SystemType,
    codes: string[],
  ): Promise<void> {
    for (const code of new Set(codes)) {
      await this.assertKnownRole(system, code);
    }
  }
}
