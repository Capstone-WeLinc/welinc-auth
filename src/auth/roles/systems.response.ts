import { ApiProperty } from '@nestjs/swagger';
import { SystemType } from '@prisma/client';

/**
 * A live role: built in roles first in catalog order (most powerful first), then custom roles by
 * name (suite spec 0018).
 */
export class CatalogRoleView {
  @ApiProperty({ example: 'ADMIN' })
  code!: string;

  @ApiProperty()
  name!: string;

  @ApiProperty()
  description!: string;

  @ApiProperty()
  isSystemAdmin!: boolean;

  @ApiProperty({
    description:
      'True for a role from the catalog file; false for a custom role a suite admin made (suite spec 0018)',
  })
  builtIn!: boolean;
}

/** One system of the suite. */
export class SystemView {
  @ApiProperty({ enum: SystemType })
  code!: SystemType;

  @ApiProperty()
  name!: string;

  @ApiProperty()
  description!: string;

  @ApiProperty({
    type: String,
    nullable: true,
    description: "The system's web app address; null when it has none",
  })
  webAddress!: string | null;

  @ApiProperty({ type: Number, nullable: true })
  maxRolesPerUser!: number | null;

  @ApiProperty({ type: [CatalogRoleView] })
  roles!: CatalogRoleView[];
}

/** `GET /auth/systems`. */
export class SystemsResponse {
  @ApiProperty({ type: [SystemView] })
  systems!: SystemView[];
}
