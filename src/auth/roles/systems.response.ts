import { ApiProperty } from '@nestjs/swagger';
import { SystemType } from '@prisma/client';

/** A role from the catalog, in display order (most powerful first). */
export class CatalogRoleView {
  @ApiProperty({ example: 'ADMIN' })
  code!: string;

  @ApiProperty()
  name!: string;

  @ApiProperty()
  description!: string;

  @ApiProperty()
  isSystemAdmin!: boolean;
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
