import { ApiProperty } from '@nestjs/swagger';
import { SystemType } from '@prisma/client';

// The launcher body as `docs/openapi.json` describes it (spec 0007; suite spec 0014, AC-4;
// suite spec 0016, AC-12a). The service builds the `LauncherAnswer` type in `launcher.ts`.

export class LauncherRoleResponse {
  @ApiProperty({ example: 'MECHANIC' })
  code!: string;

  @ApiProperty({ example: 'Mechanic' })
  name!: string;
}

export class LauncherUserResponse {
  @ApiProperty()
  id!: string;

  @ApiProperty({ example: 'VRMS Admin' })
  name!: string;

  @ApiProperty({ example: 'admin@welinc.com' })
  email!: string;

  @ApiProperty({ type: String, nullable: true })
  picture!: string | null;
}

export class LauncherSystemResponse {
  @ApiProperty({ enum: SystemType })
  system!: SystemType;

  @ApiProperty({ example: 'VRMS' })
  name!: string;

  @ApiProperty()
  description!: string;

  @ApiProperty({ description: 'Where the system opens' })
  url!: string;

  @ApiProperty({ type: [LauncherRoleResponse] })
  roles!: LauncherRoleResponse[];
}

export class LauncherAppResponse {
  @ApiProperty()
  clientId!: string;

  @ApiProperty()
  released!: boolean;
}

export class LauncherMobileSystemResponse {
  @ApiProperty({ enum: SystemType })
  system!: SystemType;

  @ApiProperty({ example: 'VMMS' })
  name!: string;

  @ApiProperty()
  description!: string;

  @ApiProperty({ type: [LauncherRoleResponse] })
  roles!: LauncherRoleResponse[];

  @ApiProperty({ type: LauncherAppResponse })
  app!: LauncherAppResponse;
}

/** `GET /auth/sso`, `POST /auth/login` and `POST /auth/login/verify-email`. */
export class LauncherAnswerResponse {
  @ApiProperty({ type: LauncherUserResponse })
  user!: LauncherUserResponse;

  @ApiProperty({ type: [LauncherSystemResponse] })
  systems!: LauncherSystemResponse[];

  @ApiProperty({ type: [LauncherMobileSystemResponse] })
  mobileSystems!: LauncherMobileSystemResponse[];

  @ApiProperty({
    description:
      'Whether the signed in person is a suite admin (suite spec 0019, AC-6)',
  })
  suiteAdmin!: boolean;

  @ApiProperty({
    description:
      'The earlier of the idle and the 12 hour cutoff of this browser session (ISO 8601)',
  })
  sessionExpiresAt!: string;

  @ApiProperty({
    description: 'The 12 hour cutoff of this browser session (ISO 8601)',
  })
  sessionAbsoluteExpiresAt!: string;

  @ApiProperty({
    description:
      "The server's clock when it answered (ISO 8601), so the portal can count on the server's time",
  })
  serverTime!: string;
}
