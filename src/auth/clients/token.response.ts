import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { SystemType } from '@prisma/client';

/** A role in one system. */
export class RoleRef {
  @ApiProperty({ example: 'ADMIN' })
  role!: string;

  @ApiProperty({ example: 'VRMS' })
  system!: string;
}

/** The live role codes a person holds in one system (VRMS spec 0027, step 6a). */
export class SystemRolesRef {
  @ApiProperty({ enum: SystemType, example: 'VMMS' })
  system!: SystemType;

  @ApiProperty({
    type: [String],
    example: ['ADMIN'],
    description:
      'Role codes held there, in catalog order (a live temporary role included). Display only',
  })
  roles!: string[];
}

/** The signed in person a user grant answers with. */
export class GrantUser {
  @ApiProperty()
  id!: string;

  @ApiProperty({ example: 'VRMS Admin' })
  name!: string;

  @ApiProperty({ example: 'admin@welinc.com' })
  email!: string;

  @ApiProperty({ type: [RoleRef] })
  roles!: RoleRef[];

  @ApiProperty({
    enum: SystemType,
    isArray: true,
    description: 'The web systems the person can open, in launcher order',
  })
  systems!: SystemType[];

  @ApiProperty({
    type: [SystemRolesRef],
    description:
      'One entry per system in `systems`, same order: the role codes held there. Never in the token',
  })
  systemRoles!: SystemRolesRef[];

  @ApiProperty({
    description: 'Whether the person is a suite admin. Never in the token',
  })
  suiteAdmin!: boolean;
}

/**
 * `POST /auth/token` (RFC 6749 section 5.1). `client_credentials` sends `scope`; the user grants
 * (`authorization_code`, `refresh_token`) send `refresh_token`, `sid`, `session_expires_at` and
 * `user`, plus `session_absolute_expires_at` for a web session.
 */
export class TokenResponse {
  @ApiProperty()
  access_token!: string;

  @ApiProperty({ enum: ['Bearer'] })
  token_type!: 'Bearer';

  @ApiProperty({ description: 'Seconds until the access token expires' })
  expires_in!: number;

  @ApiPropertyOptional({
    description:
      '`client_credentials` only: the granted scopes, space separated',
    example: 'directory.read',
  })
  scope?: string;

  @ApiPropertyOptional({ description: 'User grants only' })
  refresh_token?: string;

  @ApiPropertyOptional({ description: 'User grants only: the session id' })
  sid?: string;

  @ApiPropertyOptional({
    description: 'User grants only: when the session ends if idle (ISO 8601)',
  })
  session_expires_at?: string;

  @ApiPropertyOptional({
    description:
      'User grants on a web session only: the hard end of the session (ISO 8601)',
  })
  session_absolute_expires_at?: string;

  @ApiPropertyOptional({ type: GrantUser, description: 'User grants only' })
  user?: GrantUser;
}
