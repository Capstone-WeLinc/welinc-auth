import { ApiProperty } from '@nestjs/swagger';

/** The person behind a session. */
export class SessionUser {
  @ApiProperty()
  id!: string;

  @ApiProperty({ example: 'VRMS Admin' })
  name!: string;

  @ApiProperty({ example: 'admin@welinc.com' })
  email!: string;
}

/** `GET /auth/session`: the token's session is live. */
export class SessionResponse {
  @ApiProperty({ enum: [true] })
  active!: true;

  @ApiProperty()
  sid!: string;

  @ApiProperty({
    description: 'The earlier of the idle and the absolute end (ISO 8601)',
  })
  expiresAt!: string;

  @ApiProperty({ type: SessionUser })
  user!: SessionUser;
}
