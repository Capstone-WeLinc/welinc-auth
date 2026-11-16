import { ApiProperty } from '@nestjs/swagger';
import { SystemType } from '@prisma/client';

/** A role in the token's system. */
export class MeRole {
  @ApiProperty({ example: 'ADMIN' })
  role!: string;

  @ApiProperty({ enum: SystemType })
  system!: SystemType;
}

/** `GET /auth/me`: the caller, with roles in the token's system only. */
export class MeResponse {
  @ApiProperty()
  id!: string;

  @ApiProperty()
  name!: string;

  @ApiProperty({ example: 'admin@welinc.com' })
  email!: string;

  @ApiProperty()
  emailVerified!: boolean;

  @ApiProperty()
  passwordSet!: boolean;

  @ApiProperty({ type: String, nullable: true })
  contact!: string | null;

  @ApiProperty({ type: String, nullable: true })
  profilePicture!: string | null;

  @ApiProperty()
  isActive!: boolean;

  @ApiProperty()
  isLocked!: boolean;

  @ApiProperty({
    type: String,
    nullable: true,
    description: 'Set only while a lock is active (ISO 8601)',
  })
  lockedAt!: string | null;

  @ApiProperty()
  createdAt!: string;

  @ApiProperty()
  updatedAt!: string;

  @ApiProperty({ type: [MeRole] })
  roles!: MeRole[];

  @ApiProperty({
    type: String,
    nullable: true,
    description: 'The new address of a pending email change',
  })
  pendingEmail!: string | null;
}
