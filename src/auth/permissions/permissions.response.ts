import { ApiProperty } from '@nestjs/swagger';
import { SystemType } from '@prisma/client';

/** One permission key of the system. */
export class PermissionKeyView {
  @ApiProperty({ example: 'repairs.approve' })
  key!: string;

  @ApiProperty({
    type: [String],
    description: 'Roles whose cell for this key can never change',
  })
  lockedRoles!: string[];
}

/** `GET /auth/permissions/{system}`: the system's matrix. */
export class SystemMatrixResponse {
  @ApiProperty({ enum: SystemType })
  system!: SystemType;

  @ApiProperty({ description: 'Raised on every change; also the ETag' })
  version!: number;

  @ApiProperty({ type: [PermissionKeyView] })
  permissions!: PermissionKeyView[];

  @ApiProperty({
    type: 'object',
    additionalProperties: { type: 'array', items: { type: 'string' } },
    description:
      'Role code to the permission keys it holds; every role has an entry',
  })
  grants!: Record<string, string[]>;
}
