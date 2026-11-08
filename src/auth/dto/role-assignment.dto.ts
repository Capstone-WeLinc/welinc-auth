import { IsEnum, IsString, Matches } from 'class-validator';
import { SystemType } from '@prisma/client';
import { ROLE_CODE_RE, type RoleCode } from '../roles/catalog.types';

export class RoleAssignmentDto {
  // The shape only: whether the system has this role is checked against the catalog in the
  // service (spec 0004, AC-9), since a DTO can't read the database
  @IsString()
  @Matches(ROLE_CODE_RE)
  role!: RoleCode;

  @IsEnum(SystemType)
  system!: SystemType;
}
