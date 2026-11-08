import { IsEnum, IsOptional, IsString, Matches } from 'class-validator';
import { SystemType } from '@prisma/client';
import { ROLE_CODE_RE, type RoleCode } from '../roles/catalog.types';

export class ListUsersQueryDto {
  @IsOptional()
  @IsEnum(SystemType)
  system?: SystemType;

  /** Only users holding this role in the caller's system (spec 0004, AC-9). */
  @IsOptional()
  @IsString()
  @Matches(ROLE_CODE_RE)
  role?: RoleCode;
}
