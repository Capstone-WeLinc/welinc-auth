import { Type } from 'class-transformer';
import {
  IsArray,
  IsBoolean,
  IsEmail,
  IsNotEmpty,
  IsOptional,
  IsString,
  MaxLength,
  ValidateNested,
} from 'class-validator';
import { RoleAssignmentDto } from './role-assignment.dto';

/** No `password`: admins can't set passwords (spec 0009, AC-15). */
export class UpdateUserDto {
  @IsOptional()
  @IsString()
  @IsNotEmpty()
  name?: string;

  @IsOptional()
  @IsString()
  @IsEmail()
  email?: string;

  @IsOptional()
  @IsBoolean()
  isActive?: boolean;

  // Replaces the caller's system roles; an empty list removes the account from it (spec 0011, AC-28)
  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => RoleAssignmentDto)
  roleAssignments?: RoleAssignmentDto[];

  /** Spec 0013, AC-14a, AC-14b: the actor's ADMIN_ACTION reauth token, when the change needs it. */
  @IsOptional()
  @IsString()
  @MaxLength(200)
  reauthToken?: string;
}
