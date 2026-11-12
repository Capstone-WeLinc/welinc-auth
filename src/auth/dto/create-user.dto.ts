import { Type } from 'class-transformer';
import {
  ArrayMinSize,
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

/** No `password`: a new user always gets a setup code (spec 0009, AC-15). */
export class CreateUserDto {
  @IsString()
  @IsNotEmpty()
  name!: string;

  @IsEmail()
  @IsNotEmpty()
  email!: string;

  @IsOptional()
  @IsBoolean()
  isActive?: boolean;

  @IsArray()
  @ArrayMinSize(1)
  @ValidateNested({ each: true })
  @Type(() => RoleAssignmentDto)
  roleAssignments!: RoleAssignmentDto[];

  /** Add the roles to the account that already owns this email (spec 0011, AC-30). */
  @IsOptional()
  @IsBoolean()
  attachExisting?: boolean;

  /** Spec 0013, AC-14a, AC-14b: the actor's ADMIN_ACTION reauth token, when the change needs it. */
  @IsOptional()
  @IsString()
  @MaxLength(200)
  reauthToken?: string;
}
