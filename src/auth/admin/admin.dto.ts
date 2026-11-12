import { Transform } from 'class-transformer';
import {
  Allow,
  IsBoolean,
  IsEnum,
  IsIn,
  IsOptional,
  IsString,
  Matches,
  MaxLength,
  MinLength,
} from 'class-validator';
import { SystemType } from '@prisma/client';
import { CreateUserDto } from '../dto/create-user.dto';
import { UpdateUserDto } from '../dto/update-user.dto';
import { ROLE_CODE_RE, type RoleCode } from '../roles/catalog.types';
import { PEOPLE_STATUSES, type PeopleStatus } from './people-page';

// Spec 0013, AC-16: the `/auth/admin/*` account bodies are today's bearer bodies plus the
// `system` the admin acts in (checked against their admin roles by the controller).

export class AdminSystemDto {
  @IsEnum(SystemType)
  system!: SystemType;
}

/** AC-17: `system` a suite admin may leave out (lists, delete, restore, deletion decisions). */
export class AdminOptionalSystemDto {
  @IsOptional()
  @IsEnum(SystemType)
  system?: SystemType;
}

/** A write that may need the actor's `ADMIN_ACTION` recheck (AC-14b). */
export class AdminSystemReauthDto extends AdminSystemDto {
  @IsOptional()
  @IsString()
  @MaxLength(200)
  reauthToken?: string;
}

export class AdminListUsersQueryDto extends AdminOptionalSystemDto {
  @IsOptional()
  @Transform(({ value }: { value: unknown }) =>
    typeof value === 'string' ? value.trim() : value,
  )
  @IsString()
  @MaxLength(100)
  q?: string;

  @IsOptional()
  @IsIn(PEOPLE_STATUSES)
  status?: PeopleStatus;

  @IsOptional()
  @IsString()
  @Matches(ROLE_CODE_RE)
  role?: RoleCode;

  @IsOptional()
  @IsString()
  @MaxLength(400)
  cursor?: string;

  @IsOptional()
  @IsString()
  limit?: string;
}

export class AdminLookupQueryDto extends AdminSystemDto {
  @Transform(({ value }: { value: unknown }) =>
    typeof value === 'string' ? value.trim() : value,
  )
  @IsString()
  @MinLength(2)
  @MaxLength(100)
  q!: string;
}

export class AdminCreateUserDto extends CreateUserDto {
  @IsEnum(SystemType)
  system!: SystemType;
}

export class AdminUpdateUserDto extends UpdateUserDto {
  @IsEnum(SystemType)
  system!: SystemType;
}

export class AdminSetStatusDto extends AdminSystemDto {
  @IsBoolean()
  isActive!: boolean;
}

/** The deletion bodies are whitelisted only; DeletionService checks the fields (spec 0012). */
export class AdminDeletionListQueryDto extends AdminOptionalSystemDto {
  @Allow()
  view?: unknown;

  @Allow()
  cursor?: unknown;

  @Allow()
  limit?: unknown;
}

export class AdminRejectDto extends AdminOptionalSystemDto {
  @Allow()
  note?: unknown;
}

export class AdminVerifyPasswordDto {
  @Allow()
  password?: unknown;

  @Allow()
  purpose?: unknown;
}
