import { Transform } from 'class-transformer';
import {
  Allow,
  IsBoolean,
  IsEmail,
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
import {
  PEOPLE_GROUPS,
  PEOPLE_SORTS,
  PEOPLE_STATUSES,
  PEOPLE_STATUS_LIST_RE,
  type PeopleGroup,
  type PeopleSort,
} from './people-page';

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

/**
 * The People filters the list and `GET users/facets` share (suite spec 0019, AC-21b): `system`
 * (the scope), search, statuses and `access`.
 */
export class AdminPeopleFilterQueryDto extends AdminOptionalSystemDto {
  @IsOptional()
  @Transform(({ value }: { value: unknown }) =>
    typeof value === 'string' ? value.trim() : value,
  )
  @IsString()
  @MaxLength(100)
  q?: string;

  /** One status, or a comma list read as any of them (suite spec 0017, AC-20). */
  @IsOptional()
  @IsString()
  @MaxLength(200)
  @Matches(PEOPLE_STATUS_LIST_RE, {
    message: `status must be one of ${PEOPLE_STATUSES.join(', ')}, or a comma list of them`,
  })
  status?: string;

  /**
   * Suite spec 0019, AC-21a: a comma list of `SYSTEM` or `SYSTEM:ROLE`, read as any of them.
   * Checked and normalized by `parseAccess`, so its error order holds.
   */
  @IsOptional()
  @IsString()
  access?: string;
}

export class AdminListUsersQueryDto extends AdminPeopleFilterQueryDto {
  /** Suite spec 0017, AC-5: one group, and the answer adds `counts`. */
  @IsOptional()
  @IsIn(PEOPLE_GROUPS)
  group?: PeopleGroup;

  /** Suite spec 0017, AC-20: `name` (default), `lastSignedIn` or `newest`. */
  @IsOptional()
  @IsIn(PEOPLE_SORTS)
  sort?: PeopleSort;

  @IsOptional()
  @IsString()
  @Matches(ROLE_CODE_RE)
  role?: RoleCode;

  /** Suite spec 0018, AC-14: leave out the holders of this role (needs `system`). */
  @IsOptional()
  @IsString()
  @Matches(ROLE_CODE_RE)
  excludeRole?: RoleCode;

  /** Suite spec 0018, AC-14: `true` leaves out suite admins and the caller (Add people). */
  @IsOptional()
  @IsIn(['true', 'false'])
  assignable?: 'true' | 'false';

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

/** Suite spec 0019, AC-23: one whole email, trimmed and lowercased; never a partial match. */
export class AdminEmailCheckQueryDto extends AdminSystemDto {
  @Transform(({ value }: { value: unknown }) =>
    typeof value === 'string' ? value.trim().toLowerCase() : value,
  )
  @IsEmail()
  @MaxLength(254)
  email!: string;
}

export class AdminCreateUserDto extends CreateUserDto {
  @IsEnum(SystemType)
  system!: SystemType;

  /** Suite spec 0019, AC-22: optional, stored in `users.contact`; blank stores nothing. */
  @IsOptional()
  @Transform(({ value }: { value: unknown }) =>
    typeof value === 'string' ? value.trim() : value,
  )
  @IsString()
  @MaxLength(100)
  contact?: string;
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
