import { IsOptional, IsString, MaxLength } from 'class-validator';

/**
 * Spec 0013, AC-14a, AC-14b: the actor's `ADMIN_ACTION` reauth token, for admin writes that
 * need a password recheck when they touch an admin account or give the admin role.
 */
export class ReauthBodyDto {
  @IsOptional()
  @IsString()
  @MaxLength(200)
  reauthToken?: string;
}
