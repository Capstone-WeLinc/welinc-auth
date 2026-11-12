import { IsEmail, IsOptional, IsString, MaxLength } from 'class-validator';

export class ForgotPasswordDto {
  @IsEmail()
  email!: string;

  /** Spec 0013, AC-14b: an admin sending a code to an admin account sends their reauth token. */
  @IsOptional()
  @IsString()
  @MaxLength(200)
  reauthToken?: string;
}
