import { IsString, IsEmail, Matches } from 'class-validator';
import { SIX_DIGITS } from './email-verification.dto';

/**
 * DTO for the public OTP-based password reset flow (POST /auth/reset-password).
 * The only way to set a password: admins can't set one (spec 0009, AC-15).
 */
export class OtpResetPasswordDto {
  @IsEmail()
  email!: string;

  @IsString()
  @Matches(SIX_DIGITS, { message: 'otp must be 6 digits' })
  otp!: string;

  @IsString()
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$/, {
    message:
      'Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character.',
  })
  newPassword!: string;
}
