import {
  IsEmail,
  IsNotEmpty,
  IsString,
  Matches,
  MaxLength,
} from 'class-validator';

// Spec 0009 request bodies. A code that is not exactly 6 digits fails here with a plain 400 and
// is never counted as a wrong try (AC-4).

export const SIX_DIGITS = /^\d{6}$/;
const SIX_DIGITS_MESSAGE = 'code must be 6 digits';

/** `POST /auth/login/verify-email` (AC-9). */
export class VerifySignInDto {
  @IsString()
  @MaxLength(64)
  challengeId!: string;

  @IsString()
  @Matches(SIX_DIGITS, { message: SIX_DIGITS_MESSAGE })
  code!: string;
}

/** `POST /auth/login/verify-email/resend` and its mobile twin (AC-10, AC-11). */
export class ResendSignInDto {
  @IsString()
  @MaxLength(64)
  challengeId!: string;
}

/** `POST /auth/mobile/login/verify-email` (AC-11). */
export class MobileVerifySignInDto extends VerifySignInDto {
  @IsString()
  @IsNotEmpty()
  @MaxLength(64)
  clientId!: string;

  @IsString()
  @MaxLength(200)
  deviceName!: string;
}

/** `POST /auth/profile/email` (AC-17): start a change, or resend the pending one. */
export class StartEmailChangeDto {
  @IsEmail()
  @MaxLength(255)
  newEmail!: string;

  @IsString()
  @IsNotEmpty()
  currentPassword!: string;
}

/** `POST /auth/profile/email/verify` (AC-18). */
export class VerifyEmailChangeDto {
  @IsString()
  @Matches(SIX_DIGITS, { message: SIX_DIGITS_MESSAGE })
  code!: string;
}
