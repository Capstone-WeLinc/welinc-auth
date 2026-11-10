import { IsEmail, IsString, Matches } from 'class-validator';
import { SIX_DIGITS } from './email-verification.dto';

export class VerifyOtpDto {
  @IsEmail()
  email!: string;

  @IsString()
  @Matches(SIX_DIGITS, { message: 'otp must be 6 digits' })
  otp!: string;
}
