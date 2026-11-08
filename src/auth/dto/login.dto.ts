import {
  IsEmail,
  IsEnum,
  IsNotEmpty,
  IsOptional,
  IsString,
  MaxLength,
} from 'class-validator';
import { SystemType } from '@prisma/client';

export class LoginDto {
  @IsEmail()
  email!: string;

  @IsString()
  @IsNotEmpty()
  password!: string;

  /** The system to sign in to (spec 0002, AC-5). Optional; welinc-auth picks when it's absent. */
  @IsOptional()
  @IsEnum(SystemType)
  system?: SystemType;

  /** Sent by the portal once reCAPTCHA (WL-103) is wired; not checked yet. */
  @IsOptional()
  @IsString()
  @MaxLength(4096)
  recaptchaToken?: string;
}
