import {
  IsEmail,
  IsNotEmpty,
  IsOptional,
  IsString,
  MaxLength,
} from 'class-validator';

export class LoginDto {
  @IsEmail()
  email!: string;

  @IsString()
  @IsNotEmpty()
  password!: string;

  /** Sent by the portal once reCAPTCHA (WL-103) is wired; not checked yet. */
  @IsOptional()
  @IsString()
  @MaxLength(4096)
  recaptchaToken?: string;
}
