import { IsEmail, IsNotEmpty, IsString, MaxLength } from 'class-validator';

/** `POST /auth/mobile/login` (spec 0001 section 8, spec 0003 AC-28). */
export class MobileLoginDto {
  @IsEmail()
  email!: string;

  @IsString()
  @IsNotEmpty()
  password!: string;

  /** A public native client, such as `vmms-mobile`. */
  @IsString()
  @IsNotEmpty()
  @MaxLength(64)
  clientId!: string;

  /** The device as the app reports it; trimmed and cut to 100 characters (AC-33). */
  @IsString()
  @MaxLength(200)
  deviceName!: string;
}
