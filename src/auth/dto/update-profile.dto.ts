import { IsNotEmpty, IsOptional, IsString } from 'class-validator';

/** No `email`: your own email changes through `/auth/profile/email` (spec 0009, AC-20). */
export class UpdateProfileDto {
  @IsOptional()
  @IsString()
  @IsNotEmpty()
  name?: string;

  @IsOptional()
  @IsString()
  contact?: string;
}
