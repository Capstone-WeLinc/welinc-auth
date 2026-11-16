import { ApiProperty } from '@nestjs/swagger';

/**
 * The code step a login answers instead of signing in (`codes/sign-in-step.service.ts`), shared
 * by the web and mobile logins. Mobile sends only `EMAIL_VERIFICATION_REQUIRED`; the web login
 * also sends `SIGN_IN_CODE_REQUIRED` for admins.
 */
export class SignInStepResponse {
  @ApiProperty({
    enum: ['EMAIL_VERIFICATION_REQUIRED', 'SIGN_IN_CODE_REQUIRED'],
  })
  status!: 'EMAIL_VERIFICATION_REQUIRED' | 'SIGN_IN_CODE_REQUIRED';

  @ApiProperty({ description: 'Send it back with the code' })
  challengeId!: string;

  @ApiProperty({ description: 'Where the code went' })
  email!: string;

  @ApiProperty({ description: 'Seconds before a new code can be asked for' })
  resendAfter!: number;
}
