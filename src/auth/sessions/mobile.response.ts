import { ApiProperty } from '@nestjs/swagger';
import { GrantUser } from '../clients/token.response';

/** A mobile sign in: the tokens in the body, no cookie. */
export class MobileTokenResponse {
  @ApiProperty()
  accessToken!: string;

  @ApiProperty()
  refreshToken!: string;

  @ApiProperty({ description: 'Seconds until the access token expires' })
  expiresIn!: number;

  @ApiProperty({ description: 'The session id' })
  sid!: string;

  @ApiProperty({ description: 'When the session ends if idle (ISO 8601)' })
  sessionExpiresAt!: string;

  @ApiProperty({ type: GrantUser })
  user!: GrantUser;
}
