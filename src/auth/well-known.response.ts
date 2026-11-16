import { ApiProperty } from '@nestjs/swagger';

/** One public signing key (EC P-256, ES256), as `SigningKeyRing.publicSet` publishes it. */
export class PublicJwk {
  @ApiProperty({ enum: ['EC'] })
  kty!: 'EC';

  @ApiProperty({ enum: ['P-256'] })
  crv!: 'P-256';

  @ApiProperty({ description: 'The public point, base64url' })
  x!: string;

  @ApiProperty({ description: 'The public point, base64url' })
  y!: string;

  @ApiProperty({ description: 'The key id a token header names' })
  kid!: string;

  @ApiProperty({ enum: ['ES256'] })
  alg!: 'ES256';

  @ApiProperty({ enum: ['sig'] })
  use!: 'sig';
}

/** `GET /auth/.well-known/jwks.json`: every current, next and retired public key. */
export class JwksResponse {
  @ApiProperty({ type: [PublicJwk] })
  keys!: PublicJwk[];
}

/** `GET /auth/.well-known/oauth-authorization-server` (RFC 8414). */
export class AuthServerMetadataResponse {
  @ApiProperty({ example: 'http://localhost:3000/auth' })
  issuer!: string;

  @ApiProperty()
  authorization_endpoint!: string;

  @ApiProperty()
  token_endpoint!: string;

  @ApiProperty()
  jwks_uri!: string;

  @ApiProperty({
    type: [String],
    example: ['authorization_code', 'refresh_token', 'client_credentials'],
  })
  grant_types_supported!: string[];

  @ApiProperty({ type: [String], example: ['code'] })
  response_types_supported!: string[];

  @ApiProperty({ type: [String], example: ['S256'] })
  code_challenge_methods_supported!: string[];

  @ApiProperty({ type: [String], example: ['private_key_jwt'] })
  token_endpoint_auth_methods_supported!: string[];

  @ApiProperty({ type: [String], example: ['ES256'] })
  token_endpoint_auth_signing_alg_values_supported!: string[];
}
