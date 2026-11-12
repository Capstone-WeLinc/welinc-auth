import { Allow } from 'class-validator';

// Spec 0012: the bodies are only whitelisted here (`@Allow`); DeletionService checks each field
// itself so a bad value answers 400 VALIDATION_FAILED, the code the contract names.

export class VerifyPasswordDto {
  @Allow()
  password?: unknown;

  @Allow()
  purpose?: unknown;
}

export class DeletionRequestDto {
  @Allow()
  reauthToken?: unknown;

  @Allow()
  reason?: unknown;
}

export class RejectDeletionDto {
  @Allow()
  note?: unknown;
}

export class DeletionListQueryDto {
  @Allow()
  view?: unknown;

  @Allow()
  cursor?: unknown;

  @Allow()
  limit?: unknown;
}
