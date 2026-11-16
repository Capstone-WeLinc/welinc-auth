import { ApiProperty } from '@nestjs/swagger';

/** A person as a system backend sees them: roles in the caller's system only. */
export class DirectoryUserView {
  @ApiProperty()
  id!: string;

  @ApiProperty()
  name!: string;

  @ApiProperty()
  email!: string;

  @ApiProperty({
    type: String,
    nullable: true,
    description: 'Only with the `directory.contact` scope; null otherwise',
  })
  phone!: string | null;

  @ApiProperty({ type: String, nullable: true })
  picture!: string | null;

  @ApiProperty()
  isActive!: boolean;

  @ApiProperty()
  deleted!: boolean;

  @ApiProperty()
  erased!: boolean;

  @ApiProperty({ type: [String], description: 'Role codes, sorted' })
  roles!: string[];

  @ApiProperty({
    type: [String],
    description: 'The part of `roles` that comes from a temporary grant',
  })
  temporaryRoles!: string[];

  @ApiProperty()
  updatedAt!: string;
}

/** `GET /auth/directory/users`: one page. */
export class DirectoryUsersResponse {
  @ApiProperty({ type: [DirectoryUserView] })
  users!: DirectoryUserView[];

  @ApiProperty({
    type: String,
    nullable: true,
    description: 'The next page cursor; null on the last page',
  })
  next!: string | null;

  @ApiProperty({
    description:
      'Where to start reading `/auth/directory/changes` after this scan',
  })
  changesCursor!: string;
}

/** `POST /auth/directory/users/lookup`. */
export class DirectoryLookupResponse {
  @ApiProperty({ type: [DirectoryUserView], description: 'In the order asked' })
  users!: DirectoryUserView[];

  @ApiProperty({
    type: [String],
    description: "Ids the caller's system never held, as sent",
  })
  missing!: string[];
}

/** One feed entry. */
export class DirectoryChangeView {
  @ApiProperty()
  cursor!: string;

  @ApiProperty({
    enum: [
      'created',
      'updated',
      'roles_changed',
      'activated',
      'deactivated',
      'deleted',
    ],
  })
  type!: string;

  @ApiProperty()
  at!: string;

  @ApiProperty({ type: DirectoryUserView })
  user!: DirectoryUserView;
}

/** `GET /auth/directory/changes`. */
export class DirectoryChangesResponse {
  @ApiProperty({ type: [DirectoryChangeView] })
  changes!: DirectoryChangeView[];

  @ApiProperty({ description: 'Where to read from next; never null' })
  next!: string;

  @ApiProperty()
  hasMore!: boolean;
}
