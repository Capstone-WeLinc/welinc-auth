import { describe, it, expect } from '@jest/globals';
import { BadRequestException, ValidationPipe } from '@nestjs/common';
import { LoginDto } from './login.dto';

// covers: spec 0007 AC-3 (the login body no longer takes `system`; the strict pipe answers 400)

/** The same options `main.ts` gives the app's global pipe. */
const pipe = new ValidationPipe({
  forbidNonWhitelisted: true,
  transform: true,
  whitelist: true,
});
const check = (body: unknown) =>
  pipe.transform(body, { type: 'body', metatype: LoginDto });

describe('LoginDto through the global pipe', () => {
  it('accepts an email and a password', async () => {
    await expect(
      check({ email: 'm@welinc.com', password: 'x' }),
    ).resolves.toMatchObject({ email: 'm@welinc.com', password: 'x' });
  });

  it('rejects a body that still sends `system`, with a 400', async () => {
    await expect(
      check({ email: 'm@welinc.com', password: 'x', system: 'VMMS' }),
    ).rejects.toBeInstanceOf(BadRequestException);
  });

  it('rejects any other unknown field', async () => {
    await expect(
      check({ email: 'm@welinc.com', password: 'x', roles: ['ADMIN'] }),
    ).rejects.toBeInstanceOf(BadRequestException);
  });

  it('rejects a missing password and a malformed email', async () => {
    await expect(check({ email: 'm@welinc.com' })).rejects.toBeInstanceOf(
      BadRequestException,
    );
    await expect(
      check({ email: 'not an email', password: 'x' }),
    ).rejects.toBeInstanceOf(BadRequestException);
  });
});
