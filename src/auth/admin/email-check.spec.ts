import { BadRequestException, ValidationPipe } from '@nestjs/common';
import { SystemType } from '@prisma/client';
import { AdminCreateUserDto, AdminEmailCheckQueryDto } from './admin.dto';
import { emailCheckAnswer } from './email-check.service';

// covers: suite spec 0019 AC-22, AC-23 (the Add a user email check and the contact field)

const SUITE = { suiteAdmin: true, adminOf: [] };
const VRMS_ADMIN = { suiteAdmin: false, adminOf: [SystemType.VRMS] };

const person = (
  over: Partial<Parameters<typeof emailCheckAnswer>[0]> = {},
) => ({
  name: 'Ana Reyes',
  profilePicture: '/uploads/a.png',
  isActive: true,
  deletedAt: null,
  suiteAdmin: null,
  roles: [] as { system: SystemType }[],
  ...over,
});

describe('emailCheckAnswer', () => {
  it('is free when no account has the email', () => {
    expect(emailCheckAnswer(null, SystemType.VRMS, VRMS_ADMIN)).toEqual({
      status: 'free',
    });
  });

  it('is inactive for a deactivated or deleted account, with nothing else', () => {
    expect(
      emailCheckAnswer(
        person({ isActive: false }),
        SystemType.VRMS,
        VRMS_ADMIN,
      ),
    ).toEqual({ status: 'inactive' });
    expect(
      emailCheckAnswer(
        person({ deletedAt: new Date(), suiteAdmin: { userId: 'u' } }),
        SystemType.VRMS,
        SUITE,
      ),
    ).toEqual({ status: 'inactive' });
  });

  it("tells only a suite admin that an address is a suite admin's", () => {
    const admin = person({ suiteAdmin: { userId: 'u' } });
    expect(emailCheckAnswer(admin, SystemType.VRMS, SUITE)).toEqual({
      status: 'suite-admin',
    });
    expect(emailCheckAnswer(admin, SystemType.VRMS, VRMS_ADMIN)).toEqual({
      status: 'existing',
      name: 'Ana Reyes',
      picture: '/uploads/a.png',
      systems: [],
    });
  });

  it('is in-system when the person already holds a role there', () => {
    const answer = emailCheckAnswer(
      person({ roles: [{ system: SystemType.VRMS }] }),
      SystemType.VRMS,
      VRMS_ADMIN,
    );
    expect(answer).toMatchObject({ status: 'in-system', systems: ['VRMS'] });
  });

  it('lists only the systems the caller administers, in launcher order', () => {
    const roles = [{ system: SystemType.VRMS }, { system: SystemType.BMS }];
    expect(
      emailCheckAnswer(person({ roles }), SystemType.VMMS, VRMS_ADMIN),
    ).toMatchObject({ status: 'existing', systems: ['VRMS'] });
    expect(
      emailCheckAnswer(person({ roles }), SystemType.VMMS, SUITE),
    ).toMatchObject({ status: 'existing', systems: ['BMS', 'VRMS'] });
  });
});

/** The same options `main.ts` gives the app's global pipe. */
const pipe = new ValidationPipe({
  forbidNonWhitelisted: true,
  transform: true,
  whitelist: true,
});

describe('AdminEmailCheckQueryDto', () => {
  const check = (query: unknown) =>
    pipe.transform(query, { type: 'query', metatype: AdminEmailCheckQueryDto });

  it('trims and lowercases a whole email', async () => {
    await expect(
      check({ email: '  Ana.Reyes@WeLinc.com ', system: 'VRMS' }),
    ).resolves.toMatchObject({ email: 'ana.reyes@welinc.com' });
  });

  it('answers 400 to a partial email, never a partial match', async () => {
    for (const email of ['ana', 'ana@', '@welinc.com', '']) {
      await expect(check({ email, system: 'VRMS' })).rejects.toBeInstanceOf(
        BadRequestException,
      );
    }
  });

  it('needs a system', async () => {
    await expect(check({ email: 'a@welinc.com' })).rejects.toBeInstanceOf(
      BadRequestException,
    );
  });
});

describe('AdminCreateUserDto contact', () => {
  const base = {
    name: 'Ana',
    email: 'a@welinc.com',
    system: 'VRMS',
    roleAssignments: [{ role: 'MECHANIC', system: 'VRMS' }],
  };
  const check = (body: unknown) =>
    pipe.transform(body, { type: 'body', metatype: AdminCreateUserDto });

  it('is optional and trimmed', async () => {
    const plain = (await check(base)) as AdminCreateUserDto;
    expect(plain.contact).toBeUndefined();
    await expect(
      check({ ...base, contact: ' 0917 555 0134 ' }),
    ).resolves.toMatchObject({ contact: '0917 555 0134' });
  });

  it('answers 400 past 100 characters', async () => {
    await expect(
      check({ ...base, contact: '1'.repeat(101) }),
    ).rejects.toBeInstanceOf(BadRequestException);
  });
});
