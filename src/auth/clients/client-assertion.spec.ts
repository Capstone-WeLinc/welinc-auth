import { describe, it, expect, beforeAll } from '@jest/globals';
import { TEST_ISSUER } from '../testing/test-keys';
import {
  signAssertion,
  testClient,
  type TestClient,
} from '../testing/test-clients';
import {
  AssertionRefusedError,
  checkAssertion,
  logSafe,
  type AssertionClient,
} from './client-assertion';

// covers: spec 0002 AC-15 (each assertion check, in order, with its log reason)
describe('checkAssertion', () => {
  let vrms: TestClient;
  let other: TestClient;
  let rows: Record<string, AssertionClient>;

  beforeAll(async () => {
    vrms = await testClient('vrms');
    other = await testClient('bms');
  });

  const check = (assertion: string, extra: { clientIdField?: string } = {}) =>
    checkAssertion(assertion, {
      issuer: TEST_ISSUER,
      findClient: (id) => Promise.resolve(rows[id] ?? null),
      ...extra,
    });

  async function reason(assertion: Promise<string> | string, extra = {}) {
    const error = await check(await assertion, extra).then(
      () => null,
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(AssertionRefusedError);
    return (error as AssertionRefusedError).reason;
  }

  beforeEach(() => {
    rows = { vrms: { ...vrms.row }, bms: { ...other.row } };
  });

  it('accepts a good assertion and answers the client, jti and expiry', async () => {
    const now = Math.floor(Date.now() / 1000);
    const checked = await check(
      await signAssertion(vrms, { exp: now + 30, claims: { jti: 'abc' } }),
    );
    expect(checked).toEqual({
      clientId: 'vrms',
      jti: 'abc',
      expiresAt: new Date((now + 30) * 1000),
      kid: vrms.kid,
    });
  });

  it('refuses garbage, an unknown client, a switched off client and one with no keys', async () => {
    expect(await reason('not-a-jwt')).toBe('malformed');
    expect(
      await reason(
        signAssertion(vrms, { claims: { iss: 'ghost', sub: 'ghost' } }),
      ),
    ).toBe('unknown_client');
    rows.vrms.isActive = false;
    expect(await reason(signAssertion(vrms))).toBe('client_inactive');
    rows.vrms = { ...vrms.row, jwks: null };
    expect(await reason(signAssertion(vrms))).toBe('client_inactive');
  });

  it('refuses a client_id field that differs from iss', async () => {
    expect(await reason(signAssertion(vrms), { clientIdField: 'bms' })).toBe(
      'client_id_mismatch',
    );
    await expect(
      check(await signAssertion(vrms), { clientIdField: 'vrms' }),
    ).resolves.toBeDefined();
  });

  it('refuses the wrong typ and an unknown kid', async () => {
    expect(
      await reason(signAssertion(vrms, { header: { typ: 'at+jwt' } })),
    ).toBe('bad_header');
    expect(
      await reason(signAssertion(vrms, { header: { kid: 'vrms-unknown' } })),
    ).toBe('unknown_kid');
  });

  it("refuses a forged signature: another client's key under this client's kid", async () => {
    expect(await reason(signAssertion(vrms, { key: other.privateKey }))).toBe(
      'bad_signature',
    );
  });

  it('refuses sub not equal to iss, and the wrong or a list aud', async () => {
    expect(await reason(signAssertion(vrms, { claims: { sub: 'bms' } }))).toBe(
      'sub_mismatch',
    );
    expect(
      await reason(
        signAssertion(vrms, { claims: { aud: 'http://elsewhere/token' } }),
      ),
    ).toBe('bad_audience');
    expect(
      await reason(
        signAssertion(vrms, { claims: { aud: [`${TEST_ISSUER}/token`] } }),
      ),
    ).toBe('bad_audience');
  });

  it('checks the times with 5 s of leeway, and a life of at most 60 s', async () => {
    const now = Math.floor(Date.now() / 1000);
    expect(
      await reason(signAssertion(vrms, { iat: now - 70, exp: now - 10 })),
    ).toBe('expired');
    await expect(
      check(await signAssertion(vrms, { iat: now - 50, exp: now - 2 })),
    ).resolves.toBeDefined();
    expect(
      await reason(signAssertion(vrms, { claims: { iat: undefined } })),
    ).toBe('iat_missing');
    expect(
      await reason(signAssertion(vrms, { iat: now + 20, exp: now + 40 })),
    ).toBe('iat_in_future');
    expect(
      await reason(signAssertion(vrms, { claims: { nbf: now + 20 } })),
    ).toBe('not_yet_valid');
    expect(await reason(signAssertion(vrms, { iat: now, exp: now + 61 }))).toBe(
      'lifetime_too_long',
    );
  });

  it('refuses a missing or overlong jti', async () => {
    expect(
      await reason(signAssertion(vrms, { claims: { jti: undefined } })),
    ).toBe('bad_jti');
    expect(
      await reason(signAssertion(vrms, { claims: { jti: 'x'.repeat(129) } })),
    ).toBe('bad_jti');
  });
});

describe('logSafe', () => {
  it('keeps a claimed id printable and short for the log', () => {
    expect(logSafe('vrms')).toBe('vrms');
    expect(logSafe('evil\nline')).toBe('evil?line');
    expect(logSafe('x'.repeat(100))).toHaveLength(64);
    expect(logSafe(undefined)).toBe('-');
  });
});
