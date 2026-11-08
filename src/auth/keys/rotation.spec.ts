import { describe, it, expect } from '@jest/globals';
import { decodeProtectedHeader } from 'jose';
import { TEST_SETTINGS } from '../testing/test-keys';
import { TokenRejectedError, TokenService } from '../tokens/token.service';
import { rotate, RotationRefusedError } from './rotation';
import { SigningKeyRing } from './signing-keys';

const MIN = 60_000;
const at = (base: Date, minutes: number) =>
  new Date(base.getTime() + minutes * MIN);
const opts = (now: Date, extra: { force?: boolean; kid?: string } = {}) => ({
  now,
  force: false,
  tokenMinutes: 15,
  ...extra,
});

async function tokensFor(raw: string) {
  return new TokenService(await SigningKeyRing.load(raw), TEST_SETTINGS);
}
const sign = (tokens: TokenService) =>
  tokens.signUserToken({
    sub: 'user-1',
    email: 'pedro@welinc.com',
    aud: 'VRMS',
    roles: [],
    sid: 'sid-1',
    clientId: 'vrms',
  });

// covers: spec 0002 AC-26 (a full rotation logs nobody out), AC-24 (the step rules)
describe('signing key rotation', () => {
  it('runs add, promote and remove with no one logged out until the old key is gone', async () => {
    const t0 = new Date('2026-11-08T09:00:00Z');
    // A new environment: add, then promote --now (there is no old key to protect)
    const first = await rotate(undefined, 'add', opts(t0));
    const start = await rotate(
      JSON.stringify(first.set),
      'promote',
      opts(t0, { force: true }),
    );
    const oldKid = start.set.keys[0].kid;
    const before = await tokensFor(JSON.stringify(start.set));
    const oldToken = await sign(before);

    // add: the new key is published as next; the old key still signs
    const added = await rotate(
      JSON.stringify(start.set),
      'add',
      opts(at(t0, 10)),
    );
    const newKid = added.set.keys.find((k) => k.status === 'next')!.kid;
    const duringAdd = await tokensFor(JSON.stringify(added.set));
    expect(decodeProtectedHeader(await sign(duringAdd)).kid).toBe(oldKid);
    await expect(duringAdd.verify(oldToken)).resolves.toMatchObject({
      sub: 'user-1',
    });

    // promote after an hour: new tokens carry the new kid, the old token keeps working
    const promoted = await rotate(
      JSON.stringify(added.set),
      'promote',
      opts(at(t0, 71)),
    );
    expect(promoted.set.keys.find((k) => k.kid === oldKid)).toMatchObject({
      status: 'retired',
    });
    const afterPromote = await tokensFor(JSON.stringify(promoted.set));
    const newToken = await sign(afterPromote);
    expect(decodeProtectedHeader(newToken).kid).toBe(newKid);
    await expect(afterPromote.verify(oldToken)).resolves.toMatchObject({
      sub: 'user-1',
    });

    // remove 45 minutes after retiring: the old key's tokens stop, the new ones don't
    const removed = await rotate(
      JSON.stringify(promoted.set),
      'remove',
      opts(at(t0, 71 + 45)),
    );
    expect(removed.set.keys.map((k) => k.kid)).toEqual([newKid]);
    const afterRemove = await tokensFor(JSON.stringify(removed.set));
    await expect(afterRemove.verify(oldToken)).rejects.toBeInstanceOf(
      TokenRejectedError,
    );
    await expect(afterRemove.verify(newToken)).resolves.toMatchObject({
      sub: 'user-1',
    });
  });

  it('refuses a second next key, an early promote and an early remove, naming when they become allowed', async () => {
    const t0 = new Date('2026-11-08T09:00:00Z');
    const one = await rotate(undefined, 'add', opts(t0));
    const live = await rotate(
      JSON.stringify(one.set),
      'promote',
      opts(t0, { force: true }),
    );
    const added = await rotate(JSON.stringify(live.set), 'add', opts(t0));

    await expect(
      rotate(JSON.stringify(added.set), 'add', opts(t0)),
    ).rejects.toThrow(/already next/);
    await expect(
      rotate(JSON.stringify(added.set), 'promote', opts(at(t0, 59))),
    ).rejects.toThrow('at 2026-11-08T10:00:00Z or later');
    const promoted = await rotate(
      JSON.stringify(added.set),
      'promote',
      opts(at(t0, 60)),
    );
    await expect(
      rotate(JSON.stringify(promoted.set), 'remove', opts(at(t0, 60 + 44))),
    ).rejects.toThrow('at 2026-11-08T10:45:00Z or later');
    await expect(
      rotate(JSON.stringify(live.set), 'remove', opts(t0)),
    ).rejects.toThrow(/no retired key/);
  });

  it('waits on the longer of the two token lives', async () => {
    const t0 = new Date('2026-11-08T09:00:00Z');
    const one = await rotate(undefined, 'add', opts(t0));
    const live = await rotate(
      JSON.stringify(one.set),
      'promote',
      opts(t0, { force: true }),
    );
    const added = await rotate(JSON.stringify(live.set), 'add', opts(t0));
    const promoted = await rotate(
      JSON.stringify(added.set),
      'promote',
      opts(at(t0, 60)),
    );
    const longer = { ...opts(at(t0, 60 + 45)), tokenMinutes: 20 };
    await expect(
      rotate(JSON.stringify(promoted.set), 'remove', longer),
    ).rejects.toBeInstanceOf(RotationRefusedError);
  });

  it('kills a leaked key at once with promote --now and remove --now, warning about live tokens', async () => {
    const t0 = new Date('2026-11-08T09:00:00Z');
    const one = await rotate(undefined, 'add', opts(t0));
    const live = await rotate(
      JSON.stringify(one.set),
      'promote',
      opts(t0, { force: true }),
    );
    const leaked = live.set.keys[0].kid;
    const added = await rotate(JSON.stringify(live.set), 'add', opts(t0));
    const promoted = await rotate(
      JSON.stringify(added.set),
      'promote',
      opts(t0, { force: true }),
    );
    expect(promoted.notes.join('\n')).toMatch(/WARNING/);

    await expect(
      rotate(
        JSON.stringify(promoted.set),
        'remove',
        opts(t0, {
          force: true,
          kid: promoted.set.keys.find((k) => k.status === 'current')!.kid,
        }),
      ),
    ).rejects.toThrow(/is current/);
    const removed = await rotate(
      JSON.stringify(promoted.set),
      'remove',
      opts(t0, { force: true, kid: leaked }),
    );
    expect(removed.set.keys.map((k) => k.kid)).not.toContain(leaked);
    expect(removed.notes.join('\n')).toMatch(/stop working.*5 more minutes/);
  });

  it('never puts key material in what it prints', async () => {
    const t0 = new Date('2026-11-08T09:00:00Z');
    const one = await rotate(undefined, 'add', opts(t0));
    const live = await rotate(
      JSON.stringify(one.set),
      'promote',
      opts(t0, { force: true }),
    );
    const printed = [...one.notes, ...live.notes].join('\n');
    for (const key of live.set.keys) {
      expect(printed).not.toContain(key.d!);
      expect(printed).not.toContain(key.x!);
    }
    expect(printed).toMatch(/Next: add/);
  });
});
