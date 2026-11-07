import { describe, it, expect } from '@jest/globals';
import { SystemType } from '@prisma/client';
import { pickLoginSystem } from './login-system';

const held = (...systems: SystemType[]) =>
  systems.map((system) => ({ system }));

// covers: spec 0002 AC-5 (which system a login token is for)
describe('pickLoginSystem', () => {
  it('uses the requested system when the user holds it', () => {
    expect(
      pickLoginSystem(held(SystemType.VRMS, SystemType.BMS), SystemType.BMS),
    ).toBe(SystemType.BMS);
  });

  it('refuses a requested system the user does not hold', () => {
    expect(pickLoginSystem(held(SystemType.VRMS), SystemType.VMMS)).toBeNull();
  });

  it('picks the only system held', () => {
    expect(pickLoginSystem(held(SystemType.BMS, SystemType.BMS))).toBe(
      SystemType.BMS,
    );
  });

  it('prefers VRMS, then VMMS, then BMS', () => {
    expect(pickLoginSystem(held(SystemType.BMS, SystemType.VRMS))).toBe(
      SystemType.VRMS,
    );
    expect(pickLoginSystem(held(SystemType.BMS, SystemType.VMMS))).toBe(
      SystemType.VMMS,
    );
  });

  it('answers null for a user with no system role', () => {
    expect(pickLoginSystem([])).toBeNull();
  });
});
