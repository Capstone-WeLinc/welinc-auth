import { describe, it, expect } from '@jest/globals';
import { SystemType } from '@prisma/client';
import {
  allowedCodes,
  appNotAllowedMessage,
  filterAllowed,
} from './allowed-roles';

// covers: spec 0004 AC-18, AC-19
describe('allowed roles per app', () => {
  const vmmsMobile = {
    VMMS: ['MECHANIC', 'CHIEF_MECHANIC'],
    VRMS: ['MECHANIC', 'CHIEF_MECHANIC'],
  };

  it('reads the list for the audience, and null when the system is left out', () => {
    expect(allowedCodes(vmmsMobile, SystemType.VMMS)).toEqual([
      'MECHANIC',
      'CHIEF_MECHANIC',
    ]);
    expect(allowedCodes(vmmsMobile, SystemType.BMS)).toBeNull();
    expect(allowedCodes({}, SystemType.VRMS)).toBeNull();
    expect(allowedCodes(null, SystemType.VRMS)).toBeNull();
    expect(allowedCodes({ VRMS: 'ADMIN' }, SystemType.VRMS)).toBeNull();
  });

  it('keeps only allowed roles, and every role when there is no list', () => {
    const held = [{ role: 'OPERATIONS', system: SystemType.VMMS }];
    expect(filterAllowed(held, ['MECHANIC'])).toEqual([]);
    expect(filterAllowed(held, null)).toEqual(held);
    expect(
      filterAllowed(
        [{ role: 'MECHANIC', system: SystemType.VMMS }],
        ['MECHANIC'],
      ),
    ).toHaveLength(1);
  });

  it('names the allowed roles in the refusal', () => {
    expect(appNotAllowedMessage(['Mechanic', 'Chief Mechanic'])).toBe(
      'This app is for Mechanic and Chief Mechanic accounts.',
    );
    expect(appNotAllowedMessage(['Driver'])).toBe(
      'This app is for Driver accounts.',
    );
    expect(appNotAllowedMessage(['A', 'B', 'C'])).toBe(
      'This app is for A, B and C accounts.',
    );
    expect(appNotAllowedMessage([])).toBe('This app is not for your account.');
  });
});
