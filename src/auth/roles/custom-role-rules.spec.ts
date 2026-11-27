import { describe, it, expect } from '@jest/globals';
import { ROLE_CODE_RE } from './catalog.types';
import {
  NAME_LENGTH_MESSAGE,
  NAME_LETTERS_MESSAGE,
  codeBody,
  nameProblem,
  pickRoleCode,
} from './custom-role-rules';

// covers: suite spec 0018 umbrella code rule, child 0002 AC-22 (name rules and codes)

describe('custom role names (AC-22)', () => {
  it('needs 2 to 40 characters', () => {
    expect(nameProblem('A')).toBe(NAME_LENGTH_MESSAGE);
    expect(nameProblem('x'.repeat(41))).toBe(NAME_LENGTH_MESSAGE);
    expect(nameProblem('QA')).toBeNull();
    expect(nameProblem('x'.repeat(40))).toBeNull();
  });

  it('needs a letter A to Z or a digit', () => {
    expect(nameProblem('!!')).toBe(NAME_LETTERS_MESSAGE);
    expect(nameProblem('Мастер')).toBe(NAME_LETTERS_MESSAGE);
    expect(nameProblem('Night shift lead ✓')).toBeNull();
  });
});

describe('custom role codes (umbrella rule)', () => {
  it('turns every other run into one underscore, trimmed', () => {
    expect(codeBody('Tire specialist')).toBe('TIRE_SPECIALIST');
    expect(codeBody('  --Night / shift lead!! ')).toBe('NIGHT_SHIFT_LEAD');
    expect(codeBody('3rd line')).toBe('3RD_LINE');
  });

  it('keeps a 40 character name within 30 characters and the code shape', () => {
    const body = codeBody('Senior quality and diagnostics specialist');
    const code = pickRoleCode(body, new Set());
    expect(code).not.toBeNull();
    expect(code!.length).toBeLessThanOrEqual(30);
    expect(code).toMatch(ROLE_CODE_RE);
    expect(code!.endsWith('_')).toBe(false);
    expect(pickRoleCode('3RD_LINE', new Set())).toMatch(ROLE_CODE_RE);
  });

  it('never reuses a code the system had, live or archived', () => {
    const taken = new Set(['C_TIRE_SPECIALIST', 'C_TIRE_SPECIALIST_2']);
    expect(pickRoleCode('TIRE_SPECIALIST', taken)).toBe('C_TIRE_SPECIALIST_3');
  });

  it('gives up after _99', () => {
    const taken = new Set(['C_X']);
    for (let n = 2; n <= 99; n += 1) taken.add(`C_X_${n}`);
    expect(pickRoleCode('X', taken)).toBeNull();
    const code = pickRoleCode('A'.repeat(24), new Set([`C_${'A'.repeat(24)}`]));
    expect(code!.length).toBeLessThanOrEqual(30);
  });
});
