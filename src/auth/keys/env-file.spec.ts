import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import {
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { EnvFile, option } from '../../../scripts/env-file';

// covers: spec 0002 AC-24 (keys scripts edit .env line by line and keep every other line)
describe('EnvFile', () => {
  let dir: string;
  let path: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'envfile-'));
    path = join(dir, '.env');
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it('reads an empty file when none exists', () => {
    expect(EnvFile.read(path).get('A')).toBeUndefined();
  });

  it('strips single and double quotes from values', () => {
    writeFileSync(path, 'A=\'one\'\nB="two"\nC=three\n');
    const env = EnvFile.read(path);

    expect([env.get('A'), env.get('B'), env.get('C')]).toEqual([
      'one',
      'two',
      'three',
    ]);
  });

  it('treats an empty value as missing', () => {
    writeFileSync(path, "A=\nB=''\n");
    const env = EnvFile.read(path);

    expect(env.has('A')).toBe(false);
    expect(env.has('B')).toBe(false);
  });

  it('does not match a key that only shares a prefix', () => {
    writeFileSync(path, 'AUTH_KEYS_OLD=x\n');

    expect(EnvFile.read(path).get('AUTH_KEYS')).toBeUndefined();
  });

  it('replaces one line and keeps comments and other lines', () => {
    writeFileSync(path, '# note\nA=1\nB=2\n');
    const env = EnvFile.read(path);
    env.set('A', '{"k":1}');
    env.save();

    expect(readFileSync(path, 'utf8')).toBe('# note\nA=\'{"k":1}\'\nB=2\n');
  });

  it('appends a new key at the end', () => {
    writeFileSync(path, 'A=1\n');
    const env = EnvFile.read(path);
    env.set('B', 'two');
    env.save();

    expect(readFileSync(path, 'utf8')).toBe("A=1\nB='two'\n");
  });

  it('refuses values with a single quote or a line break', () => {
    const env = EnvFile.read(path);

    expect(() => env.set('A', "it's")).toThrow(/single quote/);
    expect(() => env.set('A', 'a\nb')).toThrow(/line break/);
  });

  it('saves readable by the owner only and leaves no temp file', () => {
    const env = EnvFile.read(path);
    env.set('A', '1');
    env.save();

    expect(statSync(path).mode & 0o777).toBe(0o600);
    expect(readdirSync(dir)).toEqual(['.env']);
  });
});

describe('option', () => {
  it('reads the value after --name', () => {
    expect(option(['--client', 'vrms', '--x', '1'], 'client')).toBe('vrms');
  });

  it('returns undefined when the flag is absent', () => {
    expect(option(['--x', '1'], 'client')).toBeUndefined();
  });
});
