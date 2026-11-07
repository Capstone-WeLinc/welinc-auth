import { existsSync, readFileSync, renameSync, writeFileSync } from 'fs';

/**
 * A plain `KEY=value` env file, edited line by line so every other line and comment stays
 * (spec 0002, AC-24). Values the keys scripts write are single quoted JSON on one line.
 */
export class EnvFile {
  private constructor(
    readonly path: string,
    private lines: string[],
  ) {}

  static read(path: string): EnvFile {
    const text = existsSync(path) ? readFileSync(path, 'utf8') : '';
    const lines = text === '' ? [] : text.replace(/\n$/, '').split('\n');
    return new EnvFile(path, lines);
  }

  private index(key: string): number {
    return this.lines.findIndex((line) => line.startsWith(`${key}=`));
  }

  /** The value with its surrounding quotes removed, or undefined when missing or empty. */
  get(key: string): string | undefined {
    const at = this.index(key);
    if (at === -1) return undefined;
    let value = this.lines[at].slice(key.length + 1).trim();
    const quote = value[0];
    if (
      (quote === "'" || quote === '"') &&
      value.endsWith(quote) &&
      value.length > 1
    ) {
      value = value.slice(1, -1);
    }
    return value === '' ? undefined : value;
  }

  has(key: string): boolean {
    return this.get(key) !== undefined;
  }

  set(key: string, value: string): void {
    if (value.includes("'") || value.includes('\n')) {
      throw new Error(
        `${key}: a value can't hold a single quote or a line break`,
      );
    }
    const line = `${key}='${value}'`;
    const at = this.index(key);
    if (at === -1) this.lines.push(line);
    else this.lines[at] = line;
  }

  /** Writes through a temporary file and a rename, readable by the owner only. */
  save(): void {
    const temp = `${this.path}.tmp-${process.pid}`;
    writeFileSync(temp, `${this.lines.join('\n')}\n`, { mode: 0o600 });
    renameSync(temp, this.path);
  }
}

/** Reads `--name value` from the command line. */
export function option(args: string[], name: string): string | undefined {
  const at = args.indexOf(`--${name}`);
  return at === -1 ? undefined : args[at + 1];
}
