// `npm run admin:recover -- --email <address> --reason "<text>"` (spec 0013, AC-12): makes an
// account a suite admin again when nobody can sign in as one. Run it in the auth container shell.
// `npm run admin:recover -- --create --email <address> --name "<full name>" --reason "<text>"`
// (AC-12b): makes the first suite admin of an empty database and mails them a setup code. Flags
// only, so a Container Apps job can run it (VRMS spec 0008, AC-15).
// It boots the app's services without the web server, so the rules match the routes exactly.
import 'dotenv/config';
import { hostname, userInfo } from 'node:os';
import { Logger } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { AppModule } from '../src/app.module';
import {
  AdminRecoveryService,
  RecoveryRefused,
} from '../src/auth/admin/admin-recovery.service';

const USAGE = [
  'Usage: npm run admin:recover -- --email <address> --reason "<why, 10 to 500 characters>"',
  '   or: npm run admin:recover -- --create --email <address> --name "<full name>" --reason "<why>"',
].join('\n');

function arg(name: string): string | undefined {
  const at = process.argv.indexOf(`--${name}`);
  const value = at === -1 ? undefined : process.argv[at + 1];
  return value && !value.startsWith('--') ? value : undefined;
}

function osUser(): string {
  try {
    return userInfo().username;
  } catch {
    return 'unknown';
  }
}

async function main(): Promise<number> {
  const email = arg('email');
  const reason = arg('reason');
  const create = process.argv.includes('--create');
  const name = arg('name');
  if (!email || !reason || (create && !name)) {
    console.error(USAGE);
    return 1;
  }
  const app = await NestFactory.createApplicationContext(AppModule, {
    logger: ['error', 'warn'],
  });
  try {
    if (create) {
      const made = await app.get(AdminRecoveryService).create({
        email,
        name: name!,
        reason,
        host: hostname(),
        osUser: osUser(),
      });
      console.log(`${made.name} (${made.email}) is the first suite admin.`);
      if (!made.setupEmailSent) {
        // AC-12b: the account stays made, but the job fails so the deploy shows mail is broken
        console.error(
          'The setup code could not be sent (see the log). Fix mail, then use Forgot password in the portal. A second --create refuses, since a suite admin exists now.',
        );
        return 1;
      }
      console.log(
        'A setup code was emailed. Using it in the portal verifies the email and sets the password.',
      );
      return 0;
    }
    const result = await app.get(AdminRecoveryService).recover({
      email,
      reason,
      host: hostname(),
      osUser: osUser(),
    });
    console.log(
      result.added
        ? `${result.name} (${result.email}) is a suite admin now.`
        : `${result.name} (${result.email}) already was a suite admin.`,
    );
    console.log(
      `Unlocked, ${result.sessionsEnded} session(s) ended. If the password is lost, use Forgot password in the portal.`,
    );
    return 0;
  } catch (error) {
    if (error instanceof RecoveryRefused) {
      console.error(`Refused, nothing was written: ${error.message}.`);
      return 1;
    }
    new Logger('AdminRecovery').error(error);
    return 1;
  } finally {
    await app.close();
  }
}

void main().then((code) => process.exit(code));
