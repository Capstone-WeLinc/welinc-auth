// `npm run admin:recover -- --email <address> --reason "<text>"` (spec 0013, AC-12): makes an
// account a suite admin again when nobody can sign in as one. Run it in the auth container shell.
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

const USAGE =
  'Usage: npm run admin:recover -- --email <address> --reason "<why, 10 to 500 characters>"';

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
  if (!email || !reason) {
    console.error(USAGE);
    return 1;
  }
  const app = await NestFactory.createApplicationContext(AppModule, {
    logger: ['error', 'warn'],
  });
  try {
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
