import type { AdminAlertsService } from '../admin/admin-alerts.service';
import type {
  AdminStanding,
  AdminStandingService,
} from '../admin/admin-standing.service';

/**
 * Spec 0013 test doubles: who is an admin (nobody by default; pass a map to make some ids
 * admins) and an alert sender that records what it was asked to send.
 */
export function fakeAdminStanding(
  standings: Record<string, AdminStanding> = {},
  codeRequired = false,
): AdminStandingService {
  return {
    codeRequired: () => codeRequired,
    standing: (userId: string) =>
      Promise.resolve(standings[userId] ?? { suiteAdmin: false, adminOf: [] }),
    asksCodeAtLogin: () => Promise.resolve(false),
  } as unknown as AdminStandingService;
}

export function fakeAdminAlerts(): AdminAlertsService & {
  sent: Parameters<AdminAlertsService['send']>[];
} {
  const sent: Parameters<AdminAlertsService['send']>[] = [];
  return {
    sent,
    send: (...args: Parameters<AdminAlertsService['send']>) => {
      sent.push(args);
      return Promise.resolve();
    },
  } as unknown as AdminAlertsService & {
    sent: Parameters<AdminAlertsService['send']>[];
  };
}
