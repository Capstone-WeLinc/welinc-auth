import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { SystemType } from '@prisma/client';
import type { Env } from '../../config/env';
import { MailService } from '../../shared/mail.service';
import { PrismaService } from '../../shared/prisma.service';
import { CatalogService } from '../roles/catalog.service';
import {
  adminAlertEmail,
  type AdminAlertKind,
  type AlertLine,
  type AlertSystems,
} from './admin-alert-emails';

/** One change to alert about (spec 0013, AC-13). */
export type AdminAlert = {
  kind: AdminAlertKind;
  /** The person the change is about; null for a matrix edit (AC-27), which is about a system. */
  targetId: string | null;
  /** Whose admins get it: the systems concerned, or `ALL` (a suite admin target). */
  systems: AlertSystems;
  /** For role lines: the system whose admin role was added or removed. */
  roleSystem?: SystemType;
  /** A role other than the admin role (temporary access, a suite admin's grant), by code. */
  role?: string;
  /** When temporary access ends. */
  until?: Date;
  /** The person the line is about gets it too, even when no longer an admin (AC-13). */
  notifyTarget?: boolean;
  reason?: string | null;
  /** `PERMISSIONS_CHANGED`: how many cells the save changed. */
  cells?: number;
};

type Recipient = {
  id: string;
  name: string;
  email: string;
  suite: boolean;
  adminOf: Set<SystemType>;
};

/**
 * Spec 0013, AC-13: alert emails after commit to every suite admin and the active admins of the
 * systems concerned, the actor included. One email per recipient per save, deduplicated; a
 * recipient sees only lines about systems they admin (a suite admin sees all). Never throws:
 * a failed lookup or email is logged and the save stands.
 */
@Injectable()
export class AdminAlertsService {
  private readonly logger = new Logger(AdminAlertsService.name);
  private mailQueue: Promise<void> = Promise.resolve();
  private readonly portal: string;

  constructor(
    private readonly prisma: PrismaService,
    private readonly catalog: CatalogService,
    private readonly mail: MailService,
    config: ConfigService<Env, true>,
  ) {
    this.portal = config.get('PORTAL_URL', { infer: true }).replace(/\/+$/, '');
  }

  /** Call after the commit, with every change of one save. */
  async send(actorId: string | null, alerts: AdminAlert[]): Promise<void> {
    if (alerts.length === 0) return;
    try {
      await this.deliver(actorId, alerts, new Date());
    } catch (error) {
      this.logger.error(
        `admin alert failed actor=${actorId ?? '-'}: ${error instanceof Error ? error.message : 'unknown error'}`,
      );
    }
  }

  private async deliver(
    actorId: string | null,
    alerts: AdminAlert[],
    at: Date,
  ): Promise<void> {
    const systems = await this.catalog.systems();
    const systemName = new Map(systems.map((s) => [s.code, s.name]));
    const adminRole = new Map(
      systems.flatMap((s) =>
        s.roles.filter((r) => r.isSystemAdmin).map((r) => [s.code, r] as const),
      ),
    );
    const roleName = (system: SystemType, code: string) =>
      systems.find((s) => s.code === system)?.roles.find((r) => r.code === code)
        ?.name ?? code;

    const targetIds = [
      ...new Set(
        alerts.flatMap((a) => (a.targetId === null ? [] : [a.targetId])),
      ),
    ];
    const people = await this.prisma.user.findMany({
      where: { id: { in: [...targetIds, ...(actorId ? [actorId] : [])] } },
      select: { id: true, name: true, email: true },
    });
    const byId = new Map(people.map((p) => [p.id, p]));

    const lines = alerts.map((alert) => {
      const target = alert.targetId ? byId.get(alert.targetId) : undefined;
      const line: AlertLine = {
        kind: alert.kind,
        targetName: target?.name || 'Deleted user',
        targetEmail: target?.email ?? '',
        systemName: alert.roleSystem
          ? (systemName.get(alert.roleSystem) ?? alert.roleSystem)
          : null,
        roleName: !alert.roleSystem
          ? null
          : alert.role
            ? roleName(alert.roleSystem, alert.role)
            : (adminRole.get(alert.roleSystem)?.name ?? null),
        until: alert.until ?? null,
        at,
        reason: alert.reason ?? null,
        cells: alert.cells,
      };
      return { alert, line };
    });

    const recipients = await this.recipients(alerts, adminRole);
    // AC-13: a removed suite admin also hears about their own removal
    for (const alert of alerts) {
      if (!alert.notifyTarget || alert.targetId === null) continue;
      if (recipients.some((r) => r.id === alert.targetId)) continue;
      const target = byId.get(alert.targetId);
      if (!target) continue;
      recipients.push({
        id: target.id,
        name: target.name,
        email: target.email,
        suite: true,
        adminOf: new Set(),
      });
    }
    const actorName = actorId
      ? byId.get(actorId)?.name || 'An admin'
      : 'WeLinc (automatic)';

    for (const recipient of recipients) {
      const mine = lines.filter(
        ({ alert }) =>
          recipient.suite ||
          alert.systems === 'ALL' ||
          alert.systems.some((s) => recipient.adminOf.has(s)),
      );
      if (mine.length === 0) continue;
      const link = this.linkFor(
        recipient,
        mine.map((m) => m.alert),
      );
      this.queue(recipient, () =>
        adminAlertEmail({
          recipientName: recipient.name,
          actorName,
          lines: mine.map((m) => m.line),
          link,
        }),
      );
    }
    for (const { alert } of lines) {
      this.logger.log(
        `admin alert actor=${actorId ?? '-'} user=${alert.targetId} kind=${alert.kind}`,
      );
    }
  }

  /** Suite admins plus the active admins of every system concerned, each once. */
  private async recipients(
    alerts: AdminAlert[],
    adminRole: Map<SystemType, { code: string }>,
  ): Promise<Recipient[]> {
    const concerned = new Set<SystemType>();
    for (const alert of alerts) {
      const list =
        alert.systems === 'ALL' ? Object.values(SystemType) : alert.systems;
      for (const s of list) concerned.add(s);
    }
    const roleFilters = [...concerned].flatMap((system) => {
      const role = adminRole.get(system);
      return role ? [{ system, role: role.code }] : [];
    });

    const rows = await this.prisma.user.findMany({
      where: {
        isActive: true,
        deletedAt: null,
        OR: [
          { suiteAdmin: { isNot: null } },
          ...(roleFilters.length > 0
            ? [{ roles: { some: { OR: roleFilters } } }]
            : []),
        ],
      },
      select: {
        id: true,
        name: true,
        email: true,
        suiteAdmin: { select: { userId: true } },
        roles: { select: { role: true, system: true } },
      },
    });
    return rows.map((row) => ({
      id: row.id,
      name: row.name,
      email: row.email,
      suite: row.suiteAdmin !== null,
      adminOf: new Set(
        row.roles
          .filter((r) => adminRole.get(r.system)?.code === r.role)
          .map((r) => r.system),
      ),
    }));
  }

  /** The person page when the save was about one person, else the admin section. */
  private linkFor(recipient: Recipient, alerts: AdminAlert[]): string {
    const matrix = alerts.find((a) => a.kind === 'PERMISSIONS_CHANGED');
    if (matrix?.roleSystem) {
      return `${this.portal}/admin/permissions?system=${matrix.roleSystem}`;
    }
    const targets = new Set(alerts.map((a) => a.targetId));
    if (targets.size !== 1) return `${this.portal}/admin`;
    const [targetId] = targets;
    const systems = alerts.flatMap((a) =>
      a.systems === 'ALL' ? [] : a.systems,
    );
    const system =
      systems.find((s) => recipient.adminOf.has(s)) ??
      (recipient.suite ? systems[0] : undefined);
    const query = system ? `?system=${system}` : '';
    return `${this.portal}/admin/people/${targetId}${query}`;
  }

  /** Waits for queued alert emails; a script calls it before it exits (AC-12). */
  flush(): Promise<void> {
    return this.mailQueue;
  }

  /** Mails go out one after another in the background (as deletion notices), never awaited. */
  private queue(
    recipient: Recipient,
    build: () => ReturnType<typeof adminAlertEmail>,
  ) {
    this.mailQueue = this.mailQueue.then(async () => {
      try {
        await this.mail.sendMail({
          to: recipient.email,
          ...build(),
          tag: `user=${recipient.id} purpose=ADMIN_ALERT`,
        });
      } catch (error) {
        this.logger.error(
          `admin alert email failed user=${recipient.id}: ${error instanceof Error ? error.message : 'unknown error'}`,
        );
      }
    });
  }
}
