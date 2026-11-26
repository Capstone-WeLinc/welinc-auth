import { ClientKind, Prisma, PrismaClient, SystemType } from '@prisma/client';

/**
 * The clients of spec 0001 section 4 (spec 0002, AC-13). Running the seed again updates each row
 * in place: `jwks` changes only when its env value is set, and `isActive` is set only when the
 * row is created, so a client switched off by hand stays off.
 */
type ClientDefinition = {
  id: string;
  kind: ClientKind;
  system: SystemType | null;
  grants: string[];
  userAudiences: string[];
  serviceScopes: Record<string, string[]>;
  /** The system's web address in local development (spec 0001 section 1). */
  localWebAddress?: string;
  /** Builds the one exact redirect address from the gateway address (spec 0001 section 4). */
  callbackPath?: string;
  /**
   * Spec 0004, AC-18: the roles this app serves, per audience. A system left out lets every role
   * of that system through. Authoritative: a rerun overwrites a hand edited value.
   */
  allowedRoles?: Partial<Record<SystemType, string[]>>;
  /**
   * Suite spec 0014, AC-6: the phone app has shipped, for the portal's phone only state ("on the
   * mobile app" or "coming to"). Default false. Authoritative like `allowedRoles`.
   */
  appReleased?: boolean;
};

const SYSTEM_GRANTS = [
  'authorization_code',
  'refresh_token',
  'client_credentials',
];
/** Spec 0005 AC-7: VMMS and BMS may read phones; VRMS keeps names and roles only. */
const DIRECTORY = { AUTH: ['directory.read', 'directory.contact'] };
/**
 * VRMS reads the directory without phones, and its permission matrix (spec 0013, AC-26). VRMS
 * spec 0029, AC-26: the fleet copy, repair and referral events to VMMS, and the trips read and
 * repair updates to BMS.
 */
const VRMS_SCOPES = {
  AUTH: ['directory.read', 'permissions.read'],
  VMMS: ['fleet.read', 'fleet.repair-status.write', 'repair.referral-status.write'],
  BMS: ['schedule.read', 'repair.update.write'],
};

export const CLIENTS: ClientDefinition[] = [
  {
    id: 'portal',
    kind: ClientKind.FIRST_PARTY_WEB,
    localWebAddress: 'http://localhost:8000',
    system: null,
    grants: ['sso'],
    userAudiences: [],
    serviceScopes: {},
  },
  {
    id: 'vrms',
    kind: ClientKind.CONFIDENTIAL,
    localWebAddress: 'http://localhost:8001',
    callbackPath: '/vrms/session/callback',
    system: SystemType.VRMS,
    grants: SYSTEM_GRANTS,
    userAudiences: ['VRMS'],
    serviceScopes: VRMS_SCOPES,
  },
  {
    id: 'vmms',
    kind: ClientKind.CONFIDENTIAL,
    localWebAddress: 'http://localhost:8002',
    callbackPath: '/vmms/session/callback',
    system: SystemType.VMMS,
    grants: SYSTEM_GRANTS,
    userAudiences: ['VMMS'],
    // VRMS spec 0029, AC-26: referrals, the repair status and history reads and fleet change
    // messages to VRMS; VMMS's own senders to BMS (spec vmms/0026), since the registry is shared
    serviceScopes: {
      ...DIRECTORY,
      VRMS: [
        'repair.referral.write',
        'repair.status.read',
        'repair.history.read',
        'fleet.change.write',
      ],
      BMS: ['fleet.availability.write', 'fleet.change.write'],
    },
    // Suite spec 0014, AC-1: the web app is for office roles; mechanics use vmms-mobile
    allowedRoles: { VMMS: ['ADMIN', 'OPERATIONS'] },
  },
  {
    id: 'bms',
    kind: ClientKind.CONFIDENTIAL,
    localWebAddress: 'http://localhost:8003',
    callbackPath: '/bms/session/callback',
    system: SystemType.BMS,
    grants: SYSTEM_GRANTS,
    userAudiences: ['BMS'],
    // Suite spec 0014, AC-10: BMS dispatch reads trucks and garages from the VMMS fleet API.
    // VRMS spec 0029, AC-26: the active repair read and expedite requests to VRMS
    serviceScopes: {
      ...DIRECTORY,
      VMMS: ['fleet.read'],
      VRMS: ['repair.status.read', 'repair.expedite.write'],
    },
    // Suite spec 0014, AC-1: the web app is for office roles; drivers and helpers use bms-mobile
    allowedRoles: { BMS: ['ADMIN', 'CUSTOMER_SUPPORT', 'OPERATIONS'] },
  },
  {
    id: 'vmms-mobile',
    kind: ClientKind.PUBLIC_NATIVE,
    system: SystemType.VMMS,
    grants: ['mobile_login', 'refresh_token'],
    // VMMS by default; VRMS for its tab in the VMMS app (scope feature 48, spec 0003 AC-29)
    userAudiences: ['VMMS', 'VRMS'],
    serviceScopes: {},
    allowedRoles: {
      VMMS: ['MECHANIC', 'CHIEF_MECHANIC'],
      VRMS: ['MECHANIC', 'CHIEF_MECHANIC'],
    },
    appReleased: true,
  },
  {
    // The BMS app for drivers and helpers in the field (spec 0004, AC-18)
    id: 'bms-mobile',
    kind: ClientKind.PUBLIC_NATIVE,
    system: SystemType.BMS,
    grants: ['mobile_login', 'refresh_token'],
    userAudiences: ['BMS'],
    serviceScopes: {},
    allowedRoles: { BMS: ['DRIVER', 'HELPER'] },
    appReleased: false,
  },
  {
    id: 'vmms-analytics',
    kind: ClientKind.SERVICE,
    system: SystemType.VMMS,
    grants: ['client_credentials'],
    userAudiences: [],
    serviceScopes: { AUTH: ['directory.read'] },
  },
  {
    id: 'bms-analytics',
    kind: ClientKind.SERVICE,
    system: SystemType.BMS,
    grants: ['client_credentials'],
    userAudiences: [],
    serviceScopes: { AUTH: ['directory.read'] },
  },
];

/** `vmms-analytics` → `CLIENT_VMMS_ANALYTICS_JWKS`. */
export const jwksEnvName = (id: string) =>
  `CLIENT_${id.toUpperCase().replace(/-/g, '_')}_JWKS`;

/** `vrms` → `CLIENT_VRMS_WEB_ADDRESS`. */
export const webAddressEnvName = (id: string) =>
  `CLIENT_${id.toUpperCase().replace(/-/g, '_')}_WEB_ADDRESS`;

const trimSlash = (value: string) => value.trim().replace(/\/+$/, '');

/**
 * A client's web address and redirect addresses (spec 0003): the web address from
 * `CLIENT_<ID>_WEB_ADDRESS` (the portal's from `PORTAL_URL`), else the local one; the redirect
 * address is `API_PUBLIC_URL` (the gateway address the browser sees) plus the callback path.
 */
export function addressesFor(
  client: ClientDefinition,
  env: NodeJS.ProcessEnv,
): { webAddress: string | null; redirectUris: string[] } {
  const fromEnv =
    client.id === 'portal' ? env['PORTAL_URL'] : env[webAddressEnvName(client.id)];
  const web = fromEnv?.trim() ? trimSlash(fromEnv) : client.localWebAddress;
  const api = trimSlash(env['API_PUBLIC_URL'] || 'http://localhost:3000');
  return {
    webAddress: web ?? null,
    redirectUris: client.callbackPath ? [`${api}${client.callbackPath}`] : [],
  };
}

/** Checks a client's public key set from env. Refuses a private key: welinc-auth never holds one. */
export function parseClientJwks(
  name: string,
  raw: string,
): Prisma.InputJsonObject {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`${name} is not valid JSON`);
  }
  const keys = (parsed as { keys?: unknown } | null)?.keys;
  if (!Array.isArray(keys) || keys.length === 0 || keys.length > 2) {
    throw new Error(`${name} must be {"keys":[...]} with one or two keys`);
  }
  for (const key of keys as Record<string, unknown>[]) {
    if ('d' in key) {
      throw new Error(
        `${name} holds a private key. Register the public key only.`,
      );
    }
    if (
      key.kty !== 'EC' ||
      key.crv !== 'P-256' ||
      typeof key.kid !== 'string' ||
      key.alg !== 'ES256'
    ) {
      throw new Error(
        `${name}: each key must be a public EC P-256 key with a kid and alg ES256`,
      );
    }
  }
  return { keys } as Prisma.InputJsonObject;
}

/**
 * Spec 0004, AC-18: every allowed role must be in the catalog for its system. Throws before any
 * write, so a typo never lands half the registry.
 */
export function checkAllowedRoles(
  clients: ClientDefinition[],
  catalog: { system: SystemType; code: string }[],
): void {
  if (catalog.length === 0) {
    throw new Error('The role catalog is empty. Run npm run db:deploy first.');
  }
  const problems: string[] = [];
  for (const client of clients) {
    for (const [system, codes] of Object.entries(client.allowedRoles ?? {})) {
      for (const code of codes ?? []) {
        if (!catalog.some((r) => r.system === system && r.code === code)) {
          problems.push(`${client.id}: ${system} has no role '${code}'`);
        }
      }
    }
  }
  if (problems.length > 0) {
    throw new Error(`Allowed roles not in the catalog: ${problems.join('; ')}`);
  }
}

export async function seedClients(
  prisma: PrismaClient,
  env: NodeJS.ProcessEnv = process.env,
): Promise<void> {
  console.log('Seeding clients...');
  checkAllowedRoles(
    CLIENTS,
    await prisma.systemRole.findMany({ select: { system: true, code: true } }),
  );
  for (const client of CLIENTS) {
    const name = jwksEnvName(client.id);
    const raw = env[name]?.trim();
    const jwks = raw ? parseClientJwks(name, raw) : undefined;
    const fields = {
      kind: client.kind,
      system: client.system,
      grants: client.grants,
      userAudiences: client.userAudiences,
      serviceScopes: client.serviceScopes,
      allowedRoles: client.allowedRoles ?? {},
      appReleased: client.appReleased ?? false,
      ...addressesFor(client, env),
    };
    await prisma.oAuthClient.upsert({
      where: { id: client.id },
      create: { id: client.id, ...fields, ...(jwks ? { jwks } : {}) },
      update: { ...fields, ...(jwks ? { jwks } : {}) },
    });
    console.log(`  ${client.id}${jwks ? ' (keys from ' + name + ')' : ''}`);
  }
}
