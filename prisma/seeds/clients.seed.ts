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
};

const SYSTEM_GRANTS = [
  'authorization_code',
  'refresh_token',
  'client_credentials',
];
const DIRECTORY = { AUTH: ['directory.read', 'directory.contact'] };

export const CLIENTS: ClientDefinition[] = [
  {
    id: 'portal',
    kind: ClientKind.FIRST_PARTY_WEB,
    system: null,
    grants: ['sso'],
    userAudiences: [],
    serviceScopes: {},
  },
  {
    id: 'vrms',
    kind: ClientKind.CONFIDENTIAL,
    system: SystemType.VRMS,
    grants: SYSTEM_GRANTS,
    userAudiences: ['VRMS'],
    serviceScopes: DIRECTORY,
  },
  {
    id: 'vmms',
    kind: ClientKind.CONFIDENTIAL,
    system: SystemType.VMMS,
    grants: SYSTEM_GRANTS,
    userAudiences: ['VMMS'],
    serviceScopes: DIRECTORY,
  },
  {
    id: 'bms',
    kind: ClientKind.CONFIDENTIAL,
    system: SystemType.BMS,
    grants: SYSTEM_GRANTS,
    userAudiences: ['BMS'],
    serviceScopes: DIRECTORY,
  },
  {
    id: 'vmms-mobile',
    kind: ClientKind.PUBLIC_NATIVE,
    system: SystemType.VMMS,
    grants: ['mobile_login', 'refresh_token'],
    userAudiences: ['VMMS'],
    serviceScopes: {},
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

export async function seedClients(
  prisma: PrismaClient,
  env: NodeJS.ProcessEnv = process.env,
): Promise<void> {
  console.log('Seeding clients...');
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
    };
    await prisma.oAuthClient.upsert({
      where: { id: client.id },
      create: { id: client.id, ...fields, ...(jwks ? { jwks } : {}) },
      update: { ...fields, ...(jwks ? { jwks } : {}) },
    });
    console.log(`  ${client.id}${jwks ? ' (keys from ' + name + ')' : ''}`);
  }
}
