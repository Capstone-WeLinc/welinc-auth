import { SystemType } from '@prisma/client';

/** The order welinc-auth falls back through when a user holds several systems (spec 0002, AC-5). */
const PICK_ORDER: SystemType[] = [
  SystemType.VRMS,
  SystemType.VMMS,
  SystemType.BMS,
];

/**
 * Which system a login token is for, until S4's launcher replaces this: the requested one;
 * otherwise the only system held; otherwise the first held in the order VRMS, VMMS, BMS.
 * Null when the user holds no role there (or none at all), which the login answers with 403.
 */
export function pickLoginSystem(
  held: readonly { system: SystemType }[],
  requested?: SystemType,
): SystemType | null {
  const systems = new Set(held.map((assignment) => assignment.system));
  if (requested) return systems.has(requested) ? requested : null;
  return PICK_ORDER.find((system) => systems.has(system)) ?? null;
}
