import type { SystemDefinition } from '../../src/auth/roles/catalog.types';
import { bms } from './bms';
import { vmms } from './vmms';
import { vrms } from './vrms';

/** Every system's file (spec 0004, AC-1). `catalog:sync` refuses a SystemType with no file. */
export const CATALOG: SystemDefinition[] = [vrms, vmms, bms];
