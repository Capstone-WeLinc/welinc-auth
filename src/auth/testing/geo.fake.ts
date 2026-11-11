import type { GeoService } from '../events/geo.service';

/** A GeoService with no location files: every place is empty (spec 0011, AC-17). */
export const noGeo = {
  lookup: () => ({ country: null, network: null, asn: null }),
} as unknown as GeoService;
