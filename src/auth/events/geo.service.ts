import { Injectable, Logger, type OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import maxmind, {
  type AsnResponse,
  type CountryResponse,
  type Reader,
} from 'maxmind';
import type { Env } from '../../config/env';
import { isLocalAddress } from './local-address';

export type Place = {
  country: string | null;
  network: string | null;
  asn: number | null;
};

const NO_PLACE: Place = { country: null, network: null, asn: null };

/**
 * Spec 0011, AC-17: country and network provider for an address, from the offline DB-IP Lite
 * files (`npm run geo:fetch`, CC BY 4.0, "IP data by DB-IP"). Looked up once, when an event is
 * written. Missing or unreadable files log one warning at boot and leave every place empty.
 */
@Injectable()
export class GeoService implements OnModuleInit {
  private readonly logger = new Logger('Geo');
  private country: Reader<CountryResponse> | null = null;
  private asn: Reader<AsnResponse> | null = null;

  constructor(private readonly config: ConfigService<Env, true>) {}

  async onModuleInit(): Promise<void> {
    const countryFile = this.config.get('GEOIP_COUNTRY_FILE', { infer: true });
    const asnFile = this.config.get('GEOIP_ASN_FILE', { infer: true });
    const [country, asn] = await Promise.all([
      this.open<CountryResponse>(countryFile),
      this.open<AsnResponse>(asnFile),
    ]);
    this.country = country;
    this.asn = asn;
    const missing = [!country && countryFile, !asn && asnFile].filter(Boolean);
    if (missing.length > 0) {
      this.logger.warn(
        `Location files missing or unreadable (${missing.join(', ')}); account events get no place. Run npm run geo:fetch.`,
      );
    }
  }

  private async open<T extends CountryResponse | AsnResponse>(
    file: string,
  ): Promise<Reader<T> | null> {
    try {
      return await maxmind.open<T>(file);
    } catch {
      return null;
    }
  }

  /** The place of a public address; none for a private, loopback or shared one, or no address. */
  lookup(ip: string | null): Place {
    if (!ip || isLocalAddress(ip) || (!this.country && !this.asn)) {
      return NO_PLACE;
    }
    try {
      const country = this.country?.get(ip)?.country?.iso_code ?? null;
      const asn = this.asn?.get(ip);
      return {
        country: country && /^[A-Z]{2}$/.test(country) ? country : null,
        network: asn?.autonomous_system_organization?.slice(0, 120) ?? null,
        asn: asn?.autonomous_system_number ?? null,
      };
    } catch {
      return NO_PLACE;
    }
  }
}
