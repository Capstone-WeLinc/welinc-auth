/* eslint-disable @typescript-eslint/require-await -- test doubles */
import { beforeEach, describe, expect, it, jest } from '@jest/globals';
import type { ConfigService } from '@nestjs/config';
import maxmind from 'maxmind';
import type { Env } from '../../config/env';
import { GeoService } from './geo.service';

jest.mock('maxmind', () => ({
  __esModule: true,
  default: { open: jest.fn() },
}));
const open = maxmind.open as unknown as jest.Mock<
  (f: string) => Promise<unknown>
>;

const config = {
  get: (k: string) =>
    k === 'GEOIP_COUNTRY_FILE' ? 'country.mmdb' : 'asn.mmdb',
} as unknown as ConfigService<Env, true>;

const countryReader = {
  get: (ip: string) =>
    ip === '112.198.0.1'
      ? { country: { iso_code: 'PH' } }
      : ip === '1.1.1.1'
        ? { country: { iso_code: 'xx1' } }
        : null,
};
const asnReader = {
  get: (ip: string) =>
    ip === '112.198.0.1'
      ? {
          autonomous_system_organization: 'Globe Telecom',
          autonomous_system_number: 4775,
        }
      : null,
};
const EMPTY = { country: null, network: null, asn: null };

async function boot() {
  const geo = new GeoService(config);
  await geo.onModuleInit();
  return geo;
}

// covers: AC-17
describe('GeoService', () => {
  beforeEach(() => {
    open.mockReset();
  });

  const both = async (f: string) =>
    f === 'country.mmdb' ? countryReader : asnReader;

  it('finds country and network for a public address', async () => {
    open.mockImplementation(both);
    const geo = await boot();
    expect(geo.lookup('112.198.0.1')).toEqual({
      country: 'PH',
      network: 'Globe Telecom',
      asn: 4775,
    });
  });

  it('gives an empty place for local addresses and no address', async () => {
    open.mockImplementation(both);
    const geo = await boot();
    expect(geo.lookup('172.19.0.1')).toEqual(EMPTY);
    expect(geo.lookup(null)).toEqual(EMPTY);
  });

  it('drops a country code that is not two capital letters', async () => {
    open.mockImplementation(both);
    const geo = await boot();
    expect(geo.lookup('1.1.1.1').country).toBeNull();
  });

  it('starts with empty places when the files are missing', async () => {
    open.mockRejectedValue(new Error('ENOENT'));
    const geo = await boot();
    expect(geo.lookup('112.198.0.1')).toEqual(EMPTY);
  });

  it('returns an empty place when a lookup throws', async () => {
    open.mockResolvedValue({
      get: () => {
        throw new Error('corrupt');
      },
    });
    const geo = await boot();
    expect(geo.lookup('8.8.8.8')).toEqual(EMPTY);
  });
});
