import type { SystemType } from '@prisma/client';
import { pendingDeletionsFor } from './admin.controller';

// covers: VRMS spec 0027 AC-12
describe('pendingDeletionsFor (GET /auth/admin/me)', () => {
  const deletion = () => ({ pendingCount: jest.fn().mockResolvedValue(4) });

  it('counts every pending request for a suite admin, as the suite list does', async () => {
    const service = deletion();
    await expect(
      pendingDeletionsFor(service, {
        suiteAdmin: true,
        adminOf: ['VRMS'],
      }),
    ).resolves.toBe(4);
    expect(service.pendingCount).toHaveBeenCalledWith(null);
  });

  it("counts a system admin's own systems", async () => {
    const service = deletion();
    await pendingDeletionsFor(service, {
      suiteAdmin: false,
      adminOf: ['VRMS', 'BMS'] as SystemType[],
    });
    expect(service.pendingCount).toHaveBeenCalledWith(['VRMS', 'BMS']);
  });

  it('answers 0 for someone who is not an admin, with no query', async () => {
    const service = deletion();
    await expect(
      pendingDeletionsFor(service, { suiteAdmin: false, adminOf: [] }),
    ).resolves.toBe(0);
    expect(service.pendingCount).not.toHaveBeenCalled();
  });
});
