import * as Sentry from '@sentry/nestjs';
import { reportJobFailure } from './job-failure';

jest.mock('@sentry/nestjs', () => ({ captureException: jest.fn() }));

// VRMS spec 0025, AC-10: a job failure is one issue tagged with the job name, and never throws.

describe('reportJobFailure', () => {
  beforeEach(() => jest.clearAllMocks());

  it('captures the error tagged with the job name', () => {
    const error = new Error('db down');
    reportJobFailure('session-sweep', error);
    expect(Sentry.captureException).toHaveBeenCalledWith(error, {
      tags: { job: 'session-sweep' },
    });
  });

  it('never throws, even when the SDK does', () => {
    (Sentry.captureException as jest.Mock).mockImplementationOnce(() => {
      throw new Error('sdk broke');
    });
    expect(() =>
      reportJobFailure('temporary-grant-sweep', new Error('x')),
    ).not.toThrow();
  });
});
