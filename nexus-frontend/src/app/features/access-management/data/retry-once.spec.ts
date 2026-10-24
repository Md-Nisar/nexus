import { Observable, of, throwError } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';
import type { LoggerService } from '../../../core/logging/logger.service';
import type { AppError } from '../../../shared/types/app-error';
import { retryOnceOnClassificationChange } from './retry-once';

const ROLE_ID = '0190a000-0000-7000-8000-0000000000c1';

function failure(code: string): AppError {
  return { code, message: `Server detail for ${code}`, traceId: 'trace-1' };
}

/** A `send` that answers each subscription with the next scripted outcome. */
function scripted(...outcomes: readonly (AppError | string)[]) {
  let calls = 0;
  const send = vi.fn((): Observable<string> => {
    const outcome = outcomes[calls++];
    return typeof outcome === 'string' ? of(outcome) : throwError(() => outcome);
  });
  return send;
}

function logger() {
  return { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() };
}

function run(send: () => Observable<string>, log = logger()) {
  let value: string | undefined;
  let error: unknown;
  retryOnceOnClassificationChange(
    send,
    { operation: 'replace', roleId: ROLE_ID },
    log as unknown as LoggerService,
  ).subscribe({
    next: (v) => (value = v),
    error: (e: unknown) => (error = e),
  });
  return { value, error, log };
}

describe('retryOnceOnClassificationChange (design §7.3, RES-53)', () => {
  it('retries RBAC_012 exactly once, re-sending the same request, then emits the answer', () => {
    const send = scripted(failure('RBAC_012'), 'saved');

    const { value, error } = run(send);

    expect(send).toHaveBeenCalledTimes(2);
    expect(value).toBe('saved');
    expect(error).toBeUndefined();
  });

  it('surfaces a second RBAC_012 instead of retrying again', () => {
    const send = scripted(failure('RBAC_012'), failure('RBAC_012'), 'never');

    const { value, error } = run(send);

    expect(send).toHaveBeenCalledTimes(2);
    expect(value).toBeUndefined();
    expect((error as AppError).code).toBe('RBAC_012');
  });

  it.each(['RBAC_001', 'PRECONDITION_FAILED'])('surfaces a %s met on the retry', (code) => {
    const send = scripted(failure('RBAC_012'), failure(code), 'never');

    const { error } = run(send);

    expect(send).toHaveBeenCalledTimes(2);
    expect((error as AppError).code).toBe(code);
  });

  it.each([
    'RBAC_001',
    'ACCESS_DENIED',
    'PRECONDITION_FAILED',
    'PRECONDITION_REQUIRED',
    'RBAC_011',
    'AUTH_005',
    'RBAC_003',
    'RBAC_010',
    'NETWORK_ERROR',
  ])('never retries %s', (code) => {
    const send = scripted(failure(code), 'never');

    const { error, log } = run(send);

    expect(send).toHaveBeenCalledTimes(1);
    expect((error as AppError).code).toBe(code);
    expect(log.info).not.toHaveBeenCalled();
  });

  it('never retries an error that is not an AppError', () => {
    const odd = new Error('boom');
    let calls = 0;
    const send = vi.fn(() => {
      calls++;
      return throwError(() => odd);
    });

    const { error } = run(send);

    expect(calls).toBe(1);
    expect(error).toBe(odd);
  });

  it('sends nothing until subscribed', () => {
    const send = scripted('saved');

    retryOnceOnClassificationChange(
      send,
      { operation: 'assign', roleId: ROLE_ID },
      logger() as unknown as LoggerService,
    );

    expect(send).not.toHaveBeenCalled();
  });

  it('logs access_console_retry_rbac_012 with the operation and role id only', () => {
    const { log } = run(scripted(failure('RBAC_012'), 'saved'));

    expect(log.info).toHaveBeenCalledTimes(1);
    expect(log.info).toHaveBeenCalledWith(expect.any(String), {
      event: 'access_console_retry_rbac_012',
      context: { operation: 'replace', roleId: ROLE_ID },
    });
    expect(JSON.stringify(log.info.mock.calls)).not.toContain('Server detail');
  });
});
