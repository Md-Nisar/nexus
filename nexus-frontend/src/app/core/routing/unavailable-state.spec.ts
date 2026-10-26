import { TestBed } from '@angular/core/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { UnavailableState } from './unavailable-state';

/**
 * UnavailableState (US-020 design §4.5): the in-memory record of the last cold-start refresh that
 * nobody authoritative answered. It must never reach storage or the URL (`app-error.ts` traceId).
 */
describe('UnavailableState', () => {
  let state: UnavailableState;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-10-23T10:00:00Z'));
    TestBed.configureTestingModule({});
    state = TestBed.inject(UnavailableState);
  });

  afterEach(() => {
    vi.useRealTimers();
    localStorage.clear();
    sessionStorage.clear();
  });

  it('holds no record until one is recorded', () => {
    expect(state.latest()).toBeNull();
  });

  it('records the traceId as the reference, the Retry-After and the time', () => {
    state.record({
      code: 'AUTH_005',
      message: 'unavailable',
      traceId: 'trace-1',
      correlationId: 'corr-1',
      retryAfterSeconds: 30,
    });

    expect(state.latest()).toEqual({
      reference: 'trace-1',
      retryAfterSeconds: 30,
      recordedAt: Date.parse('2026-10-23T10:00:00Z'),
    });
  });

  it('falls back to the correlationId when the error carries no traceId', () => {
    state.record({
      code: 'NETWORK_ERROR',
      message: 'Could not reach the server.',
      correlationId: 'c',
    });
    expect(state.latest()?.reference).toBe('c');
    expect(state.latest()?.retryAfterSeconds).toBeUndefined();
  });

  it('has no reference when the error carries neither id', () => {
    state.record({ code: 'HTTP_ERROR', message: 'Request failed with status 502.' });
    expect(state.latest()?.reference).toBeUndefined();
  });

  it('replaces the record on a second failure with a new identity and time', () => {
    state.record({ code: 'NETWORK_ERROR', message: 'x', correlationId: 'a' });
    const first = state.latest();
    vi.advanceTimersByTime(12_000);
    state.record({ code: 'NETWORK_ERROR', message: 'x', correlationId: 'b' });

    expect(state.latest()).not.toBe(first);
    expect(state.latest()?.reference).toBe('b');
    expect(state.latest()?.recordedAt).toBe((first?.recordedAt ?? 0) + 12_000);
  });

  it('clear() drops the record, so a later visit shows no stale reference (MN-4)', () => {
    state.record({ code: 'AUTH_005', message: 'm', traceId: 'trace-1', retryAfterSeconds: 5 });

    state.clear();

    expect(state.latest()).toBeNull();
  });

  it('never writes to localStorage or sessionStorage', () => {
    const setItem = vi.spyOn(Storage.prototype, 'setItem');
    state.record({ code: 'AUTH_005', message: 'm', traceId: 'trace-1', retryAfterSeconds: 5 });
    expect(setItem).not.toHaveBeenCalled();
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it('keeps no message, details or permission from the error', () => {
    state.record({
      code: 'AUTH_005',
      message: 'server text',
      traceId: 't',
      details: [{ field: 'f', message: 'detail' }],
      requiredPermission: 'role:read',
    });
    expect(Object.keys(state.latest() ?? {}).sort()).toEqual([
      'recordedAt',
      'reference',
      'retryAfterSeconds',
    ]);
  });
});
