import { DestroyRef, Injector, runInInjectionContext } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  DEFAULT_RETRY_AFTER_SECONDS,
  createRetryCountdown,
  retryAfterSeconds,
} from './retry-after';

describe('retryAfterSeconds (design §7.4)', () => {
  it('uses the server value when it sent one', () => {
    expect(retryAfterSeconds({ code: 'AUTH_005', message: 'x', retryAfterSeconds: 7 })).toBe(7);
  });

  it('waits 30 seconds when the server sent no Retry-After', () => {
    expect(DEFAULT_RETRY_AFTER_SECONDS).toBe(30);
    expect(retryAfterSeconds({ code: 'AUTH_005', message: 'x' })).toBe(30);
  });
});

describe('createRetryCountdown', () => {
  let destroy: () => void;
  let destroyRef: DestroyRef;

  beforeEach(() => {
    vi.useFakeTimers();
    const callbacks: (() => void)[] = [];
    destroyRef = {
      onDestroy: (fn: () => void) => {
        callbacks.push(fn);
        return () => undefined;
      },
      destroyed: false,
    } as unknown as DestroyRef;
    destroy = () => callbacks.forEach((fn) => fn());
  });

  afterEach(() => vi.useRealTimers());

  it('counts whole seconds down to zero, then is inactive', () => {
    const countdown = createRetryCountdown(destroyRef);
    expect(countdown.active()).toBe(false);

    countdown.start(3);
    expect(countdown.active()).toBe(true);
    expect(countdown.remaining()).toBe(3);

    vi.advanceTimersByTime(1000);
    expect(countdown.remaining()).toBe(2);
    vi.advanceTimersByTime(2000);
    expect(countdown.remaining()).toBe(0);
    expect(countdown.active()).toBe(false);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('counts against a deadline, so a late tick (a throttled background tab) does not drift (MN-11)', () => {
    const countdown = createRetryCountdown(destroyRef);
    countdown.start(30);

    // The clock moves on while no timer fires, as in a hidden tab, then one tick runs.
    vi.setSystemTime(Date.now() + 10_000);
    vi.advanceTimersByTime(1000);

    expect(countdown.remaining()).toBe(19);
    vi.setSystemTime(Date.now() + 60_000);
    vi.advanceTimersByTime(1000);
    expect(countdown.remaining()).toBe(0);
    expect(countdown.active()).toBe(false);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('restarts from the new value when started again', () => {
    const countdown = createRetryCountdown(destroyRef);
    countdown.start(5);
    vi.advanceTimersByTime(3000);

    countdown.start(10);
    expect(countdown.remaining()).toBe(10);
    vi.advanceTimersByTime(9000);
    expect(countdown.remaining()).toBe(1);
  });

  it('stop ends it at once', () => {
    const countdown = createRetryCountdown(destroyRef);
    countdown.start(5);

    countdown.stop();

    expect(countdown.active()).toBe(false);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('a non-positive wait is not a countdown', () => {
    const countdown = createRetryCountdown(destroyRef);
    countdown.start(0);
    expect(countdown.active()).toBe(false);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('clears its timer when the owner is destroyed', () => {
    const countdown = createRetryCountdown(destroyRef);
    countdown.start(5);

    destroy();

    expect(vi.getTimerCount()).toBe(0);
  });

  it('works with a real DestroyRef', () => {
    const injector = TestBed.inject(Injector);
    const countdown = runInInjectionContext(injector, () =>
      createRetryCountdown(TestBed.inject(DestroyRef)),
    );
    countdown.start(1);
    vi.advanceTimersByTime(1000);
    expect(countdown.active()).toBe(false);
  });
});
