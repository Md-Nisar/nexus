import { TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { NxToast } from '../../shared/ui';
import { ServiceAvailabilityNotifier } from './service-availability-notifier';

describe('ServiceAvailabilityNotifier', () => {
  let toast: { warning: ReturnType<typeof vi.fn> };
  let router: { navigate: ReturnType<typeof vi.fn>; navigateByUrl: ReturnType<typeof vi.fn> };
  let notifier: ServiceAvailabilityNotifier;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-10-20T12:00:00Z'));
    toast = { warning: vi.fn() };
    router = { navigate: vi.fn(), navigateByUrl: vi.fn() };
    TestBed.configureTestingModule({
      providers: [
        { provide: NxToast, useValue: toast },
        { provide: Router, useValue: router },
      ],
    });
    notifier = TestBed.inject(ServiceAvailabilityNotifier);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should show one warning naming the Retry-After seconds', async () => {
    notifier.notifyUnavailable(30);
    await vi.dynamicImportSettled();

    expect(toast.warning).toHaveBeenCalledOnce();
    expect(toast.warning).toHaveBeenCalledWith(
      'Nexus is temporarily unavailable. Try again in 30 seconds.',
    );
  });

  it('should cap an excessive Retry-After at 300 seconds, in the message and the window', async () => {
    notifier.notifyUnavailable(99_999_999);
    notifier.notifyUnavailable(Infinity);
    await vi.dynamicImportSettled();

    expect(toast.warning).toHaveBeenCalledOnce();
    expect(toast.warning).toHaveBeenCalledWith(
      'Nexus is temporarily unavailable. Try again in 300 seconds.',
    );
    vi.advanceTimersByTime(300_000);
    notifier.notifyUnavailable(30);
    await vi.dynamicImportSettled();
    expect(toast.warning).toHaveBeenCalledTimes(2);
  });

  it('should show one toast for two 503s within the Retry-After window, and never navigate', async () => {
    notifier.notifyUnavailable(30);
    vi.advanceTimersByTime(29_999);
    notifier.notifyUnavailable(30);
    await vi.dynamicImportSettled();

    expect(toast.warning).toHaveBeenCalledOnce();
    expect(router.navigate).not.toHaveBeenCalled();
    expect(router.navigateByUrl).not.toHaveBeenCalled();
  });

  it('should show a new toast once the Retry-After window has passed', async () => {
    notifier.notifyUnavailable(30);
    vi.advanceTimersByTime(30_000);
    notifier.notifyUnavailable(10);

    await vi.dynamicImportSettled();

    expect(toast.warning).toHaveBeenCalledTimes(2);
    expect(toast.warning).toHaveBeenLastCalledWith(
      'Nexus is temporarily unavailable. Try again in 10 seconds.',
    );
  });

  it('should use the singular for one second', async () => {
    notifier.notifyUnavailable(1);
    await vi.dynamicImportSettled();

    expect(toast.warning).toHaveBeenCalledWith(
      'Nexus is temporarily unavailable. Try again in 1 second.',
    );
  });

  it('should fall back to a 30-second window when the response carried no Retry-After', async () => {
    notifier.notifyUnavailable(undefined);
    vi.advanceTimersByTime(29_999);
    notifier.notifyUnavailable(undefined);

    await vi.dynamicImportSettled();

    expect(toast.warning).toHaveBeenCalledOnce();
    expect(toast.warning).toHaveBeenCalledWith(
      'Nexus is temporarily unavailable. Try again in 30 seconds.',
    );
  });
});
