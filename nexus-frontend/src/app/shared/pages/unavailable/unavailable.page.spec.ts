import { HttpClient, provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { Component, EnvironmentProviders, Provider } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { Router, Routes, provideRouter } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';
import { Subject } from 'rxjs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { LoggerService } from '../../../core/logging/logger.service';
import { UnavailableState } from '../../../core/routing/unavailable-state';
import { NxAnnouncer } from '../../ui';
import { COOL_DOWN_RANDOM } from './unavailable-notice';
import { UnavailablePage } from './unavailable.page';

const NOW = Date.parse('2026-10-23T10:00:00Z');

@Component({ template: '<h1>Target</h1>' })
class TargetPage {}

/** A navigation to `/pending` settles only when a test says so, so Retry stays in flight. */
let pendingGuard = new Subject<boolean>();

const ROUTES: Routes = [
  { path: 'unavailable', component: UnavailablePage, data: { selfManagedFocus: true } },
  { path: 'dashboard', component: TargetPage },
  { path: 'admin/access/roles', component: TargetPage },
  { path: 'auth/login', component: TargetPage },
  { path: 'pending', canActivate: [() => pendingGuard], component: TargetPage },
  {
    path: 'broken',
    loadComponent: () => Promise.reject(new Error('chunk load failed')),
  },
];

/**
 * UnavailablePage (US-020 design §4.5, §12.11, RC-75): a static page with no HTTP, a cooled-down
 * Retry that only navigates, and the reference held in memory, never in the URL.
 */
describe('UnavailablePage', () => {
  let harness: RouterTestingHarness;
  let announce: ReturnType<typeof vi.fn>;
  let random: ReturnType<typeof vi.fn>;
  let warn: ReturnType<typeof vi.fn>;

  function configure(extra: (Provider | EnvironmentProviders)[] = []): void {
    TestBed.configureTestingModule({
      providers: [
        provideRouter(ROUTES),
        { provide: NxAnnouncer, useValue: { announce, clear: vi.fn() } },
        { provide: COOL_DOWN_RANDOM, useValue: random },
        {
          provide: LoggerService,
          useValue: { warn, error: vi.fn(), info: vi.fn(), debug: vi.fn() },
        },
        ...extra,
      ],
    });
  }

  async function open(url: string): Promise<HTMLElement> {
    harness = await RouterTestingHarness.create();
    await harness.navigateByUrl(url, UnavailablePage);
    harness.detectChanges();
    return harness.routeNativeElement as HTMLElement;
  }

  function q(testId: string): HTMLElement | null {
    return (harness.routeNativeElement as HTMLElement).querySelector(`[data-testid="${testId}"]`);
  }

  function retry(): HTMLButtonElement {
    return q('unavailable-retry') as HTMLButtonElement;
  }

  async function advance(ms: number): Promise<void> {
    await vi.advanceTimersByTimeAsync(ms);
    harness.detectChanges();
  }

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
    announce = vi.fn(() => Promise.resolve());
    random = vi.fn(() => 0.6);
    warn = vi.fn();
    pendingGuard = new Subject<boolean>();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('makes no HTTP call', () => {
    it('renders and retries without HttpClient ever being injected', async () => {
      const factory = vi.fn(() => {
        throw new Error('UnavailablePage must not inject HttpClient');
      });
      configure([{ provide: HttpClient, useFactory: factory }]);

      await open('/unavailable?returnUrl=%2Fadmin%2Faccess%2Froles');
      await advance(16_000);
      retry().click();
      await advance(0);

      expect(factory).not.toHaveBeenCalled();
      expect(TestBed.inject(Router).url).toBe('/admin/access/roles');
    });

    it('issues zero requests on render, during the countdown and on Retry', async () => {
      configure([provideHttpClient(), provideHttpClientTesting()]);
      const http = TestBed.inject(HttpTestingController);

      await open('/unavailable?returnUrl=%2Fdashboard');
      await advance(60_000);
      retry().click();
      await advance(0);

      http.verify();
    });
  });

  describe('content and focus', () => {
    beforeEach(() => configure());

    it('renders one h1 with the unavailable copy and focuses it', async () => {
      const root = await open('/unavailable');
      await advance(0);

      const headings = root.querySelectorAll('h1');
      expect(headings).toHaveLength(1);
      expect(headings[0].textContent?.trim()).toBe('Nexus is temporarily unavailable');
      expect(document.activeElement).toBe(headings[0]);
      expect(root.textContent).toContain(
        "We couldn't confirm your sign-in because Nexus isn't responding. Your session may still be valid.",
      );
      expect(root.querySelector('main')).not.toBeNull();
    });

    it('shows the recorded reference without putting the trace id in the URL', async () => {
      TestBed.inject(UnavailableState).record({
        code: 'AUTH_005',
        message: 'unavailable',
        traceId: 'trace-secret-7',
        retryAfterSeconds: 30,
      });

      await open('/unavailable?returnUrl=%2Fdashboard');

      expect(q('unavailable-reference')?.textContent).toContain('trace-secret-7');
      expect(TestBed.inject(Router).url).not.toContain('trace-secret-7');
      expect(globalThis.location.href).not.toContain('trace-secret-7');
      expect(q('unavailable-sign-in')?.getAttribute('href')).not.toContain('trace-secret-7');
    });

    it('offers no contact link (supportContact is null, Q23)', async () => {
      const root = await open('/unavailable');
      expect(root.querySelectorAll('a')).toHaveLength(1);
    });
  });

  describe('return URL', () => {
    beforeEach(() => configure());

    it('points "Go to sign-in" at /auth/login with the validated returnUrl', async () => {
      await open('/unavailable?returnUrl=%2Fadmin%2Faccess%2Froles');
      const link = q('unavailable-sign-in');
      expect(link?.textContent?.trim()).toBe('Go to sign-in');
      expect(link?.getAttribute('href')).toBe('/auth/login?returnUrl=%2Fadmin%2Faccess%2Froles');
    });

    it.each([
      ['the view itself', '%2Funavailable'],
      ['an encoded first segment', '%2F%2575navailable'],
      ['an off-site URL', '%2F%2Fevil.example'],
      ['the login page', '%2Fauth%2Flogin'],
    ])('replaces %s with /dashboard for Retry and sign-in', async (_name, encoded) => {
      await open(`/unavailable?returnUrl=${encoded}`);
      expect(q('unavailable-sign-in')?.getAttribute('href')).toBe(
        '/auth/login?returnUrl=%2Fdashboard',
      );

      await advance(10_000);
      retry().click();
      await advance(0);
      expect(TestBed.inject(Router).url).toBe('/dashboard');
    });

    it('uses /dashboard when there is no returnUrl', async () => {
      await open('/unavailable');
      await advance(10_000);
      retry().click();
      await advance(0);
      expect(TestBed.inject(Router).url).toBe('/dashboard');
    });
  });

  describe('cool-down (RC-75)', () => {
    beforeEach(() => configure());

    it('waits min(Retry-After, 60) s plus seeded jitter from recordedAt', async () => {
      TestBed.inject(UnavailableState).record({
        code: 'AUTH_005',
        message: 'unavailable',
        retryAfterSeconds: 20,
      });
      await open('/unavailable?returnUrl=%2Fdashboard'); // 20 + 0.6 × 5 = 23 s

      expect(q('unavailable-countdown')?.textContent?.trim()).toBe('Retry in 23 s');
      await advance(22_999);
      expect(retry().getAttribute('aria-disabled')).toBe('true');
      await advance(1);
      expect(retry().getAttribute('aria-disabled')).toBeNull();
    });

    it('defaults to 10 s plus jitter when the failure had no Retry-After', async () => {
      TestBed.inject(UnavailableState).record({ code: 'NETWORK_ERROR', message: 'x' });
      await open('/unavailable'); // 10 + 3 s

      await advance(12_999);
      expect(retry().getAttribute('aria-disabled')).toBe('true');
      await advance(1);
      expect(retry().getAttribute('aria-disabled')).toBeNull();
    });

    it('caps a Retry-After of 300 s at 60 s plus jitter', async () => {
      TestBed.inject(UnavailableState).record({
        code: 'AUTH_005',
        message: 'unavailable',
        retryAfterSeconds: 300,
      });
      await open('/unavailable'); // 60 + 3 s

      await advance(62_999);
      expect(retry().getAttribute('aria-disabled')).toBe('true');
      await advance(1);
      expect(retry().getAttribute('aria-disabled')).toBeNull();
    });

    it('counts exactly 10 s from render when there is no state (reload or direct visit)', async () => {
      random.mockReturnValue(0.99);
      vi.setSystemTime(NOW + 50_000);
      await open('/unavailable');

      expect(q('unavailable-countdown')?.textContent?.trim()).toBe('Retry in 10 s');
      await advance(9_999);
      expect(retry().getAttribute('aria-disabled')).toBe('true');
      await advance(1);
      expect(retry().getAttribute('aria-disabled')).toBeNull();
    });

    it('never retries on its own', async () => {
      await open('/unavailable?returnUrl=%2Fdashboard');
      const navigate = vi.spyOn(TestBed.inject(Router), 'navigateByUrl');
      await advance(300_000);
      expect(navigate).not.toHaveBeenCalled();
      expect(TestBed.inject(Router).url).toBe('/unavailable?returnUrl=%2Fdashboard');
    });

    it('makes exactly one polite announcement, at zero', async () => {
      await open('/unavailable');
      await advance(9_000);
      expect(announce).not.toHaveBeenCalled();
      await advance(1_000);
      expect(announce).toHaveBeenCalledTimes(1);
      expect(announce).toHaveBeenCalledWith('You can retry now.', 'polite');
      await advance(60_000);
      expect(announce).toHaveBeenCalledTimes(1);
    });
  });

  describe('Retry', () => {
    beforeEach(() => configure());

    it('navigates once to the validated returnUrl, ignoring a double press', async () => {
      await open('/unavailable?returnUrl=%2Fpending');
      await advance(10_000);
      const navigate = vi.spyOn(TestBed.inject(Router), 'navigateByUrl');

      retry().click();
      retry().click();
      harness.detectChanges();
      retry().click();

      expect(navigate).toHaveBeenCalledTimes(1);
      expect(navigate).toHaveBeenCalledWith('/pending');
      expect(retry().getAttribute('aria-busy')).toBe('true');
      expect(retry().getAttribute('aria-disabled')).toBe('true');
    });

    it('restarts the countdown when the retried navigation records a new failure', async () => {
      await open('/unavailable?returnUrl=%2Fpending');
      await advance(10_000);
      retry().click();
      harness.detectChanges();
      expect(retry().getAttribute('aria-busy')).toBe('true');

      // What authGuard does when the retried refresh fails again and the router ignores the
      // same-URL redirect: a new record, with the page still mounted.
      TestBed.inject(UnavailableState).record({ code: 'NETWORK_ERROR', message: 'x' });
      harness.detectChanges();

      expect(retry().getAttribute('aria-busy')).toBeNull();
      expect(retry().getAttribute('aria-disabled')).toBe('true');
      expect(q('unavailable-countdown')?.textContent?.trim()).toBe('Retry in 13 s');
      await advance(13_000);
      expect(retry().getAttribute('aria-disabled')).toBeNull();
    });

    it('re-enables Retry when the navigation settles without leaving the page', async () => {
      await open('/unavailable?returnUrl=%2Fpending');
      await advance(10_000);
      retry().click();
      await advance(0); // let the router reach the pending guard

      pendingGuard.next(false);
      await advance(0);

      expect(TestBed.inject(Router).url).toBe('/unavailable?returnUrl=%2Fpending');
      expect(retry().getAttribute('aria-busy')).toBeNull();
      expect(retry().getAttribute('aria-disabled')).toBeNull();
    });

    it('stays on the view, logs without the URL and re-enables Retry when navigation errors', async () => {
      await open('/unavailable?returnUrl=%2Fbroken%3Fq%3Dsecret');
      await advance(10_000);
      retry().click();
      await advance(0);
      harness.detectChanges();

      expect(TestBed.inject(Router).url).toBe('/unavailable?returnUrl=%2Fbroken%3Fq%3Dsecret');
      expect(warn).toHaveBeenCalledTimes(1);
      expect(warn.mock.calls[0][1]).toMatchObject({
        event: 'unavailable_retry_navigation_failed',
        outcome: 'FAILURE',
      });
      expect(JSON.stringify(warn.mock.calls)).not.toContain('secret');
      expect(JSON.stringify(warn.mock.calls)).not.toContain('broken');
      expect(retry().getAttribute('aria-busy')).toBeNull();
      expect(retry().getAttribute('aria-disabled')).toBeNull();
    });
  });
});
