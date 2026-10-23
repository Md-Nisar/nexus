import { provideHttpClient, withInterceptors } from '@angular/common/http';
import {
  HttpTestingController,
  TestRequest,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { Component } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import { Router, Routes, provideRouter } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { routes } from '../../app.routes';
import { APP_CONFIG } from '../config/app-config';
import { permissionGuard } from '../guards/permission.guard';
import { apiErrorInterceptor } from '../http/api-error.interceptor';
import { authInterceptor } from '../http/auth.interceptor';
import { correlationIdInterceptor } from '../http/correlation-id.interceptor';

const API = 'http://localhost:1000/api';
const REFRESH_DELAY_MS = 500;

@Component({ template: '<h1 data-testid="role-page">Roles</h1>' })
class RolePage {}

/** The real route table with a `role:read` child added under the real shell. */
function buildRoutes(): Routes {
  const shell = routes[routes.length - 1];
  return [
    ...routes.slice(0, -1),
    {
      ...shell,
      // Before the shell's `**` Not Found catch-all, which would otherwise match first.
      children: [
        {
          path: 'role-test',
          canActivate: [permissionGuard],
          data: { permission: 'role:read' },
          component: RolePage,
        },
        ...(shell.children ?? []),
      ],
    },
  ];
}

function refreshRequests(http: HttpTestingController): TestRequest[] {
  return http.match((req) => req.method === 'POST' && req.url.endsWith('/auth/refresh'));
}

/**
 * Starts a navigation to `url`, lets the lazy shell and the guards run, and answers the refresh
 * only after {@link REFRESH_DELAY_MS} of fake time, as a slow network would.
 */
async function coldNavigate(
  url: string,
  http: HttpTestingController,
  answer: (refresh: TestRequest) => void,
): Promise<{ refreshCount: number; harness: RouterTestingHarness }> {
  const harness = await RouterTestingHarness.create();
  const navigation = harness.navigateByUrl(url);
  const refreshCount = await answerRefresh(http, answer);
  await navigation;
  return { refreshCount, harness };
}

/**
 * Waits for the refresh(es) in flight, answers each after {@link REFRESH_DELAY_MS}, and returns
 * how many there were. Every pending refresh is counted, so a second concurrent one would show.
 */
async function answerRefresh(
  http: HttpTestingController,
  answer: (refresh: TestRequest) => void,
): Promise<number> {
  let pending: TestRequest[] = [];
  for (let i = 0; i < 200 && pending.length === 0; i++) {
    await vi.advanceTimersByTimeAsync(10);
    pending = refreshRequests(http);
  }
  await vi.advanceTimersByTimeAsync(REFRESH_DELAY_MS);
  pending.push(...refreshRequests(http));
  for (const refresh of pending) answer(refresh);
  await vi.advanceTimersByTimeAsync(0);
  return pending.length;
}

/** Fails the refresh at the transport level (connection refused or reset): `NETWORK_ERROR`. */
function dropConnection(refresh: TestRequest): void {
  refresh.error(new ProgressEvent('error'), { status: 0, statusText: '' });
}

/** A backend problem document: the refresh cookie was rejected (a reuse, an expiry, a revocation). */
function rejectRefresh(refresh: TestRequest): void {
  refresh.flush(
    { code: 'AUTH_004', detail: 'Refresh token is invalid.', traceId: 'trace-auth-004' },
    { status: 401, statusText: 'Unauthorized' },
  );
}

function retryButton(harness: RouterTestingHarness): HTMLButtonElement {
  const root = harness.routeNativeElement as HTMLElement;
  return root.querySelector('[data-testid="unavailable-retry"]') as HTMLButtonElement;
}

/** Waits out the longest cool-down (10 s + 5 s jitter with no Retry-After), then presses Retry. */
async function pressRetryAfterCoolDown(harness: RouterTestingHarness, presses = 1): Promise<void> {
  await vi.advanceTimersByTimeAsync(15_000);
  harness.detectChanges();
  expect(retryButton(harness).getAttribute('aria-disabled')).toBeNull();
  for (let i = 0; i < presses; i++) retryButton(harness).click();
}

function flushSession(
  http: HttpTestingController,
  refresh: TestRequest,
  permissions: readonly string[],
): void {
  refresh.flush({ accessToken: 't', tokenType: 'Bearer', expiresIn: 3600, userId: 'u1' });
  http
    .expectOne(
      (req) =>
        req.method === 'GET' &&
        req.url === `${API}/v1/users/me` &&
        req.headers.has('Authorization'),
    )
    .flush({
      userId: 'u1',
      tenantId: 't1',
      emailVerified: true,
      roles: ['USER'],
      permissions,
      tokenVersion: 1,
    });
}

describe('cold start routing (real router, real shell and guards)', () => {
  let http: HttpTestingController;

  beforeEach(() => {
    vi.useFakeTimers();
    TestBed.configureTestingModule({
      providers: [
        {
          provide: APP_CONFIG,
          useValue: {
            production: false,
            apiBaseUrl: API,
            logLevel: 'debug',
            accessConsoleEnabled: false,
          },
        },
        provideAnimationsAsync(),
        // The production interceptor chain (app.config.ts), so a refresh failure reaches the guard
        // as the same AppError it would in the app.
        provideHttpClient(
          withInterceptors([correlationIdInterceptor, apiErrorInterceptor, authInterceptor]),
        ),
        provideHttpClientTesting(),
        provideRouter([...buildRoutes()]),
      ],
    });
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  function url(): string {
    return TestBed.inject(Router).url;
  }

  it.each(['/dashboard', '/'])('lands an entitled user on %s after one refresh', async (target) => {
    const { refreshCount } = await coldNavigate(target, http, (refresh) =>
      flushSession(http, refresh, ['role:read']),
    );

    expect(refreshCount).toBe(1);
    expect(url()).toBe('/dashboard');
  });

  it('lands an entitled user on a permission-guarded deep link', async () => {
    await coldNavigate('/role-test', http, (refresh) => flushSession(http, refresh, ['role:read']));

    expect(url()).toBe('/role-test');
  });

  it('sends an unentitled user to /access-denied', async () => {
    await coldNavigate('/role-test', http, (refresh) => flushSession(http, refresh, []));

    expect(url()).toBe('/access-denied');
  });

  it('sends a user whose refresh is rejected by the backend to the login page', async () => {
    const { refreshCount } = await coldNavigate('/role-test', http, rejectRefresh);

    expect(refreshCount).toBe(1);
    expect(url()).toBe('/auth/login?returnUrl=%2Frole-test');
  });

  it('sends exactly one POST /refresh, including the shell priming request', async () => {
    await coldNavigate('/role-test', http, (refresh) => flushSession(http, refresh, ['role:read']));
    await vi.advanceTimersByTimeAsync(0);

    expect(refreshRequests(http)).toEqual([]);
    http.expectOne(`${API}/v1/users/me`).flush({});
    http.verify();
  });

  describe('nobody authoritative answers (US-020 T-002, design §4.5)', () => {
    it('lands a dropped connection on /unavailable with the returnUrl, after exactly one refresh', async () => {
      const { refreshCount, harness } = await coldNavigate('/role-test', http, dropConnection);

      expect(refreshCount).toBe(1);
      expect(url()).toBe('/unavailable?returnUrl=%2Frole-test');
      expect(retryButton(harness)).not.toBeNull();
    });

    it('lands a gateway answer that is not a problem document (HTTP_ERROR) on /unavailable', async () => {
      await coldNavigate('/role-test', http, (refresh) =>
        refresh.flush('<html>502 Bad Gateway</html>', { status: 502, statusText: 'Bad Gateway' }),
      );

      expect(url()).toBe('/unavailable?returnUrl=%2Frole-test');
    });

    it('makes zero requests while the view is shown, through the whole cool-down', async () => {
      await coldNavigate('/role-test', http, dropConnection);

      await vi.advanceTimersByTimeAsync(120_000);

      http.verify();
      expect(url()).toBe('/unavailable?returnUrl=%2Frole-test');
    });

    it('re-enters through the shell with exactly one more refresh, never two concurrent', async () => {
      const { harness } = await coldNavigate('/role-test', http, dropConnection);

      await pressRetryAfterCoolDown(harness, 3);
      const refreshCount = await answerRefresh(http, (refresh) =>
        flushSession(http, refresh, ['role:read']),
      );
      await vi.advanceTimersByTimeAsync(0);

      expect(refreshCount).toBe(1);
      expect(url()).toBe('/role-test');
      expect(refreshRequests(http)).toEqual([]);
    });

    it('restarts the cool-down when the retried refresh fails the same way again', async () => {
      const { harness } = await coldNavigate('/role-test', http, dropConnection);

      await pressRetryAfterCoolDown(harness);
      const refreshCount = await answerRefresh(http, dropConnection);
      harness.detectChanges();

      expect(refreshCount).toBe(1);
      expect(url()).toBe('/unavailable?returnUrl=%2Frole-test');
      expect(retryButton(harness).getAttribute('aria-disabled')).toBe('true');
      expect(retryButton(harness).getAttribute('aria-busy')).toBeNull();
      await vi.advanceTimersByTimeAsync(60_000);
      http.verify();
    });

    it('RC-71: a lost refresh response then Retry (a reuse, 401 AUTH_004) lands on login, no loop', async () => {
      const { harness } = await coldNavigate('/role-test', http, dropConnection);
      expect(url()).toBe('/unavailable?returnUrl=%2Frole-test');

      await pressRetryAfterCoolDown(harness);
      const refreshCount = await answerRefresh(http, rejectRefresh);

      expect(refreshCount).toBe(1);
      expect(url()).toBe('/auth/login?returnUrl=%2Frole-test');

      await vi.advanceTimersByTimeAsync(120_000);
      expect(refreshRequests(http)).toEqual([]);
      expect(url()).toBe('/auth/login?returnUrl=%2Frole-test');
    });
  });
});
