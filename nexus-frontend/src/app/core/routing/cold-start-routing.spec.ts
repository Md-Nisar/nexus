import { provideHttpClient } from '@angular/common/http';
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
): Promise<{ refreshCount: number }> {
  const harness = await RouterTestingHarness.create();
  const navigation = harness.navigateByUrl(url);

  let pending: TestRequest[] = [];
  for (let i = 0; i < 200 && pending.length === 0; i++) {
    await vi.advanceTimersByTimeAsync(10);
    pending = refreshRequests(http);
  }
  const refreshCount = pending.length;
  await vi.advanceTimersByTimeAsync(REFRESH_DELAY_MS);
  for (const refresh of pending) answer(refresh);
  await vi.advanceTimersByTimeAsync(0);
  await navigation;
  return { refreshCount };
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
          useValue: { production: false, apiBaseUrl: API, logLevel: 'debug' },
        },
        provideAnimationsAsync(),
        provideHttpClient(),
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

  it('sends a user whose refresh fails to the login page', async () => {
    await coldNavigate('/role-test', http, (refresh) =>
      refresh.flush({ message: 'expired' }, { status: 401, statusText: 'Unauthorized' }),
    );

    expect(url().startsWith('/auth/login')).toBe(true);
  });

  it('sends exactly one POST /refresh, including the shell priming request', async () => {
    await coldNavigate('/role-test', http, (refresh) => flushSession(http, refresh, ['role:read']));
    await vi.advanceTimersByTimeAsync(0);

    expect(refreshRequests(http)).toEqual([]);
    http.expectOne(`${API}/v1/users/me`).flush({});
    http.verify();
  });
});
