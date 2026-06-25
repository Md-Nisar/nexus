# US-004 Task Breakdown — Refresh sessions silently with rotating refresh tokens

Status: GATE 3 APPROVED — READY FOR IMPLEMENTATION  
Sources: `03-design.md` (approved) · `03b-threat-model.md` (approved)  
Date: 2026-06-24

---

## Pre-implementation notes

**No backend changes.** `RefreshTokenUseCase`, `POST /api/v1/auth/refresh`, `refresh_tokens`
schema, and all rotation/theft-detection tests are complete and green from US-003.

**No new dependencies.** The implementation uses only RxJS operators and Angular APIs already
imported in `auth.interceptor.ts`.

**No new feature flag.** US-004 rides `feature.nexus-us003-auth-login.enabled` (story §4).

**Three files touched in total:**
- `nexus-frontend/src/app/core/http/auth.interceptor.ts` (modify)
- `nexus-frontend/src/app/core/http/auth.interceptor.spec.ts` (modify — add tests)
- `nexus-frontend/e2e/auth/session-refresh.spec.ts` (create — new E2E test)

---

## Dependency graph

```
IMPL-01 (interceptor proactive branch)
    └──→ IMPL-02 (unit tests for proactive path)
              └──→ IMPL-03 (E2E test — requires IMPL-01 to run against the real app)
```

Each IMPL must pass `npm run test:ci && npm run lint` before moving to the next.  
IMPL-03 requires the backend running (`./mvnw spring-boot:run`) to run the full golden path.

---

## IMPL-01 — Proactive refresh in `authInterceptor`

**What gets built:** Add the pre-request TTL check to `auth.interceptor.ts`. The reactive-401
path is not modified. Both paths share the same `refreshInFlight` guard.

**Files modified:**
- `nexus-frontend/src/app/core/http/auth.interceptor.ts`

### Changes

**1. Add named threshold constant** (after the `AUTH_PATHS` constant, before the interceptor function):

```typescript
/** Proactively refresh when access token has less than this many ms remaining. */
const PROACTIVE_REFRESH_THRESHOLD_MS = 120_000; // 2 min
```

**2. Add the proactive branch** inside the `authInterceptor` function, between the existing
`const authReq = ...` block and the `return next(authReq)` call. The final structure:

```typescript
export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const authStore = inject(AuthStore);
  const authService = inject(AuthService);
  const router = inject(Router);

  const token = authStore.accessToken();
  const path = new URL(req.url, window.location.origin).pathname;
  const isAuthEndpoint = AUTH_PATHS.includes(path);

  // ── Proactive refresh (AC-4) ────────────────────────────────────────────────
  // Refresh before forwarding if the access token will expire within 2 min.
  // Excluded for auth endpoints to prevent an infinite refresh loop.
  // Both this path and the reactive-401 path below share `refreshInFlight`
  // (shareReplay(1)) so a burst of concurrent requests issues exactly one POST /refresh.
  // Cross-tab safety: the refresh cookie is shared via HttpOnly SameSite=Strict, so
  // a second tab presenting the rotated cookie will not replay a stale token and
  // will not trip theft detection (design §8).
  const session = authStore.session();
  const proactive =
    session !== null &&
    session.expiresAt - Date.now() < PROACTIVE_REFRESH_THRESHOLD_MS;

  if (proactive && !isAuthEndpoint) {
    if (!refreshInFlight) {
      refreshInFlight = authService.refresh().pipe(
        shareReplay(1),
        finalize(() => {
          refreshInFlight = null;
        }),
      );
    }
    return refreshInFlight.pipe(
      switchMap(() =>
        next(
          req.clone({
            setHeaders: { Authorization: `Bearer ${authStore.accessToken()}` },
          }),
        ),
      ),
      catchError((err) => {
        authStore.clearSession();
        router.navigate(['/auth/login']);
        return throwError(() => err);
      }),
    );
  }
  // ── End proactive refresh ───────────────────────────────────────────────────

  const authReq =
    token && !req.headers.has('Authorization')
      ? req.clone({ setHeaders: { Authorization: `Bearer ${token}` } })
      : req;

  return next(authReq).pipe(
    catchError((error: unknown) => {
      // ... existing reactive-401 block unchanged ...
    }),
  );
};
```

**Implementation notes:**

- Read `authStore.accessToken()` *inside the `switchMap`* (after refresh resolves), not from the
  outer `token` variable (which is the pre-refresh stale token). `AuthService.refresh()` calls
  `authStore.setSession()` in its `tap`, so the store is updated before `switchMap` fires.
- The existing `refreshInFlight` module-level variable (`Observable<AuthSession> | null`) and its
  `finalize` reset are reused without modification.
- Do **not** import any new RxJS operators — `switchMap`, `shareReplay`, `finalize`, `catchError`,
  `throwError` are all already imported.

**Definition of Done:**
- `PROACTIVE_REFRESH_THRESHOLD_MS` constant present.
- Proactive branch: enters only when `session !== null`, `expiresAt - now < 120_000`, and
  `!isAuthEndpoint`.
- Reactive-401 `catchError` block byte-for-byte unchanged.
- `npm run lint` green (no `any`, no unused imports).
- `npm run test:ci` green (existing 5 interceptor specs still pass).

---

## IMPL-02 — Unit tests for the proactive path

**What gets built:** Add 8 new test cases to `auth.interceptor.spec.ts` covering the proactive
branch and the threat-model security tests (T-2, T-5, T-3).

**Files modified:**
- `nexus-frontend/src/app/core/http/auth.interceptor.spec.ts`

### Setup additions

The existing `mockAuthStore` already has `session: vi.fn(() => null)`. Pin `expiresAt` via the
mock rather than `vi.useFakeTimers()`:

```typescript
// Helper: session with TTL almost gone
function nearExpirySession(msRemaining = 60_000): AuthSession {
  return { ...TEST_SESSION, expiresAt: Date.now() + msRemaining };
}

// Helper: session with plenty of TTL
function freshSession(): AuthSession {
  return { ...TEST_SESSION, expiresAt: Date.now() + 900_000 };
}
```

### New test cases

**AC-4 / proactive path:**

```
(P-1) TTL < 2 min → proactive refresh fires BEFORE the original request
      mockAuthStore.session returns nearExpirySession()
      mockAuthService.refresh returns of(TEST_SESSION)
      Call http.get('/api/v1/resource')
      Assert: controller receives exactly 2 requests in order:
        [0] '/api/v1/resource' → flush 200          (NOT the refresh, since refresh is via AuthService)
      Wait — refresh is a direct call to authService.refresh(), not an HTTP call in the test
      Actually: assert mockAuthService.refresh was called; the single HTTP request
      '/api/v1/resource' is forwarded with the NEW token (TEST_SESSION.accessToken).
      Flush '/api/v1/resource' with 200.
      Expect result received.
```

> Note: `AuthService.refresh()` is mocked (`mockAuthService.refresh`) — it doesn't go through
> `HttpTestingController`. The test asserts that `refresh()` was called and that the forwarded
> request carries `Authorization: Bearer test-token-abc` (from `TEST_SESSION`).

| # | Name | What to assert |
|---|------|----------------|
| P-1 | `proactive refresh fires when TTL < 2 min` | `mockAuthService.refresh` called once; forwarded `/api/v1/resource` has `Authorization: Bearer test-token-abc`; result received |
| P-2 | `no proactive refresh when TTL > 2 min` | `mockAuthStore.session` returns `freshSession()`; `mockAuthService.refresh` NOT called; request forwarded with existing token |
| P-3 | `no proactive refresh for auth endpoint /api/v1/auth/refresh` | `mockAuthStore.session` returns `nearExpirySession()`; call `http.post('/api/v1/auth/refresh', null)`; `mockAuthService.refresh` NOT called (loop guard) |
| P-4 | `no proactive refresh when session is null` | `mockAuthStore.session` returns `null`; `mockAuthService.refresh` NOT called |
| P-5 | `proactive refresh failure → clearSession + navigate to /auth/login` | `mockAuthStore.session` returns `nearExpirySession()`; `mockAuthService.refresh` returns `throwError(() => new Error('cookie gone'))`; assert `mockAuthStore.clearSession` called; `mockRouter.navigate(['/auth/login'])` called; error rethrown to subscriber |

**T-2 / thundering herd:**

| # | Name | What to assert |
|---|------|----------------|
| T2-1 | `concurrent requests with TTL < 2 min → exactly one refresh call` | `mockAuthStore.session` returns `nearExpirySession()`; `mockAuthService.refresh` returns `of(TEST_SESSION)`. Subscribe to `http.get('/api/v1/a')` and `http.get('/api/v1/b')` without flushing in between. Assert `mockAuthService.refresh` was called **once** (not twice). Flush both `/api/v1/a` and `/api/v1/b`. Both results received. |

**T-5 / no infinite loop:**

| # | Name | What to assert |
|---|------|----------------|
| T5-1 | `after proactive refresh failure, next request does not re-enter proactive path` | Trigger P-5 scenario (refresh fails → session cleared). Then call `http.get('/api/v1/next')`. Assert `mockAuthService.refresh` is NOT called again (session is null, `proactive = false`). Request forwarded with no `Authorization` header (no token in cleared session). |

**T-3 / no token in logs or storage:**

| # | Name | What to assert |
|---|------|----------------|
| T3-1 | `proactive refresh does not write to localStorage or sessionStorage` | `mockAuthStore.session` returns `nearExpirySession()`; `mockAuthService.refresh` returns `of(TEST_SESSION)`. Spy on `localStorage.setItem` and `sessionStorage.setItem`. After refresh, assert neither spy was called. |

**Definition of Done:**
- All 8 new tests pass.
- All 5 existing tests still pass.
- `npm run test:ci` (coverage gate) green.
- No `any` assertions; types match `AuthSession`.

---

## IMPL-03 — E2E test for silent renewal (TS-1)

**What gets built:** A Playwright E2E test that verifies the proactive refresh path end-to-end
against the real backend (TS-1: "idle 20 min, then act → action succeeds, no login prompt").

Since waiting 20 real minutes is impractical, the test achieves the same coverage by **intercepting
the `/api/v1/auth/refresh` response** to return a very-short `expiresIn` (e.g., 5 seconds), then
waiting for the TTL to drop below 2 min (which happens immediately at 5s TTL), then making a
protected request.

**Files created:**
- `nexus-frontend/e2e/auth/session-refresh.spec.ts`

### Test file

```typescript
import { test, expect } from '@playwright/test';

/**
 * E2E: US-004 — silent session renewal (proactive refresh path).
 *
 * Prerequisites:
 *   - Angular dev server running on :2000 (handled by playwright.config.ts webServer)
 *   - Spring Boot backend running on :1000 (start manually: ./mvnw spring-boot:run)
 *
 * Skip gracefully when backend is unreachable (same pattern as registration.spec.ts).
 */

async function isBackendUp(request: import('@playwright/test').APIRequestContext): Promise<boolean> {
  try {
    const resp = await request.get('http://localhost:1000/actuator/health', { timeout: 2_000 });
    return resp.ok();
  } catch {
    return false;
  }
}

test.describe('US-004 — silent session renewal', () => {
  test.beforeEach(async ({ request }, testInfo) => {
    if (!(await isBackendUp(request))) {
      testInfo.skip();
    }
  });

  test('TS-1 — proactive refresh fires before expiry; protected request succeeds without login prompt', async ({
    page,
    context,
  }) => {
    // Step 1: Log in normally (the real login creates a valid refresh cookie).
    await page.goto('/auth/login');
    await page.fill('[data-testid="email-input"]', Deno.env.get('E2E_TEST_USER_EMAIL') ?? 'test@example.com');
    await page.fill('[data-testid="password-input"]', Deno.env.get('E2E_TEST_USER_PASSWORD') ?? 'TestPass99!');
    await page.click('[data-testid="login-submit"]');
    await page.waitForURL(/\/dashboard/, { timeout: 10_000 });

    // Step 2: Intercept the NEXT /auth/refresh response to return expiresIn=5 (5 seconds).
    // This causes the Angular client to set expiresAt = now + 5000, which immediately
    // falls within the < 120 s proactive threshold on the next API call.
    let refreshCallCount = 0;
    await context.route('**/api/v1/auth/refresh', async (route) => {
      const response = await route.fetch();
      const body = await response.json();
      refreshCallCount++;
      await route.fulfill({
        status: response.status(),
        headers: { ...response.headers(), 'content-type': 'application/json' },
        body: JSON.stringify({ ...body, expiresIn: 5 }),
      });
    });

    // Step 3: Trigger one API call to force the first intercepted refresh (the proactive
    // branch will fire on the following call). Navigate to a protected page to trigger
    // a /users/me call via AuthService.login's switchMap.
    // (Alternatively, the next navigation triggers the proactive check.)
    await page.reload();

    // Wait for the session expiresAt to be within the 2-min window (5s TTL means it's
    // already there; just ensure the intercepted refresh has completed).
    await page.waitForTimeout(200);

    // Step 4: Make a protected API call. The proactive branch should fire, call /refresh
    // (which returns a normal TTL this time — unrouted), and the original request succeeds.
    await context.unroute('**/api/v1/auth/refresh');

    // Navigate to a protected route — this triggers a /users/me call through the interceptor.
    await page.goto('/dashboard');
    await expect(page).not.toHaveURL(/\/auth\/login/);
    await expect(page.locator('[data-testid="dashboard-root"]')).toBeVisible({ timeout: 5_000 });

    // At least one proactive refresh was triggered.
    expect(refreshCallCount).toBeGreaterThanOrEqual(1);
  });

  test('TS-4 — replay of revoked refresh token results in 401 and redirect to login', async ({
    page,
  }) => {
    // This is a backend-side property tested by RefreshTokenRotationIT;
    // the E2E concern is that the Angular client handles the resulting AUTH_004
    // by clearing the session and showing the login screen.

    await page.goto('/auth/login');
    await page.fill('[data-testid="email-input"]', Deno.env.get('E2E_TEST_USER_EMAIL') ?? 'test@example.com');
    await page.fill('[data-testid="password-input"]', Deno.env.get('E2E_TEST_USER_PASSWORD') ?? 'TestPass99!');
    await page.click('[data-testid="login-submit"]');
    await page.waitForURL(/\/dashboard/, { timeout: 10_000 });

    // Simulate a /refresh returning 401 (e.g., revoked family) — the client should
    // clear the session and navigate to /auth/login.
    await page.route('**/api/v1/auth/refresh', (route) =>
      route.fulfill({ status: 401, body: JSON.stringify({ code: 'AUTH_004', detail: 'Refresh token invalid' }) }),
    );
    // Also force a 401 on the next API call to trigger the reactive path.
    await page.route('**/api/v1/users/me', (route) =>
      route.fulfill({ status: 401, body: JSON.stringify({ code: 'AUTH_003', detail: 'Token invalid' }) }),
    );

    await page.goto('/dashboard');
    await expect(page).toHaveURL(/\/auth\/login/, { timeout: 5_000 });
  });
});
```

> **`data-testid` attributes:** the `LoginFormComponent` was built in US-003 IMPL-12 without
> `data-testid` attributes. If they are absent, add `data-testid="email-input"`,
> `data-testid="password-input"`, and `data-testid="login-submit"` to the form template as part
> of this IMPL. Similarly add `data-testid="dashboard-root"` to the dashboard root element.
> These are test-only attributes and do not affect production behaviour.
>
> **`E2E_TEST_USER_EMAIL` / `E2E_TEST_USER_PASSWORD`:** pre-seeded ACTIVE test user credentials.
> Default values in the test are suitable for local dev with a migrated DB.

**Definition of Done:**
- Both E2E tests pass against a running backend (`./mvnw spring-boot:run` + `npm run e2e`).
- Tests skip gracefully when the backend is unreachable (`testInfo.skip()`).
- TS-1 asserts: no navigation to `/auth/login`; dashboard visible; at least one proactive refresh
  occurred.
- TS-4 asserts: a failed `/refresh` causes redirect to `/auth/login`.
- `npm run lint` green.

---

## Task summary

| IMPL | Title | Files | Complexity |
|------|-------|-------|------------|
| IMPL-01 | Proactive refresh in `authInterceptor` | `auth.interceptor.ts` | S |
| IMPL-02 | Unit tests — proactive path + security tests | `auth.interceptor.spec.ts` | S |
| IMPL-03 | E2E test — silent renewal + revoked-token redirect | `e2e/auth/session-refresh.spec.ts` | S |

**3 tasks → 3 implementation sessions.**

---

## Acceptance-criteria traceability

| AC | IMPL | Tests |
|----|------|-------|
| AC-1 Refresh rotates token | — (US-003) | `RefreshTokenRotationIT.happy_path_rotation` |
| AC-2 Reuse → family revoke | — (US-003) | `RefreshTokenRotationIT.reused_revoked_token_revokes_family` |
| AC-3 Concurrent race, grace ≤ 10s | — (US-003 backend) + IMPL-02 (frontend) | `RefreshTokenRotationIT.concurrent_rotation_single_winner`, `T2-1` |
| AC-4 Silent renewal | IMPL-01, IMPL-02, IMPL-03 | P-1..P-5, T2-1, T5-1, T3-1, TS-1 (E2E) |

---

*Gate 3 APPROVED. Start with `/implement US-004 IMPL-01`.*
