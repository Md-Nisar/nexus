# US-005 Solution Design

**Status:** APPROVED — Gate 2 passed 2026-06-29
**Story:** US-005 | Epic: EPIC-001
**Date:** 2026-06-29

## 1. Design summary

US-005 enables an authenticated user to log out from the **dashboard**, revoking all server-side
refresh tokens so a captured refresh cookie cannot be replayed. The production code path is already
in place from US-003: `LogoutUseCase` (atomic revoke-all + LOGOUT audit), `POST /api/v1/auth/logout`
(204 + cookie-clear), `AuthService.logout()` (POST then `clearSession()` in `finalize`), and
`AuthStore.clearSession()`. **No production backend code is written in this story** — the work is
the user-facing trigger plus the test coverage that locks the behaviour.

Key design decisions, all reusing existing patterns:

- **Revocation strategy is TTL-only for GA.** The access token remains valid for its short residual
  window (≤15 min); the refresh family is revoked immediately in the DB. A `jti` denylist for
  instant access-token revocation is a planned fast-follow recorded in **ADR-0008** (no in-sprint
  Redis — ADR-0007 already commits to "no Redis / external token store" for now).
- **CSRF protection is `SameSite=Strict`** on the refresh cookie (already set by
  `LoginController.buildRefreshCookie`). No CSRF token is added — the logout endpoint has no
  state-changing effect beyond the caller's own session, and `Strict` blocks cross-site POSTs.
- **The interceptor must treat `/api/v1/auth/logout` as an auth endpoint** so a 401 during logout
  is not turned into a spurious `POST /refresh` that resurrects the session. This is the only
  functional frontend change of substance (one line + a spec).
- **The button lives in `DashboardComponent`**, not the app header (Gate 1 decision), and reuses
  `NxButton` + `NxToast`. No new components, no new routes, no new services, no new dependencies.

---

## 2. Backend design

### 2.1 LogoutUseCaseTest — test specification

New file: `nexus-backend/src/test/java/com/example/nexus/identity/application/service/LogoutUseCaseTest.java`

Plain JUnit 5 + Mockito unit test (no Spring context). Collaborators are mocked:
`RefreshTokenPort`, `AuthEventPort`, `TokenHasher`, `UuidGenerator`, `Clock`. Use a fixed
`Clock.fixed(...)` so `clock.instant()` is deterministic. `uuidGenerator.newId()` returns a fixed
UUID. `authEventPort.record(...)` is a `void` mock — assert it via `ArgumentCaptor<AuthEvent>`.

The four branches map exactly to the four control-flow paths in `LogoutUseCase.execute`:

| # | Method | Setup | Call | Assertions |
|---|--------|-------|------|------------|
| 1 | `bearer_path_revokes_by_userId_without_touching_cookie()` | `userId` = fixed UUID; `rawRefreshToken` = `null` | `execute(userId, null, "203.0.113.7")` | `verify(refreshTokenPort).revokeByUserId(userId, fixedInstant)`; `verifyNoInteractions(tokenHasher)` (cookie path never entered); captured `AuthEvent` has type `LOGOUT`, outcome `SUCCESS`, `userId` = the bearer userId, `ipAddress` = `203.0.113.7` |
| 2 | `cookie_only_path_resolves_userId_then_revokes()` | `userId` = `null`; `rawRefreshToken` = `"deadbeef"`; `tokenHasher.hash("deadbeef")` returns `"HASH"`; `refreshTokenPort.findByTokenHash("HASH")` returns `Optional.of(refreshToken)` where `refreshToken.getUserId()` = resolved UUID | `execute(null, "deadbeef", ip)` | `verify(tokenHasher).hash("deadbeef")`; `verify(refreshTokenPort).findByTokenHash("HASH")`; `verify(refreshTokenPort).revokeByUserId(resolvedUserId, fixedInstant)`; captured event `userId` = resolvedUserId |
| 3 | `malformed_cookie_degrades_to_audit_only()` | `userId` = `null`; `rawRefreshToken` = `"not-hex"`; `tokenHasher.hash("not-hex")` throws `IllegalArgumentException` | `execute(null, "not-hex", ip)` | `verify(refreshTokenPort, never()).revokeByUserId(any(), any())`; captured event recorded with `userId` = `null`, outcome `SUCCESS` (exception swallowed, no rethrow) |
| 4 | `unknown_cookie_degrades_to_audit_only()` | `userId` = `null`; `rawRefreshToken` = `"abcd"`; `tokenHasher.hash` returns `"HASH"`; `refreshTokenPort.findByTokenHash("HASH")` returns `Optional.empty()` | `execute(null, "abcd", ip)` | `verify(refreshTokenPort, never()).revokeByUserId(any(), any())`; captured event `userId` = `null`, outcome `SUCCESS` |

Notes for the engineer:
- Every branch records exactly one `AuthEvent` — assert `verify(authEventPort, times(1)).record(...)` in all four.
- Branch 1 must assert the cookie-resolution path is **not** taken (`verifyNoInteractions(tokenHasher)`), proving Bearer takes precedence over cookie.
- Do not assert on `withUserId(null)` returning a distinct object — `AuthEvent` is a domain record; assert on the captured instance's accessor (`getUserId()` is `null`).

### 2.2 AuthAuditIT addition — Bearer/multi-family test

New `@Test` appended to `AuthAuditIT` (`...interfaces/rest/AuthAuditIT.java`). Reuse existing
helpers: `createActiveUser`, `doLoginPost`, `extractCookieValue`, `doLogoutPost`, `doRefreshPost`.

```
@Test
void bearer_logout_revokes_tokens_across_multiple_families()
```

Setup and flow:
1. `createActiveUser(email)`.
2. **First login** → capture `accessToken1` from the body and `refreshToken1` from the
   `Set-Cookie` header (family A). Use `doLoginPost` + `extractCookieValue`.
3. **Second login** with the same credentials → capture `refreshToken2` (family B). Two independent
   logins create two distinct refresh-token families for the same user.
4. `doLogoutPost(accessToken1)` (Bearer-authenticated) → assert **204**.
5. Assert **both families revoked**: `doRefreshPost(refreshToken1)` → **401** and
   `doRefreshPost(refreshToken2)` → **401**. Logout revokes by `userId`, so every family for
   that user is killed, not just the one tied to the presented cookie.
6. Assert a `LOGOUT` / `SUCCESS` `AuthEvent` exists for `user.getId()` (mirror the
   `anyMatch` stream assertion already used in `logout_records_audit_event`).

This test specifically proves the **revoke-by-user (not revoke-by-cookie)** contract. Keep it
rotation-safe by never reusing a refresh token across two `doRefreshPost` calls.

### 2.3 No production code changes

Confirmed explicitly. The following are **unchanged** by US-005:

- `LogoutUseCase.java` — already handles all four branches.
- `LoginController.java` — `POST /logout` already returns 204 and clears the cookie.
- `RefreshTokenPort` / `AuthEventPort` / `TokenHasher` — no new methods.
- No Flyway migration — `revoked_at` column and `idx_refresh_tokens_user_id_revoked_at` already exist.
- No `application.yml` / feature-flag changes.

---

## 3. Frontend design

### 3.1 auth.interceptor.ts — AUTH_PATHS fix

The interceptor's `AUTH_PATHS` list drives `isAuthEndpoint`, which suppresses both the proactive
and reactive refresh branches. `/logout` is currently absent, so a 401 returned from `POST /logout`
(e.g. an already-expired access token at logout time) would trigger `POST /refresh` and could
resurrect a session the user is trying to end.

**Before** (`auth.interceptor.ts:14`):
```ts
const AUTH_PATHS = ['/api/v1/auth/login', '/api/v1/auth/refresh'];
```

**After:**
```ts
const AUTH_PATHS = ['/api/v1/auth/login', '/api/v1/auth/refresh', '/api/v1/auth/logout'];
```

One-line change. The exact-pathname comparison (`AUTH_PATHS.includes(path)`) means no false matches.

### 3.2 auth.interceptor.spec.ts — new test

Add to the existing interceptor spec (Vitest + `HttpTestingController`).

```
it('does not issue POST /refresh when POST /logout returns 401')
```

Setup:
- Seed `AuthStore` with a session whose `expiresAt` is **far in the future** (proactive branch does not fire; test isolates the reactive-401 path).

Action:
- Issue `POST /api/v1/auth/logout` through the interceptor.
- `httpMock.expectOne('.../api/v1/auth/logout').flush(null, { status: 401, statusText: 'Unauthorized' })`.

Assertions:
- `httpMock.expectNone('.../api/v1/auth/refresh')` — no refresh attempted.
- The 401 propagates to the caller (error is rethrown, not swallowed into a retry).
- `httpMock.verify()` confirms no outstanding requests.

This is the regression test for **T-5.4** (session resurrection via spurious refresh).

### 3.3 DashboardComponent — logout button

Complete revised component (add logout trigger; keep `OnPush`, standalone, `inject()`-based):

```ts
import { ChangeDetectionStrategy, Component, inject, OnInit, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Router } from '@angular/router';
import { catchError, EMPTY, finalize } from 'rxjs';
import { APP_CONFIG } from '../../core/config/app-config';
import { AuthService } from '../auth/auth.service';
import { NxButton, NxToast } from '../../shared/ui';

@Component({
  selector: 'nx-dashboard',
  standalone: true,
  imports: [NxButton],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <main class="dashboard" data-testid="dashboard-root">
      <h1>Dashboard</h1>
      <nx-button
        variant="secondary"
        [loading]="loggingOut()"
        [disabled]="loggingOut()"
        data-testid="logout-button"
        (clicked)="onLogout()"
      >
        Log out
      </nx-button>
    </main>
  `,
})
export class DashboardComponent implements OnInit {
  private readonly http = inject(HttpClient);
  private readonly config = inject(APP_CONFIG);
  private readonly authService = inject(AuthService);
  private readonly router = inject(Router);
  private readonly toast = inject(NxToast);

  protected readonly loggingOut = signal(false);

  ngOnInit(): void {
    // Triggers the auth interceptor — the proactive refresh branch fires here
    // when expiresAt - Date.now() < PROACTIVE_REFRESH_THRESHOLD_MS (120 s).
    this.http
      .get(`${this.config.apiBaseUrl}/v1/users/me`)
      .pipe(catchError(() => EMPTY))
      .subscribe();
  }

  onLogout(): void {
    this.loggingOut.set(true);
    this.authService
      .logout()
      .pipe(finalize(() => this.loggingOut.set(false)))
      .subscribe({
        // AuthService.logout() calls clearSession() in finalize(), so session is null
        // by the time either branch runs. Both branches navigate to login.
        next: () => {
          this.toast.success('You have been logged out.');
          this.router.navigate(['/auth/login']);
        },
        error: () => {
          // Logout is best-effort: cookie is cleared server-side and local session is
          // wiped via finalize. Route to login so the user is never left on a protected
          // page with a dead session.
          this.toast.error('Logout could not be confirmed, but your session was ended.');
          this.router.navigate(['/auth/login']);
        },
      });
  }
}
```

Design notes:
- `AuthService.logout()` already wipes the local session in `finalize`, so both `next` and `error` branches navigate to login — the user is never stranded.
- `variant="secondary"` — logout is a routine action, not a destructive one.
- `NxToast` is provided at root and injected via `inject()`; it is not added to `imports` (it is not a component).

### 3.4 e2e/auth/logout.spec.ts — Playwright spec outline

New file: `nexus-frontend/e2e/auth/logout.spec.ts`. Mirror structure of `e2e/auth/session-refresh.spec.ts`.

Test cases:

| # | Case | Key assertions |
|---|------|----------------|
| TS-1 | Golden path: logout redirects to login and shows toast | Click `[data-testid="logout-button"]` → `expect(page).toHaveURL(/\/auth\/login/)` → toast `You have been logged out.` visible |
| TS-2 | Back button after logout does not restore the dashboard | `page.goBack()` after logout → authGuard redirects → `toHaveURL(/\/auth\/login/)`, dashboard root not visible |
| TS-3 | `refresh_token` cookie is cleared after logout | `context.cookies()` → no live `refresh_token` cookie scoped to `/api/v1/auth`; direct `POST /refresh` → 401 |

Spec skeleton:

```ts
import { test, expect } from '@playwright/test';

const EMAIL = process.env['E2E_TEST_USER_EMAIL'] ?? 'test@example.com';
const PASSWORD = process.env['E2E_TEST_USER_PASSWORD'] ?? 'TestPass99!';

async function isBackendUp(request): Promise<boolean> { /* GET /actuator/health */ }
async function login(page): Promise<void> { /* fill + submit + waitForURL(/\/dashboard/) */ }

test.describe('US-005 — logout with refresh token revocation', () => {
  test.beforeEach(async ({ request }, testInfo) => {
    if (!(await isBackendUp(request))) testInfo.skip();
  });

  test('TS-1 — golden path: logout redirects to login and shows toast', async ({ page }) => { /* ... */ });
  test('TS-2 — back button does not restore the dashboard after logout', async ({ page }) => { /* ... */ });
  test('TS-3 — refresh_token cookie is cleared after logout', async ({ page, context }) => { /* ... */ });
});
```

---

## 4. ADR-0008 content

Full content for `docs/adr/0008-access-token-revocation-jti-denylist.md`:

```markdown
# ADR 0008 — Access-Token Revocation Strategy: TTL-Only for GA, jti Denylist as Fast-Follow

**Status:** Accepted
**Date:** 2026-06-29
**Author:** Engineering Team

## Context

US-005 introduces user-initiated logout. Logout revokes all server-side **refresh** tokens for the
user (DB-backed `jpa_refresh_tokens`), so a captured refresh cookie cannot be replayed. However, the
**access token** is a stateless RS256 JWT (ADR-0007): it carries no server-side state and is accepted
by `JwtPort` verification until it expires. After logout, an already-issued access token therefore
remains technically valid for its residual TTL.

The access-token TTL is **900 s (15 min)** (`AuthConstants.AUTH_ACCESS_TOKEN_TTL` / US-003). The
question for US-005: do we need to invalidate access tokens **immediately** on logout, or is the
residual-TTL window acceptable for GA?

Three options:

**Option A — TTL-only (status quo).** Logout revokes refresh tokens; the access token expires
naturally within ≤15 min. No new infrastructure.

**Option B — `jti` denylist in a fast store (Redis).** Each access token carries a unique `jti`
claim. Logout writes the `jti` to a denylist with a TTL equal to the remaining access-token
lifetime. `JwtPort` verification consults the denylist on every request. Provides near-instant
revocation.

**Option C — `jti` denylist in MySQL.** Same as B but using the existing MySQL instance instead of
Redis, avoiding a new datastore at the cost of a per-request DB read on the auth hot path.

## Decision

**Adopt Option A (TTL-only) for GA. Defer Option B (Redis `jti` denylist) as a planned fast-follow,
not in this sprint.**

Rationale:

1. **The exposure window is bounded and short.** The worst case is a ≤15-min window during which a
   *previously legitimate, already-issued* access token still verifies after the user clicked logout.
   This is not new attack surface introduced by US-005 — it is the inherent property of stateless
   JWTs accepted in ADR-0007 ("revocation is handled by short TTL + refresh-token rotation").

2. **Refresh revocation closes the durable risk.** The dangerous, long-lived credential is the
   14-day refresh token. Logout revokes the entire refresh family for the user immediately and
   atomically (`LogoutUseCase`), so the session cannot be silently extended past the access-token
   window. After ≤15 min the user is fully locked out.

3. **No Redis in scope (consistent with ADR-0007).** ADR-0007 explicitly commits to "no Redis /
   external token store" for the current architecture. Adding Redis for a 15-min residual window is
   not justified by the current threat model and would introduce a new operational dependency,
   failure mode, and deployment surface. Option C (MySQL denylist) avoids new infra but adds a DB
   read to **every authenticated request** — an unacceptable hot-path cost for the same bounded
   benefit.

4. **The fast-follow path is already designed.** When revocation SLA tightens (see triggers below),
   Option B is the chosen implementation: `JwtPort` gains a denylist check keyed on `jti` with a
   TTL equal to the token's remaining lifetime, populated by `LogoutUseCase`. The access token
   already carries a `jti` claim, so no claims-contract change is required.

## Triggers for re-evaluation (adopting Option B)

- A compliance or security audit mandates a revocation SLA shorter than the access-token TTL.
- The access-token TTL is increased beyond 15 min for any reason.
- A "log out everywhere / kill session now" admin capability is introduced.
- Redis is adopted for another reason, lowering the marginal cost of the denylist.

## Consequences

- For GA, logout's user-visible contract is: refresh family revoked immediately; access token
  expires within ≤15 min. This is documented in the US-005 design and threat model (T-5.1).
- No code, schema, or dependency changes are made by this ADR — it records the deliberate decision
  and the fast-follow plan so the residual window is an *accepted, tracked* risk rather than an
  oversight.
- The frontend mitigates the *client-visible* window fully: `AuthStore.clearSession()` discards the
  in-memory access token on logout, so the SPA stops sending it immediately. The residual window
  only matters to an attacker who already exfiltrated the raw access token before logout.
```

---

## 5. Observability

No new metrics, traces, or log fields are required for US-005.

- **Audit trail:** `LogoutUseCase` already records a `LOGOUT` / `SUCCESS` `AuthEvent` in
  `auth_events` with `userId` (when resolvable) and `ipAddress`. Sufficient for forensics and
  compliance.
- **Correlation:** `CorrelationIdFilter` MDC is already on the request thread. No controller-level
  logging added; raw tokens must never be logged (covered by existing `no_raw_refresh_token_in_logs`
  IT in `AuthAuditIT`).
- **No new dashboard/alert.** Logout is not a failure-prone hot path. If a future `jti` denylist
  (ADR-0008 Option B) is adopted, a `auth.logout.revocations` counter and denylist-store latency
  metric would be introduced then.

---

## 6. Sequence diagram

Happy-path logout (Bearer-authenticated, from the dashboard):

```
Browser          DashboardComponent    AuthService     Interceptor    LoginController    LogoutUseCase      MySQL
  |  click logout      |                   |               |                |                  |               |
  |-------------------->| onLogout()        |               |                |                  |               |
  |                     | loggingOut(true)  |               |                |                  |               |
  |                     |------------------>| logout()      |                |                  |               |
  |                     |                   |--POST /logout->| (AUTH_PATHS:  |                  |               |
  |                     |                   | withCredentials|  no proactive |                  |               |
  |                     |                   | + Bearer+cookie|  refresh)     |                  |               |
  |                     |                   |               |---POST /logout->| execute(userId,  |               |
  |                     |                   |               |                |   cookie, ip)    |               |
  |                     |                   |               |                |----------------->| revokeByUser  |
  |                     |                   |               |                |                  |-------------->| UPDATE
  |                     |                   |               |                |                  | record(LOGOUT)|
  |                     |                   |               |                |                  |-------------->| INSERT
  |                     |                   |               |                | 204+Set-Cookie   |  (single TX)  |
  |                     |                   |               |<--Max-Age=0----|<-----------------|               |
  |<--204, cookie clrd--------------------- |<--------------|                |                  |               |
  |                     |                   | finalize:     |                |                  |               |
  |                     |                   |  clearSession()|               |                  |               |
  |                     | next: toast.success()             |                |                  |               |
  |                     | router.navigate(['/auth/login'])  |                |                  |               |
  |<--SPA route to /auth/login-------------|               |                |                  |               |
```

Key invariants:
- Interceptor does not fire a proactive/reactive refresh because `/api/v1/auth/logout` is in `AUTH_PATHS`.
- Revocation + audit commit atomically in one `@Transactional` boundary.
- `clearSession()` runs in `finalize` before either `next`/`error` branch.
- Both `next` and `error` branches navigate to `/auth/login` — user is never stranded.
