# Test Audit — US-004: Refresh sessions silently with rotating refresh tokens

**Scope:** Frontend only (Angular 21). No backend code was changed.
**Auditor:** QA Engineer (claude-sonnet-4-6)
**Date:** 2026-06-25

---

## Coverage audit for Task US-004

### Existing tests (before this audit)

**`nexus-frontend/src/app/core/http/auth.interceptor.spec.ts`** — 21 tests total (6 pre-existing + 9 new proactive-path tests already committed)

Pre-existing (6):
- `attaches Authorization header when session has token`
- `does not attach Authorization when no session`
- `does not overwrite existing Authorization header`
- `on 401, clears session and navigates to /auth/login for non-auth URLs`
- `on 401 to /auth/refresh, does NOT navigate or clear session`
- `on 401, attempts refresh and retries the original request on success`

New proactive-path (9, already written):
- `P-1` — TTL < 2 min fires proactive refresh; new token forwarded
- `P-2` — TTL > 2 min skips proactive refresh
- `P-3` — `/auth/refresh` URL skips proactive (loop guard)
- `P-4` — null session skips proactive
- `P-5` — proactive failure clears session and navigates to login
- `T2-1` — 2 concurrent requests with near-expiry share one refresh call
- `T2-2` — proactive in-flight + concurrent reactive-401 share one refresh call
- `T5-1` — after proactive failure, next request skips proactive (session null)
- `T3-1` — proactive cycle does not write to localStorage/sessionStorage

**`nexus-frontend/src/app/core/guards/auth.guard.spec.ts`** — 2 tests:
- `returns true when authenticated`
- `returns UrlTree to /auth/login when not authenticated` (checked type only, not target path)

**`nexus-frontend/e2e/auth/session-refresh.spec.ts`** — 2 Playwright E2E tests (backend-gated):
- `TS-1` — proactive refresh fires before expiry; protected request succeeds
- `TS-4` — revoked refresh token clears session and redirects to login

**`nexus-frontend/src/app/features/dashboard/dashboard.component.ts`** — no component spec.
(Not a gap: the component is a minimal stub with no logic beyond `ngOnInit` delegating to the auth interceptor, which is fully covered by the interceptor spec.)

---

### Gaps identified

- **[HIGH] 401 on `/auth/login` does not trigger reactive refresh** — P-3 covered only `/auth/refresh`. `/auth/login` is the other member of `AUTH_PATHS` and must also be exempt from the reactive-401 recovery path (and from proactive). Gap closed in `auth.interceptor.spec.ts`.

- **[HIGH] Boundary value: TTL exactly equal to 120,000 ms** — The proactive condition is strict `< 120_000`. A session with `expiresAt - Date.now() === 120_000` must NOT trigger proactive refresh. Not previously tested. Gap closed with B-1 and B-2 (1 ms below threshold, to cover both sides). Both tests freeze `Date.now()` for determinism.

- **[MED] Third concurrent proactive request joins existing in-flight** — T2-1 covered two concurrent requests; a third arriving while the `shareReplay(1)` observable is still live must join the same flight rather than start a new one. Gap closed with T2-3.

- **[MED] `authGuard` redirect target not verified** — the existing spec only checked that the result was not `true` and was an object. It did not assert `createUrlTree` was called with `['/auth/login']`. The mock records `_commands`; the assertion was straightforward. Gap closed in `auth.guard.spec.ts`.

---

### Tests added

**File: `nexus-frontend/src/app/core/http/auth.interceptor.spec.ts`**

1. `P-3b: no proactive refresh for /api/v1/auth/login (loop guard covers all AUTH_PATHS)`
2. `on 401 to /api/v1/auth/login, does NOT trigger reactive refresh or navigate`
3. `B-1: no proactive refresh when TTL is exactly equal to the 2-min threshold (strict less-than)`
4. `B-2: proactive refresh fires when TTL is 1 ms below the threshold (boundary)`
5. `T2-3: three concurrent proactive requests share exactly one refresh call`

**File: `nexus-frontend/src/app/core/guards/auth.guard.spec.ts`**

6. `UrlTree redirect points to /auth/login (target verified)`

---

### Run results

Backend: N/A (frontend-only feature)
Frontend: **123/123 passing** — 21 test files

Coverage summary (v8):
- Statements: 89.16% (708/794)
- Branches: 87.50% (413/472)
- Functions: 82.96% (112/135)
- Lines: 91.56% (521/569)

---

### Load scenarios

No load test was added. The proactive refresh path is triggered client-side by the Angular interceptor — there is no new backend endpoint introduced by US-004. The `/api/v1/auth/refresh` endpoint is shared with US-003; its load characteristics are documented in `docs/features/US-004/load-test-plan.md`.

---

### Flaky tests

**Latent risk — module-level `refreshInFlight` variable:**
The `refreshInFlight` variable in `auth.interceptor.ts` is module-scoped (not reset between test runs by Vitest). In the current suite this is safe because every test that opens a `Subject`-based refresh completes or errors it synchronously before the test ends, causing `finalize()` to reset the variable. However, if a future test leaves the Subject open (no `.complete()` or `.error()` call before the test ends), `refreshInFlight` will remain non-null at the start of the next test, causing that test to reuse the stale observable instead of creating a new one. Recommendation: add a `beforeEach` that imports and resets the module if test isolation issues arise, or extract `refreshInFlight` into a resettable token.

**No other flaky tests identified.** B-1 and B-2 use `vi.spyOn(Date, 'now')` with `vi.restoreAllMocks()` so they are deterministic regardless of wall-clock timing.
