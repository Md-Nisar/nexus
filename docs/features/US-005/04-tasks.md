# US-005 Task Breakdown

**Status:** DRAFT — awaiting Gate 3 approval
**Story:** US-005 — Enable logout with refresh token revocation | Epic: EPIC-001
**Date:** 2026-06-29
**Design ref:** `03-design.md` (Gate 2 approved 2026-06-29)

---

## Sequencing overview

```
T-01 (ADR-0008)          ─┐
T-02 (LogoutUseCaseTest) ─┤  parallel — no inter-task deps
T-03 (AuthAuditIT ext.)  ─┤
T-04 (AUTH_PATHS fix)    ─┘
                               │
                          T-05 (Dashboard button)  ← depends on T-04
                               │
                          T-06 (Playwright e2e)    ← depends on T-04 + T-05
```

T-01 through T-04 are fully independent and can be executed in any order or in parallel.
T-05 must follow T-04 (interceptor must not do spurious refresh before dashboard is verified).
T-06 must follow T-04 and T-05 (needs the fix + the button).

---

## T-01 — Create ADR-0008

**File:** `docs/adr/0008-access-token-revocation-jti-denylist.md`
**Type:** Documentation
**Dependencies:** None
**Risk:** Low

### What

Create the ADR that formally records the TTL-only decision for GA and documents the Redis `jti`
denylist as a planned fast-follow. Content is fully drafted in `03-design.md §4`.

### Acceptance criteria

- [ ] File created at the exact path above.
- [ ] Status: `Accepted`; Date: `2026-06-29`.
- [ ] Three options (A/B/C) presented with clear rationale for each.
- [ ] Option A chosen; rationale covers: bounded 15-min window, refresh-revocation closes durable
      risk, ADR-0007 constraint (no Redis), Option C hot-path cost.
- [ ] Option B explicitly labelled "planned fast-follow" with implementation note (JwtPort denylist
      check keyed on `jti`; no claims-contract change needed since `jti` already present).
- [ ] Four re-evaluation triggers listed (compliance SLA, TTL increase, kill-all-sessions, Redis
      adoption for another reason).
- [ ] Cross-references ADR-0007.

---

## T-02 — Create LogoutUseCaseTest (backend unit test)

**File:** `nexus-backend/src/test/java/com/example/nexus/identity/application/service/LogoutUseCaseTest.java`
**Type:** Backend test (pure — no production code change)
**Dependencies:** None
**Risk:** Low

### What

Four-branch JUnit 5 + Mockito unit test for `LogoutUseCase.execute`. Mocked collaborators:
`RefreshTokenPort`, `AuthEventPort`, `TokenHasher`, `UuidGenerator`, `Clock`. Uses
`Clock.fixed(...)` for a deterministic `fixedInstant`.

### Four test methods

| Method | Key setup | Key assertions |
|---|---|---|
| `bearer_path_revokes_by_userId_without_touching_cookie` | `userId` = fixed UUID, `rawRefreshToken` = `null` | `verify(refreshTokenPort).revokeByUserId(userId, fixedInstant)`; `verifyNoInteractions(tokenHasher)`; captured `AuthEvent` has `LOGOUT`/`SUCCESS`, correct userId + ip |
| `cookie_only_path_resolves_userId_then_revokes` | `userId` = `null`, `rawRefreshToken` = `"deadbeef"`, hash → `"HASH"`, findByHash → token with resolvedUserId | `verify(tokenHasher).hash("deadbeef")`; `verify(refreshTokenPort).findByTokenHash("HASH")`; `verify(refreshTokenPort).revokeByUserId(resolvedUserId, fixedInstant)`; event userId = resolvedUserId |
| `malformed_cookie_degrades_to_audit_only` | `userId` = `null`, `rawRefreshToken` = `"not-hex"`, `tokenHasher.hash` throws `IllegalArgumentException` | `verify(refreshTokenPort, never()).revokeByUserId(any(), any())`; event recorded once with userId = `null`, no exception propagated |
| `unknown_cookie_degrades_to_audit_only` | `userId` = `null`, `rawRefreshToken` = `"abcd"`, hash → `"HASH"`, findByHash → `Optional.empty()` | `verify(refreshTokenPort, never()).revokeByUserId(any(), any())`; event recorded once with userId = `null` |

### Engineer notes

- Every branch records exactly one `AuthEvent` — assert `verify(authEventPort, times(1)).record(capture)` in all four.
- Use `ArgumentCaptor<AuthEvent>` to inspect the recorded event; assert `getEventType()`, `getOutcome()`, `getUserId()`, `getIpAddress()`.
- Branch 3 (`malformed`) covers the `catch (IllegalArgumentException ignored)` block — this is the JaCoCo gate escape hatch (MEMORY: jacoco-toString-coverage-gap pattern).
- No Spring context (`@ExtendWith(MockitoExtension.class)` only).

### Acceptance criteria

- [ ] All four branches pass.
- [ ] No `@SpringBootTest` or `@MockBean` — pure Mockito.
- [ ] JaCoCo branch coverage of `LogoutUseCase.execute` reaches 100% for the branches-under-test.
- [ ] `./mvnw verify -DskipITs` (no Docker) passes with the new test included.

---

## T-03 — Add bearer/multi-family test to AuthAuditIT (backend IT)

**File:** `nexus-backend/src/test/java/com/example/nexus/identity/interfaces/rest/AuthAuditIT.java`
**Type:** Backend integration test
**Dependencies:** None (parallel with T-02)
**Risk:** Low

### What

Append one `@Test` to the existing `AuthAuditIT` class. Reuses all existing helpers (`createActiveUser`,
`doLoginPost`, `extractCookieValue`, `doLogoutPost`, `doRefreshPost`). Requires Docker / Testcontainers.

### Test method

```java
@Test
void bearer_logout_revokes_tokens_across_multiple_families()
```

**Flow:**
1. `createActiveUser(email)`.
2. Login #1 → `accessToken1`, `refreshToken1` (family A).
3. Login #2 (same credentials) → `refreshToken2` (family B).
4. `doLogoutPost(accessToken1)` (Bearer) → assert **204**.
5. `doRefreshPost(refreshToken1)` → **401** (family A revoked).
6. `doRefreshPost(refreshToken2)` → **401** (family B revoked — proves revoke-by-user, not by-cookie).
7. Assert `LOGOUT`/`SUCCESS` `AuthEvent` exists for `user.getId()` (mirror stream assertion from `logout_records_audit_event`).

### Acceptance criteria

- [ ] Test passes on Testcontainers MySQL (Docker required).
- [ ] `./mvnw verify` (full suite, with Docker) passes.
- [ ] Test name appears in Surefire/Failsafe report.
- [ ] Does NOT duplicate any assertion already covered by the existing `logout_records_audit_event` or `tokenless_logout_revokes_server_side_refresh_tokens` methods.

---

## T-04 — Fix AUTH_PATHS gap in auth.interceptor.ts + regression spec

**Files:**
- `nexus-frontend/src/app/core/http/auth.interceptor.ts` (1-line change)
- `nexus-frontend/src/app/core/http/auth.interceptor.spec.ts` (1 new test)

**Type:** Frontend fix + test (test-first)
**Dependencies:** None
**Risk:** Medium (security fix — see T-5.4 / R2)

### What (test first — write the failing spec before touching production code)

**Step 1 — write the failing spec test:**

Add to `auth.interceptor.spec.ts`:

```ts
it('does not issue POST /refresh when POST /logout returns 401', () => {
  // seed store with a far-future session (proactive branch must not fire)
  authStore.setSession({ accessToken: 'tok', expiresAt: Date.now() + 3_600_000 });

  http.post('/api/v1/auth/logout', null).subscribe({ error: () => {} });

  httpMock
    .expectOne(req => req.url.endsWith('/api/v1/auth/logout'))
    .flush(null, { status: 401, statusText: 'Unauthorized' });

  httpMock.expectNone(req => req.url.endsWith('/api/v1/auth/refresh'));
  httpMock.verify();
});
```

Confirm this test **fails** before the fix (interceptor attempts a spurious `/refresh`).

**Step 2 — fix `auth.interceptor.ts`:**

```ts
// Before (line 14):
const AUTH_PATHS = ['/api/v1/auth/login', '/api/v1/auth/refresh'];

// After:
const AUTH_PATHS = ['/api/v1/auth/login', '/api/v1/auth/refresh', '/api/v1/auth/logout'];
```

Confirm the spec test now **passes** (green).

### Acceptance criteria

- [ ] `AUTH_PATHS` array contains exactly three entries after the change.
- [ ] New spec test name: `does not issue POST /refresh when POST /logout returns 401`.
- [ ] `httpMock.expectNone` for `/refresh` passes (no spurious refresh on logout 401).
- [ ] `npm run test:ci` passes with the new spec included.
- [ ] No other interceptor spec tests broken.

---

## T-05 — Revise DashboardComponent with logout button

**Files:**
- `nexus-frontend/src/app/features/dashboard/dashboard.component.ts`
- `nexus-frontend/src/app/features/dashboard/dashboard.component.spec.ts`

**Type:** Frontend feature
**Dependencies:** T-04 (interceptor must not spuriously refresh before testing the button flow)
**Risk:** Low

### What (test-first)

**Step 1 — write / extend dashboard spec:**

The dashboard spec must cover:

| Test | Setup | Assertion |
|---|---|---|
| `shows logout button` | render component | `[data-testid="logout-button"]` is visible |
| `sets loggingOut signal while logout is in-flight` | `authService.logout` returns a Subject (not yet complete) | `loggingOut()` is `true`; button has `[disabled]` attribute |
| `navigates to /auth/login and shows success toast on successful logout` | `authService.logout` completes (success) | `router.navigate` called with `['/auth/login']`; `toast.success` called with `'You have been logged out.'` |
| `navigates to /auth/login and shows error toast on logout HTTP failure` | `authService.logout` errors | `router.navigate` called with `['/auth/login']`; `toast.error` called |

**Step 2 — implement the component** (exact code from `03-design.md §3.3`):

- Inject `HttpClient`, `APP_CONFIG`, `AuthService`, `Router`, `NxToast` via `inject()`.
- `loggingOut = signal(false)`.
- `ngOnInit`: existing `GET /v1/users/me` probe (already present in the current component — keep it).
- `onLogout()`: set `loggingOut(true)`, call `authService.logout()`, `finalize(() => loggingOut.set(false))`, `next` + `error` both toast + navigate.
- Template: `<nx-button variant="secondary" [loading]="loggingOut()" [disabled]="loggingOut()" data-testid="logout-button" (clicked)="onLogout()">`.
- `NxButton` in `imports[]`; `NxToast` via `inject()` only (not in `imports[]`).

### Acceptance criteria

- [ ] `[data-testid="logout-button"]` renders in the dashboard template.
- [ ] Button is disabled and shows loading indicator while logout is in-flight.
- [ ] On logout success: `toast.success('You have been logged out.')` called; router navigates to `/auth/login`.
- [ ] On logout error: `toast.error(...)` called; router still navigates to `/auth/login` (user not stranded).
- [ ] `NxToast` is **not** in the component's `imports[]` array.
- [ ] `npm run test:ci` passes.
- [ ] No TypeScript strict-mode errors (`npm run lint`).

---

## T-06 — Create Playwright e2e logout spec

**File:** `nexus-frontend/e2e/auth/logout.spec.ts`
**Type:** E2E test
**Dependencies:** T-04 (interceptor fix), T-05 (dashboard button)
**Risk:** Low (test flakiness — see R7)

### What

New Playwright spec mirroring `e2e/auth/session-refresh.spec.ts` structure. Three test cases:

| Case | Steps | Assertions |
|---|---|---|
| TS-1 Golden path | login → click `[data-testid="logout-button"]` | `toHaveURL(/\/auth\/login/)` after redirect; toast `You have been logged out.` visible |
| TS-2 Back button guard | TS-1 → `page.goBack()` | URL stays `/auth/login`; `[data-testid="dashboard-root"]` not visible |
| TS-3 Cookie cleared | login → logout → `context.cookies()` | No live `refresh_token` cookie scoped to `/api/v1/auth`; direct `POST /refresh` → 401 |

### Engineer notes

- Use `process.env['E2E_TEST_USER_EMAIL']` / `'E2E_TEST_USER_PASSWORD'` with fallback defaults.
- Assert URL and cookie absence (deterministic) before asserting toast visibility (R7 — avoid toast-timing flakiness).
- Add `test.beforeEach` that skips if backend is not reachable (`GET /actuator/health`), mirroring the existing e2e pattern.
- Use `context.cookies()` (not `page.evaluate(document.cookie)`) to read `HttpOnly` cookies.

### Acceptance criteria

- [ ] All three test cases pass against a running backend + frontend.
- [ ] Spec skips gracefully when the backend is not up (CI without Docker).
- [ ] No `page.waitForTimeout` (flakiness risk) — use `page.waitForURL`, `expect(locator).toBeVisible`, `context.cookies()`.
- [ ] File path: `nexus-frontend/e2e/auth/logout.spec.ts`.

---

## Summary table

| Task | Type | File(s) | Deps | Risk | Test-first |
|---|---|---|---|---|---|
| T-01 | Docs | `docs/adr/0008-*.md` | — | Low | N/A |
| T-02 | Backend test | `LogoutUseCaseTest.java` | — | Low | Yes (test IS the deliverable) |
| T-03 | Backend IT | `AuthAuditIT.java` (append) | — | Low | Yes (test IS the deliverable) |
| T-04 | Frontend fix + spec | `auth.interceptor.ts` + `.spec.ts` | — | Med | Yes (spec first, then fix) |
| T-05 | Frontend feature | `dashboard.component.ts` + `.spec.ts` | T-04 | Low | Yes (spec first) |
| T-06 | E2E | `e2e/auth/logout.spec.ts` | T-04, T-05 | Low | Yes (test IS the deliverable) |

**Estimated story points:** 3 (matches planning estimate — bulk of production code already shipped in US-003)

---

## Definition of Done (US-005)

- [ ] All six tasks complete and their acceptance criteria met.
- [ ] `./mvnw verify -DskipITs` passes (backend unit + quality gates, no Docker).
- [ ] `./mvnw verify` passes (Testcontainers IT suite, Docker required).
- [ ] `npm run test:ci` passes (Vitest + coverage).
- [ ] `npm run lint && npm run format:check` pass.
- [ ] Playwright e2e passes against a running stack.
- [ ] ADR-0008 created and cross-referenced from the PR description.
- [ ] `/review`, `/security-review`, `/test-validate`, `/pre-pr-check` all pass.
- [ ] PR raised against `main` with the AC traceability table.
