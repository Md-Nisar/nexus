# US-005 Requirements — Enable logout with refresh token revocation

**Status:** APPROVED — Gate 1 passed 2026-06-29  
**Story:** US-005 | Epic: EPIC-001 Identity & Access  
**Date:** 2026-06-29  
**Analyst:** Claude (business-analyst)

---

## 1. Problem statement

Users need a secure logout mechanism that revokes all server-side refresh tokens so that a stolen
or abandoned device cannot mint new access tokens. Residual access-token validity is bounded by the
15-minute TTL (or instantly if a jti denylist is adopted — ARC decision required). This story
completes the session lifecycle started in US-003 (login) and US-004 (silent renewal).

---

## 2. Bounded context

**`identity`** — the same bounded context that owns `users`, `refresh_tokens`, `auth_events`,
`LoginUseCase`, `RefreshTokenUseCase`, and the frontend `AuthService`/`AuthStore`. No new bounded
context is introduced.

---

## 3. Non-goals (explicit out-of-scope)

- "Log out all devices" UI (requires session management — future epic)
- Immediate access-token revocation beyond the 15-min TTL ceiling (ADR decision point only)
- MFA challenge or step-up during logout
- Device fingerprinting

---

## 4. Reuse-first survey (what already exists)

### 4.1 Backend — substantially complete from US-003

| Artifact | Location | Status |
|---|---|---|
| `LogoutUseCase.java` | `identity/application/service/` | **Complete** — handles Bearer-authenticated and cookie-only scenarios; revokes all tokens for user; records LOGOUT audit event atomically in one `@Transactional` boundary |
| `POST /api/v1/auth/logout` | `LoginController.java` | **Complete** — returns 204 with `Set-Cookie: refresh_token=; Max-Age=0; HttpOnly; Secure; SameSite=Strict` |
| `RefreshTokenPort.revokeByUserId()` | `application/port/out/` | **Complete** — bulk revocation via `idx_refresh_tokens_user_id_revoked_at` index |
| `RefreshToken.revoke(Instant)` | `identity/domain/` | **Complete** — intention-revealing domain method |
| `refresh_tokens` schema | `V2__identity_schema.sql` | **Complete** — `revoked_at` column, family + user-id indexes |
| `AuthEventPort` LOGOUT event | `application/port/out/` | **Complete** — `auth_events` table append-only |
| `LoginControllerTest` logout test | test layer | Partial — 1 happy-path test only (unit, MockMvc) |

### 4.2 Frontend — partially complete from US-003/US-004

| Artifact | Location | Status |
|---|---|---|
| `AuthService.logout()` | `features/auth/auth.service.ts:60` | **Complete** — POSTs with `withCredentials`, clears session via `finalize` |
| `AuthStore.clearSession()` | `core/auth/auth.store.ts` | **Complete** — sets session signal to null |
| `NxToast` service | `shared/ui/toast/toast.ts` | **Complete** — `success()` / `error()` / `info()` methods |
| `authGuard` | `core/guards/auth.guard.ts` | **Complete** — redirects to `/auth/login` when unauthenticated |
| Auth interceptor `AUTH_PATHS` | `core/http/auth.interceptor.ts:14` | **Partial** — excludes login + refresh, but NOT logout |
| Logout button / UI trigger | app header / dashboard | **Missing** |
| Logout toast + redirect | (caller component) | **Missing** |
| `auth.service.spec.ts` logout tests | test layer | Partial — 2 tests (happy-path + HTTP-failure still clears session); no interceptor tests for logout path |
| E2E logout test | `e2e/auth/` | **Missing** |

### 4.3 ADR gap

ADR-0007 documents TTL-only as the current revocation approach and notes that a blocklist can be
added. AC-3 (US-005) requires the jti denylist decision to be formally recorded in an ADR before
this story is closed.

---

## 5. Acceptance criteria (re-stated with implementation notes)

| # | AC | Priority | Notes |
|---|----|----------|-------|
| AC-1 | `POST /api/v1/auth/logout` revokes the refresh token family within 1s; subsequent `POST /api/v1/auth/refresh` returns 401 | P0 | **Already implemented** — `LogoutUseCase.revokeByUserId`. Test coverage gap: integration test confirming refresh → 401 after logout is missing |
| AC-2 | Access token, cookie, and cached identity removed; user redirected to login with confirmation toast | P0 | Cookie cleared by backend (existing). Client session cleared by `finalize` (existing). **Gap: logout button and toast wiring are missing** |
| AC-3 | Revoked-session access tokens rejected no later than access-token expiry (15 min); jti denylist decision documented in ADR | P1 | Access token stateless — current 15-min TTL ceiling is correct. **Gap: formal ADR-0008 recording TTL-only decision** |
| AC-4 | Repeat logout returns 204; no error surfaced to user | P1 | `revokeByUserId` is idempotent (UPDATE WHERE revoked_at IS NULL). **Gap: double-logout integration test** |

---

## 6. Impact map

### 6.1 Backend

| Layer | Change | Type |
|---|---|---|
| `domain` | None | — |
| `application/service` | `LogoutUseCase` — exists, no change | — |
| `application/port/out` | `RefreshTokenPort` — exists, no change | — |
| `infrastructure/persistence` | Existing JPA adapter — no change | — |
| `interfaces/rest` | `LoginController.logout()` — exists, no change | — |
| `test` | `LogoutUseCaseTest.java` (new), `LogoutIT.java` (new) | CREATE |

### 6.2 Frontend

| Layer | Change | Type |
|---|---|---|
| `core/http/auth.interceptor.ts` | Add `/api/v1/auth/logout` to `AUTH_PATHS` | MODIFY (1 line) |
| `core/http/auth.interceptor.spec.ts` | Add logout-path tests | MODIFY |
| `app.html` or dashboard | Add logout button | MODIFY |
| Dashboard / header component | Wire `AuthService.logout()` + toast + redirect | MODIFY |
| `e2e/auth/logout.spec.ts` | Logout E2E (golden path + back-button + double logout) | CREATE |

### 6.3 Documentation

| Artifact | Change | Type |
|---|---|---|
| `docs/adr/0008-access-token-revocation-jti-denylist.md` | Record TTL-only decision; denylist as fast-follow | CREATE |

### 6.4 Data

No schema migrations required. The `refresh_tokens` table and `revoked_at` column are in place
from V2 (US-001). No new tables or columns.

---

## 7. Non-functional requirements

| NFR | Target | Notes |
|---|---|---|
| **Revocation latency** | < 1s | Single indexed UPDATE on `refresh_tokens`; already p95 < 50ms in load test |
| **Logout performance** | < 200ms p95 at 50 RPS | US-005 TS-5 load scenario |
| **Idempotency** | 204 on repeat | `WHERE revoked_at IS NULL` makes bulk revoke a no-op on second call |
| **Audit** | LOGOUT event recorded in `auth_events` | Same transaction as revocation |
| **Security: token in body** | Never | Cookie cleared via `Set-Cookie: Max-Age=0`; raw token never in response body |
| **Security: CSRF** | `SameSite=Strict` on cookie limits CSRF; logout endpoint is state-changing POST | Existing mitigation sufficient for MVP |
| **Observability** | LOGOUT event in `auth_events`; correlation-id in MDC | Already wired in `LogoutUseCase` |

---

## 8. Security concerns (for threat-model phase)

1. **Residual access-token window (T-5.x)** — After logout, an intercepted access token remains
   valid for up to 15 min. The jti denylist ADR must explicitly accept this risk or mandate a
   control (Redis denylist as fast-follow).
2. **Logout CSRF** — An attacker could forge a POST /logout request, logging the victim out. This
   is a low-severity DoS on the session. `SameSite=Strict` cookie mitigates cross-site requests.
   A CSRF token on the logout endpoint would fully close this, but adds complexity; flag for ADR.
3. **Token-less logout path** — `LogoutUseCase` handles the case where only the refresh cookie is
   present (access token expired). The `try/catch` on cookie hash lookup must degrade gracefully
   and not leak internal errors.
4. **Auth interceptor retry on logout 401** — If the logout POST returns 401 (expired access
   token), the current interceptor would attempt a token refresh then retry the logout. This is
   functional but wasteful; adding `/api/v1/auth/logout` to `AUTH_PATHS` makes logout
   fire-and-forget from the interceptor's perspective. Required fix.

---

## 9. Open questions (Gate 1 blockers)

| # | Question | Decision | Notes |
|---|---|---|---|
| Q-1 | **jti denylist scope:** TTL-only or denylist for GA? | **TTL-only accepted.** Redis denylist documented in ADR-0008 as planned fast-follow | Redis not in scope for this sprint |
| Q-2 | **Logout button placement:** App header vs. dashboard only? | **Dashboard only** | Header stays minimal; revisit in a future UX epic |
| Q-3 | **CSRF on logout:** SameSite=Strict sufficient? | **Yes — sufficient for MVP** | No CSRF token added to this sprint |

---

## 10. Assumptions

- **A-1:** TTL-only (15-min ceiling) is acceptable for the GA security review. ADR-0008 will
  formally close this decision and record the Redis jti denylist as a planned fast-follow for when
  Redis is added to the application stack (future epic). No in-sprint Redis work.
- **A-2:** Logout button appears in the **dashboard** only (not the app header). The header is
  currently a minimal chrome with only wordmark + theme toggle; logout is dashboard-scoped for now.
- **A-3:** `SameSite=Strict` is sufficient CSRF protection for logout at this stage.
- **A-4:** No backend changes are required — the full server-side implementation is already shipped
  as part of US-003. US-005 scope is: missing tests, frontend logout trigger, and ADR.
- **A-5:** The confirmation toast uses `NxToast.success('You have been signed out.')`.
- **A-6:** On logout error (HTTP failure), the client still clears local state and redirects —
  already implemented via `finalize` in `AuthService.logout()`.

---

## 11. Test scenarios (traceability)

| TS# | Scenario | Type | AC |
|-----|----------|------|----|
| TS-1 | Happy path: click logout → redirect to /auth/login + toast shown; back button → auth guard → /auth/login | E2E | AC-2 |
| TS-2 | Double logout: second POST returns 204, no error | Integration (IT) | AC-4 |
| TS-3 | Refresh after logout: POST /refresh with revoked cookie → 401 | Integration (IT) | AC-1 |
| TS-4 | Cookie-only logout (access token expired): cookie present, no Bearer → revocation succeeds | Unit (LogoutUseCaseTest) | AC-1 |
| TS-5 | Logout at 50 RPS | Performance | — |
| TS-6 | Auth interceptor: logout endpoint excluded from reactive-401 refresh loop | Unit (interceptor spec) | — |

---

*Gate 1: review open questions Q-1 through Q-3 and assumptions A-1 through A-6 before proceeding
to impact analysis.*
