# US-005 Impact Analysis

**Status:** COMPLETE
**Story:** US-005 — Enable logout with refresh token revocation | Epic: EPIC-001 Identity & Access
**Date:** 2026-06-29
**Architect:** Claude (architect)

---

## 1. Confirmed scope (what is / is not changing)

US-005 is overwhelmingly a **test-coverage, wiring, and documentation** story. The production
behaviour (revoke-all-tokens + clear-cookie + 204) was already built and tested under US-003.
No production Java logic changes; no schema changes; no API contract changes.

### Already exists and is complete (verified)

| Element | File | Evidence |
|---|---|---|
| `LogoutUseCase` (`@Service @Transactional`) | `nexus-backend/.../application/service/LogoutUseCase.java` | Full impl — resolves userId from Bearer OR refresh cookie; revokes all tokens; records LOGOUT audit event in one tx |
| `POST /api/v1/auth/logout` | `nexus-backend/.../interfaces/rest/LoginController.java` | Returns 204, clears cookie via `buildRefreshCookie("", 0)`, extracts userId from `SecurityContextHolder` |
| `RefreshTokenPort.revokeByUserId` | `nexus-backend/.../application/port/out/RefreshTokenPort.java` | Port method present |
| Controller unit test (logout) | `nexus-backend/.../interfaces/rest/LoginControllerTest.java` | Asserts 204, `Max-Age=0`, cookie cleared |
| Logout + refresh-after-logout IT | `nexus-backend/.../interfaces/rest/AuthAuditIT.java:202–248` | **SURPRISE** — already covers 204 + LOGOUT audit event + token-less revocation + refresh-after-logout → 401 on Testcontainers MySQL |
| `AuthService.logout()` | `nexus-frontend/src/app/features/auth/auth.service.ts` | POSTs with `withCredentials`, `finalize(() => authStore.clearSession())` |
| `AuthStore.clearSession()` | `nexus-frontend/src/app/core/auth/auth.store.ts` | Sets session signal to null |
| `NxToast` service | `nexus-frontend/src/app/shared/ui/toast/toast.ts` | `success()` / `error()` / `info()` methods |

### Must be created / modified

| Item | File | Type |
|---|---|---|
| `LogoutUseCaseTest` | `nexus-backend/.../application/service/LogoutUseCaseTest.java` | CREATE (confirmed absent) |
| Bearer-path multi-family IT | Extend `AuthAuditIT` OR new `LogoutIT.java` | CREATE (targeted gap only — see §2) |
| `/api/v1/auth/logout` → `AUTH_PATHS` | `nexus-frontend/src/app/core/http/auth.interceptor.ts:14` | MODIFY (1 line) |
| Interceptor logout-path test | `nexus-frontend/src/app/core/http/auth.interceptor.spec.ts` | MODIFY |
| Logout button + handler | `nexus-frontend/src/app/features/dashboard/dashboard.component.ts` | MODIFY |
| `logout.spec.ts` (Playwright) | `nexus-frontend/e2e/auth/logout.spec.ts` | CREATE (confirmed absent) |
| ADR-0008 (jti denylist decision) | `docs/adr/0008-access-token-revocation-jti-denylist.md` | CREATE |

---

## 2. Backend impact

### Layer-by-layer

| Layer | Change | Why | Risk |
|---|---|---|---|
| **domain** | None | `AuthEvent`, `RefreshToken` already model everything needed | None |
| **application** | ADD `LogoutUseCaseTest` only | Use case has 4 behavioural branches untested in isolation | LOW |
| **infrastructure** | None | `revokeByUserId` adapter + index already present | None |
| **interfaces** | None to production code | Controller test already covers logout | None |
| **test** | ADD `LogoutUseCaseTest`; targeted IT gap only (see below) | Coverage gates + branch coverage of cookie-resolution path | LOW |

### `LogoutUseCaseTest` — four branches required

The use case has four behavioural branches, all currently uncovered at unit level:

1. **Bearer path:** `userId` non-null → `revokeByUserId(userId, now)` called; LOGOUT/SUCCESS recorded with userId.
2. **Cookie-only path:** `userId` null + valid cookie → `findByTokenHash` hit → derived userId → `revokeByUserId` called.
3. **Malformed cookie:** `tokenHasher.hash` throws `IllegalArgumentException` → swallowed → no `revokeByUserId`; LOGOUT event still recorded with null userId (graceful degradation).
4. **Unknown cookie:** valid-shape token not in DB → `findByTokenHash` empty → no revoke; LOGOUT event with null userId.

> JaCoCo note: branch 3 above covers the `catch (IllegalArgumentException ignored)` branch, preventing a build gate failure (per the SEC-3 coverage gap pattern).

### `LogoutIT` — scope trim

`AuthAuditIT.java:202–248` already covers:
- `logout_records_audit_event` — 204 + LOGOUT/SUCCESS persisted
- `tokenless_logout_revokes_server_side_refresh_tokens` — 204, then refresh → 401

**Genuine gap:** a Bearer-authenticated logout that revokes tokens across **multiple families** for
the same user. Implement this as a single new `@Test` method inside `AuthAuditIT` rather than a
new `LogoutIT` class — avoids a redundant Testcontainers boot.

---

## 3. Frontend impact

| Area | Change | Why | Risk |
|---|---|---|---|
| `core/http/auth.interceptor.ts` | Add `/api/v1/auth/logout` to `AUTH_PATHS` (line 14) | Without it, an expired-token logout triggers a spurious `POST /refresh` that can re-`setSession`, racing `clearSession` — session resurrection on logout | MED |
| `core/http/auth.interceptor.spec.ts` | Add test: `POST /logout` returning 401 is NOT retried via `/refresh` | Locks the fix; prevents regression | LOW |
| `features/dashboard/dashboard.component.ts` | Add logout button → `AuthService.logout()` → `NxToast.success` → `router.navigate(['/auth/login'])` | The only user-visible feature work | LOW |
| `e2e/auth/logout.spec.ts` | Playwright: login → click logout → assert redirect, toast, session cleared, cookie gone | No e2e proof of full logout flow exists | LOW |

### Dashboard handler contract

```
onLogout(): void  // calls authService.logout().subscribe({ complete/error: toast + navigate })
```

`AuthService.logout()` uses `finalize(clearSession)` — in-memory session is cleared regardless of
server response. The component must navigate + toast on its own `complete`/`error`, not depend on
interceptor side-effects.

---

## 4. Data impact

**No migration required. Verified against `V2__identity_schema.sql`:**

- `refresh_tokens.revoked_at DATETIME(6) NULL` — present. Revocation is a row UPDATE, not a schema change; ADR-0003 append-only constraint applies to migrations only.
- `idx_refresh_tokens_user_id_revoked_at ON refresh_tokens (user_id, revoked_at)` — present. Covering index for `revokeByUserId` (`WHERE user_id = ? AND revoked_at IS NULL`) and for post-logout refresh-token lookup.
- `auth_events` — present with append-only triggers; LOGOUT rows insert correctly. No new `event_type` needed.

No new tables, columns, indexes, or constraints. `ddl-auto=validate` stays green.

---

## 5. API impact

**No changes to the contract.** `POST /api/v1/auth/logout` is final:

| Property | Value |
|---|---|
| Method / path | `POST /api/v1/auth/logout` |
| Auth | Optional Bearer (also works token-less via refresh cookie) |
| Request body | none |
| Cookie in | `refresh_token` (optional) |
| Success | `204 No Content` |
| Set-Cookie out | `refresh_token=; Max-Age=0; HttpOnly; Secure; SameSite=Strict; Path=/api/v1/auth` |
| Error shape | RFC 7807 via `GlobalExceptionHandler` |

No versioning action. No CSRF token (Gate 1 decision: `SameSite=Strict` sufficient).

---

## 6. Documentation / ADR impact

**ADR-0008 — `docs/adr/0008-access-token-revocation-jti-denylist.md` (CREATE).**

Must document the deferred decision (no code deliverable):

1. **Problem:** access tokens remain valid ≤15 min after logout (stateless JWT, per ADR-0007 "no Redis" constraint).
2. **Decision (GA):** accept the residual-validity window. Refresh-token revocation prevents new tokens; existing token expires naturally.
3. **Fast-follow:** Redis-backed **or** DB-backed `revoked_jti` table for sub-TTL revocation. **Flag Redis as new infra** — Nexus has no Redis today; DB-backed alternative avoids the dependency.
4. **Trigger:** compliance requirement for instant revocation would force adoption. Cross-reference ADR-0007 "if revocation SLA is tightened" clause.

---

## 7. Cross-cutting concerns

### Security — `AUTH_PATHS` fix blast radius

Adding `/api/v1/auth/logout` to `AUTH_PATHS` excludes logout from both the **proactive-refresh**
branch and the **reactive-401** branch of the interceptor. The interceptor uses exact `pathname`
comparison (not `includes()`), so blast radius is surgical — only requests whose path is exactly
`/api/v1/auth/logout`. No new attack surface; SameSite=Strict posture unchanged.

**Risk if NOT fixed:** expired-token logout → `POST /refresh` fires → on success, `setSession` is
called before `clearSession` runs → transient session resurrection. On refresh failure the interceptor
calls `clearSession` + navigate anyway, so logout is not blocked — the bug is spurious refresh + race.

### Observability

Sufficient as-is. `LogoutUseCase` records `AuthEvent("LOGOUT","SUCCESS")` with userId + IP into
`auth_events` (append-only, indexed on `event_type, created_at`). Correlation id flows via MDC.
No new metrics or log statements needed.

### Testability

- **Backend unit:** Mockito mocks of `RefreshTokenPort`, `AuthEventPort`, `TokenHasher`, `UuidGenerator`, fixed `Clock` — pure, no Spring context.
- **Backend IT:** Testcontainers MySQL only (never H2 — docs/TESTING.md). New assertion added to `AuthAuditIT`.
- **Frontend unit:** Vitest, mirror existing `auth.interceptor.spec.ts` mock harness.
- **E2E:** Playwright, mirror `e2e/auth/session-refresh.spec.ts` structure.

---

## 8. Risk register

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| R1 | `LogoutIT` duplicates `AuthAuditIT` coverage, adding Testcontainers boot cost for no new assertion | High | Low | Add one `@Test` to `AuthAuditIT` for the Bearer/multi-family gap; no new IT class |
| R2 | `AUTH_PATHS` fix omitted or path string typo'd → spurious refresh / session resurrection on expired-token logout | Medium | Medium | 1-line add + dedicated interceptor spec asserting no `/refresh` on logout 401 |
| R3 | JaCoCo branch gate fails on `catch (IllegalArgumentException ignored)` if malformed-cookie branch untested | Medium | Low | `LogoutUseCaseTest` branch 3 explicitly covers it |
| R4 | Dashboard logout handler depends on interceptor side-effects for navigation/toast | Low | Medium | Component subscribes and navigates on its own `complete`/`error`; `finalize(clearSession)` guarantees state clear |
| R5 | ADR-0008 implies Redis as existing infra | Low | Medium | ADR must flag Redis as new infra and present DB-backed `revoked_jti` alternative |
| R6 | npm install prunes `@emnapi` lockfile entries, breaking Linux CI | Medium | High | Verify `package-lock.json` diff before committing any frontend change; never let `npm install` rewrite the lockfile |
| R7 | E2E logout spec flakiness on toast/redirect timing | Low | Low | Assert on URL + cookie absence (deterministic) before toast visibility |

---

## 9. Dependency map (sequencing)

```
ADR-0008  ─────────────────────────────► (independent; no code dep; needed before design narrative)

Backend track (parallel with frontend):
  LogoutUseCaseTest
  AuthAuditIT (Bearer/multi-family @Test)

Frontend track (ordered):
  auth.interceptor.ts  (add AUTH_PATHS entry)
        │
        ├──► auth.interceptor.spec.ts  (test the exclusion)
        │
  dashboard.component.ts  (logout button + handler)
        │
        └──► e2e/auth/logout.spec.ts   (depends on interceptor fix + dashboard button)
```

**Hard ordering constraints:**
1. Interceptor fix before e2e — logout spec will be flaky without it.
2. Dashboard button before e2e — e2e drives the UI.
3. ADR-0008 before `03-design.md` — design references the revocation-model decision.

**No constraints between backend and frontend tracks** — parallel execution possible.

---

## 10. Backward compatibility

Fully backward compatible. No API contract change, no schema change, no token-format change.
The interceptor change only *removes* an unintended refresh attempt — no observable behaviour
change for clients with a valid access token. No data migration.
