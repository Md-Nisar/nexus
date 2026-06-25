# Impact Analysis — US-004
## Refresh Sessions Silently with Rotating Refresh Tokens

**Status:** DRAFT — awaiting Gate 2  
**Date:** 2026-06-24  
**Author:** Architect Agent  
**Inputs:** `docs/features/US-004/01-requirements.md`, `docs/features/US-003/02-impact.md`,
`docs/features/US-003/03-design.md`, full re-scan of the auth slice in `nexus-backend/` and
`nexus-frontend/src/app/core` + `features/auth`

---

## 1. Scope of Change

US-003 already delivered the **entire backend rotation machinery** and the **reactive (401-driven)
frontend refresh path**. Discovery confirmed that AC-1/2/3 are done and that the only genuine
US-004 delta is **AC-4: proactive, pre-emptive renewal in the Angular client** — refreshing the
access token *before* it expires rather than waiting for a 401.

Concretely, US-004 adds a single **pre-request TTL check** at the top of the existing
`authInterceptor`: before forwarding any non-auth API request, if the current session's
`expiresAt - Date.now()` is under the 120 s threshold, the interceptor runs `authService.refresh()`
through the **already-present `refreshInFlight` thundering-herd guard** and forwards the request
with the freshly minted access token. The reactive 401 path is left untouched as the safety net
for the page-reload / clock-skew / missed-window cases.

The change is **isolated to one production file** (`auth.interceptor.ts`) plus its spec, with one
new planning document (the load-test plan). There are **no backend changes, no DB migrations, no
new endpoints, no new components, no route changes, and no new dependencies**.

The optional `idx_refresh_tokens_expires_at` index (the reserved V4 slot) is explicitly
**deferred** and is not in this sprint's scope.

---

## 2. Files to MODIFY

| File path | Change description | Risk |
|-----------|--------------------|------|
| `nexus-frontend/src/app/core/http/auth.interceptor.ts` | (a) Promote the existing module-level `refreshInFlight` guard so both the proactive and reactive paths share the **same** in-flight observable. (b) Insert a pre-request branch before `return next(authReq)`: read `authStore.session()`, and when the request is **not** an auth endpoint **and** `session.expiresAt - Date.now() < 120_000`, `switchMap` through the shared refresh before forwarding with the rotated token. No change to the `catchError`/401 block. | **Low** — additive branch in one file; reactive path unchanged; reuses the proven `shareReplay(1)` guard |
| `nexus-frontend/src/app/core/http/auth.interceptor.spec.ts` | Add proactive-path tests (see §6). Existing 5 specs unchanged. | **Low** — test-only |

> **Constants reused as-is:** `AUTH_PATHS = ['/api/v1/auth/login', '/api/v1/auth/refresh']`
> already excludes auth endpoints from interceptor logic and **must** gate the proactive branch
> too — otherwise the refresh call would recursively trigger its own TTL check.
> The exact-`pathname` comparison is reused for that exclusion.

> **Threshold source:** `120_000` ms = the 2-min safety margin from AC-4. It should be a named
> module constant (`PROACTIVE_REFRESH_THRESHOLD_MS`) for testability, not a magic number.

---

## 3. Files to CREATE

| File path | Purpose |
|-----------|---------|
| `docs/features/US-004/load-test-plan.md` | k6 load-test plan for the refresh endpoint under proactive-renewal traffic. Target: TS-5 (200 RPS refresh for 10 min, p95 < 150 ms), 0 theft-detection false positives under concurrent rotation, confirmation that proactive client-side renewal does not amplify `POST /refresh` volume beyond the modelled rate. |

> **No new production code files are created.** The proactive logic lives entirely inside the
> existing `auth.interceptor.ts`.

---

## 4. Files UNCHANGED (explicitly confirmed)

### Backend — zero changes

| File path | Why unchanged |
|-----------|---------------|
| `identity/application/service/RefreshTokenUseCase.java` | Full rotation, theft detection, optimistic lock, family revocation, user-status re-check — delivered in US-003 |
| `identity/interfaces/rest/LoginController.java` (`POST /api/v1/auth/refresh`) | Endpoint already wired; the proactive client calls the identical contract |
| `identity/domain/RefreshToken.java`, `RefreshTokenPort.java`, `JpaRefreshTokenAdapter.java`, `JpaRefreshTokenRepository.java` | Persistence/rotation primitives complete |
| `identity/application/service/SecureEventService.java` | `TOKEN_REFRESH_SUCCESS` / `REFRESH_FAMILY_REVOKED` audit events already emitted on every refresh |
| `config/SecurityConfig.java` | `/api/v1/auth/refresh` is already permit-all; no matcher change |
| `db/migration/V2__identity_schema.sql` (`refresh_tokens`) | All columns + indexes present; **no V4 this sprint** |
| `RefreshTokenRotationIT.java`, `RefreshTokenUseCaseTest.java` | 5 IT + unit tests already green; behaviour unchanged |

### Frontend — zero changes

| File path | Why unchanged |
|-----------|---------------|
| `nexus-frontend/src/app/features/auth/auth.service.ts` | `refresh()` already POSTs to `/refresh` (with `withCredentials`), re-fetches `/users/me`, and calls `authStore.setSession()`. The proactive path consumes this method verbatim. |
| `nexus-frontend/src/app/core/auth/auth.store.ts` | `session()` already exposes `expiresAt` (epoch ms); `setSession()`/`clearSession()` reused as-is |
| `nexus-frontend/src/app/shared/types/auth.ts` | `AuthSession.expiresAt: number` already present |
| `nexus-frontend/src/app/app.config.ts` | `authInterceptor` is already registered in `withInterceptors([...])`; no registration change |
| `nexus-frontend/src/app/core/http/correlation-id.interceptor.ts`, `api-error.interceptor.ts` | Refresh/`/users/me` calls keep flowing through the existing pipeline unchanged |

---

## 5. Cross-Cutting Concerns — NONE

| Concern | Status | Note |
|---------|--------|------|
| Backend changes | None | Pure frontend delta |
| Database migrations | None | `refresh_tokens` complete in V2; `idx_refresh_tokens_expires_at` (V4) **deferred** |
| API changes / new endpoints | None | Reuses `POST /api/v1/auth/refresh` and `GET /api/v1/users/me` unchanged |
| JWT claims contract | None | Frozen in US-003; untouched |
| New components / routes / guards | None | No template, route, or `canActivate` change |
| New npm dependencies | None | No `package.json` change |
| Security attack surface | None | No new endpoint; refresh cookie remains `HttpOnly; Secure; SameSite=Strict`; no token written to storage |
| Backward compatibility | Fully compatible | Reactive 401 path preserved; old clients keep working |
| Downstream US-005 (logout) | Not impacted | Depends only on US-003 revocation primitives, unchanged |

---

## 6. Test Impact

| Suite | Effect |
|-------|--------|
| `auth.interceptor.spec.ts` (5 existing) | **Remain green.** All current cases use `expiresAt = Date.now() + 3600*1000`, so the `< 120 s` branch is never entered. |
| `auth.interceptor.spec.ts` (new proactive cases) | Add: **(1)** TTL < 120 s → one `POST /refresh` fires *before* the request, forwarded with new token; **(2)** TTL > 120 s → **no** proactive refresh; **(3)** TTL < 120 s on an auth endpoint → **no** proactive refresh (loop guard); **(4)** burst of N concurrent requests, TTL < 120 s → exactly **one** `POST /refresh` (thundering-herd guard), all N forwarded with new token; **(5)** proactive refresh fails → `clearSession()` + navigate to `/auth/login`. Use controlled `Date.now()` to pin `expiresAt`; assert ordering via `HttpTestingController`. |
| Backend `*IT` suite | **Unaffected** — no backend file changes |
| E2E (TS-1) | "Idle 20 min, then act → action succeeds, no login prompt" becomes satisfiable once the proactive path exists |
| Coverage gates | Frontend Vitest coverage stays above threshold; the new branch is small and fully covered by the 5 new cases above |

---

## 7. Risk Assessment — LOW

| # | Risk | Severity | Mitigation |
|---|------|----------|------------|
| 1 | Proactive branch fires on auth endpoints → recursive refresh | Low | `AUTH_PATHS` exact-`pathname` exclusion gates the proactive branch (identical to the reactive guard); covered by test case (3) |
| 2 | Concurrent requests under low TTL → multiple `POST /refresh` → server theft detection | Low | The **existing** `refreshInFlight` + `shareReplay(1)` guard serialises concurrent refreshes; proactive and reactive paths share the same guard; covered by test case (4) |
| 3 | TTL check adds per-request overhead | Negligible | One signal read + one arithmetic comparison per request; O(1), no I/O |
| 4 | Reactive 401 path regresses | Low | The `catchError`/401 block is **not modified**; the 5 existing specs lock its behaviour |
| 5 | Clock skew / suspended tab causes the window to be missed | Low (by design) | The reactive 401 path remains the safety net; a missed proactive window still yields a transparent 401 → refresh → retry |

**Overall: Low.** No backend changes, no schema changes, no new dependencies; the delta is one
additive branch in a single, well-tested frontend file, reusing proven guards and the unchanged
server contract.

---

## 8. Out of Scope

- `idx_refresh_tokens_expires_at` (V4) — reserved, **deferred** (only needed for a future cleanup sweep, not the rotation path)
- A distinct `TOKEN_REFRESH_PROACTIVE` audit event — the server cannot distinguish proactive from reactive calls; both emit the existing `TOKEN_REFRESH_SUCCESS` (requirements Q4)
- `auth.service.ts`, `auth.store.ts`, `auth.ts`, `app.config.ts` — no changes
- Device/session-management UI, server-sent `exp` notification, "remember me", token revocation on password change (US-007), logout (US-005)
