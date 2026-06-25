# US-004 Requirements — Refresh sessions silently with rotating refresh tokens

Status: DRAFT — awaiting Gate 1 approval  
Source: `story/1-authentication/EPIC-001.md` (US-004)  
Date: 2026-06-23

---

## 1. Story

**As an authenticated user,**  
I want my session renewed automatically before expiry,  
So that I stay logged in securely without re-entering credentials.

---

## 2. Discovery — Reuse survey

### What is already built (US-003, merged to `main`)

| Component | Location | Status |
|-----------|----------|--------|
| `RefreshToken` entity with `@Version` optimistic lock + `revoke()` | `identity/domain/RefreshToken.java` | ✅ Live |
| `RefreshTokenPort` — `save`, `findByTokenHash`, `revokeFamily`, `revokeByUserId` | `identity/application/port/out/RefreshTokenPort.java` | ✅ Live |
| `JpaRefreshTokenAdapter` + `JpaRefreshTokenRepository` | `identity/infrastructure/persistence/` | ✅ Live |
| `RefreshTokenUseCase` — rotation, theft detection, optimistic lock, family revocation, user status re-check | `identity/application/service/RefreshTokenUseCase.java` | ✅ Live |
| `POST /api/v1/auth/refresh` in `LoginController` | `identity/interfaces/rest/LoginController.java` | ✅ Live |
| `SecureEventService.revokeFamily()` — `REFRESH_FAMILY_REVOKED` audit event | `identity/application/service/SecureEventService.java` | ✅ Live |
| `RefreshTokenRotationIT` — 5 IT tests (rotation, reuse, expiry, concurrent, cross-tenant) | `test/.../RefreshTokenRotationIT.java` | ✅ Live |
| `RefreshTokenUseCaseTest` — unit tests | `test/.../RefreshTokenUseCaseTest.java` | ✅ Live |
| `refresh_tokens` table — `family_id`, `revoked_at`, `@Version`, token_hash unique index, family_id index | `V2__identity_schema.sql` | ✅ Live |
| `AuthService.refresh()` — POST /auth/refresh with cookies | `features/auth/auth.service.ts` | ✅ Live |
| `auth.interceptor.ts` — **reactive** 401 → refresh → retry, thundering-herd guard (`refreshInFlight`) | `core/http/auth.interceptor.ts` | ✅ Live |
| `AuthStore.expiresAt` — millisecond timestamp from `expiresIn * 1000 + Date.now()` | `core/auth/auth.store.ts` | ✅ Live |

### What is NOT yet built (genuine US-004 delta)

| Gap | AC | Detail |
|-----|----|--------|
| **Proactive refresh scheduler** | AC 4 | The interceptor currently only handles 401 responses reactively. AC 4 requires refresh when `< 2 min TTL` — before the token expires, not after rejection. `AuthStore.expiresAt` is available as the timing basis. |
| **Unit tests for proactive scheduler** | AC 4 | Timer-based scheduler or pre-request TTL check; Vitest tests with fake timers. |
| **E2E test scenario** | TS-1 | "Idle 20 min, then act → action succeeds, no login prompt" requires the proactive path. |
| **Load-test plan doc** | TS-5 | 200 RPS refresh, p95 < 150ms (analogous to US-003 load-test-plan.md). |
| **`idx_refresh_tokens_expires_at` index** | Perf | US-003 design reserved V4 slot for this index; AC perf requirement (p95 < 150ms) may require it. Decision required. |

---

## 3. Acceptance Criteria

> Criteria carried from the story with interpretation and gaps filled.

| # | Criterion | Definition of Done | Priority | Status |
|---|-----------|--------------------|----------|--------|
| AC-1 | Refresh rotates the token | POST /api/v1/auth/refresh with valid refresh token returns new access + new refresh token; old refresh marked revoked in the same transaction | P0 | ✅ **Done (US-003)** |
| AC-2 | Reuse triggers family revocation | Presenting an already-rotated token revokes the entire token family and returns 401 + AUTH_RT_001 (mapped to AUTH_004); user must re-login | P0 | ✅ **Done (US-003)** |
| AC-3 | Concurrent refresh race handled | Two simultaneous refreshes from one client do not falsely revoke the family; grace window ≤ 10s documented | P0 | ✅ **Done (US-003)** — optimistic locking (second request → AUTH_004, not false family revocation) |
| AC-4 | Silent renewal in frontend | Angular proactively refreshes when access token has < 2 min TTL; login screen shown only when refresh fails | P0 | ❌ **TODO (US-004)** |

**Note on AC-3 "grace window":** The optimistic lock approach means the losing concurrent request fails with AUTH_004 (not a family revocation). The "grace window ≤ 10s" wording in the story applies to multi-tab scenarios where both tabs independently detect approaching expiry and race to refresh — the `refreshInFlight$` module guard already prevents the thundering herd within a single tab. Cross-tab grace is not needed because both tabs share the same `HttpOnly` cookie: once one tab succeeds, the other's next attempt will use the rotated cookie. Grace window documentation is required (see §6).

---

## 4. Technical context

### Token TTLs
- Access token: 900 s (15 min), per `nexus.jwt.access-token-ttl-seconds`
- Refresh token: 14 days, per `AuthConstants.AUTH_REFRESH_TOKEN_TTL_DAYS`
- Proactive threshold: < 120 s (2 min) before access token expiry

### Proactive refresh: two viable approaches

**Option A — Timer-based scheduler in AuthService**

`AuthService` sets a `setTimeout` to fire at `expiresAt - 120_000` after each successful login/refresh. On wake, calls `refresh()`. If refresh fails (e.g., user closes browser before timer fires), the timer is a no-op (cancelled on logout/clear).

- Pro: fires exactly once at the right moment; no per-request overhead.
- Con: `setTimeout` is lost on page reload; browser tab sleeping may delay fires. Page reload must fall back to reactive 401 path.
- Implementation: cancel timer on `clearSession()`.

**Option B — Pre-request TTL check in interceptor**

Before forwarding each API request, the interceptor checks `authStore.session()?.expiresAt - Date.now() < 120_000`. If true, calls `authService.refresh()` first (sharing `refreshInFlight$`), then retries the original request with the new token.

- Pro: survives page reload (checks on first request after reload); simpler to test with `HttpTestingController`.
- Con: every API request incurs a signal read; if the user makes a burst of calls while TTL < 2 min, all of them block on one refresh (which is correct but adds latency to the first request).
- Coordination with reactive path: both paths use the same `refreshInFlight$` guard → no double refresh.

**Recommendation: Option B** (pre-request TTL check in the interceptor). It survives page reload naturally, integrates with the existing `refreshInFlight$` guard, and is easier to test with `HttpTestingController`. No timer management or page-visibility API is needed.

### Database schema
No new migrations. V2 `refresh_tokens` has all required columns and indexes. V4 (`idx_refresh_tokens_expires_at`) is reserved but the decision whether to create it is made in the design phase.

### Feature flag
US-004 rides the existing `feature.nexus-us003-auth-login.enabled` flag (confirmed in story: "No — rides auth flag").

---

## 5. Non-functional requirements

| NFR | Target | Source |
|-----|--------|--------|
| Refresh p95 latency | < 150 ms | Story TS-5 |
| Access token expiry safety margin | 120 s | AC-4 |
| Concurrent rotation: max 1 winner | Optimistic lock | AC-3 / V2 `@Version` |
| Audit events | `TOKEN_REFRESH_SUCCESS`, `REFRESH_FAMILY_REVOKED` per refresh | AC (US-003 already emits these) |
| No `localStorage` / `sessionStorage` | In-memory only | IMPL-11 convention |

---

## 6. Open questions

| # | Question | Owner | Impact |
|---|----------|-------|--------|
| Q1 | Should the `idx_refresh_tokens_expires_at` index (reserved in V2/US-003 design) be created in US-004 to support `expires_at < NOW()` cleanup queries, or deferred? | Tech lead / Arch | V4 migration scope |
| Q2 | Cross-tab grace window: AC-3 says "grace window ≤ 10s documented". Should this be a comment in code, an ADR addendum to ADR-0007, or a note in design doc? | Tech lead | Documentation scope |
| Q3 | Proactive refresh approach: Option A (timer) vs Option B (pre-request TTL check)? Recommendation is B (see §4). | Tech lead | IMPL scope |
| Q4 | Should the proactive refresh path emit an explicit `TOKEN_REFRESH_PROACTIVE` audit event distinct from the reactive-401 path, or use the same `TOKEN_REFRESH_SUCCESS` event? | Compliance / Arch | Audit trail clarity |

---

## 7. Out of scope

- Device/session management UI ("active sessions" list) — Epic 7
- Server-sent `exp` claim advance notification
- "Remember me" duration options
- Token revocation on password change (US-007)

---

## 8. Test scenarios

| # | Scenario | Type | Expected result | Status |
|---|----------|------|-----------------|--------|
| TS-1 | Happy path: idle 20 min, then act | E2E | Action succeeds, no login prompt | ❌ TODO |
| TS-2 | Two-tab concurrent refresh | Integration | Both sessions survive (one rotates, other uses same new cookie) | ✅ `concurrent_rotation_single_winner` covers server side; client thundering herd covered by interceptor spec |
| TS-3 | Refresh with revoked family | Unit | 401 AUTH_004 | ✅ `reused_revoked_token_revokes_family` |
| TS-4 | Replay rotated token | Security | Family revoked; all sessions 401 | ✅ `reused_revoked_token_revokes_family` |
| TS-5 | 200 RPS refresh for 10 min | Performance | p95 < 150ms | ❌ Load-test plan doc TODO |

---

## 9. Dependencies

- **Blocked by:** US-003 (now merged ✅)
- **Blocks:** US-005 (logout with refresh revocation)
- **External:** None
