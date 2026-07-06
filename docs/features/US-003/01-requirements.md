# Requirements & Discovery — US-003
## Authenticate Users via Login Issuing JWT Access and Refresh Tokens

**Status:** APPROVED — Gate 1 passed 2026-06-21  
**Date:** 2026-06-21  
**Author:** Business Analyst (Claude Code)  
**Inputs:** `docs/story/1-authentication/US-003.md`, `docs/features/US-002/01-requirements.md`,
`docs/ARCHITECTURE.md`, `SECURITY.md`, `docs/observability-standards.md`,
`docs/deployment-process.md`, all ADRs 0001–0006, codebase survey (US-001 + US-002 merged state)

---

## 1. Problem Statement

US-003 delivers the login flow: a registered, email-verified user submits `email + password`; the
server validates credentials against the stored Argon2id hash, issues an **RS256 access JWT**
(15-minute TTL) and a **refresh token** (14-day TTL, httpOnly Secure SameSite cookie), and
persists a `refresh_tokens` row per session. The access token carries the **frozen claims
contract** (`sub`, `tenant_id`, `email_verified`, `roles[]`, `iat`, `exp`, `jti`,
`token_version`) that every downstream feature will depend on; the contract freezes at end of
Sprint 2 and is protected by a JSON schema contract test in CI.

**Bounded context:** `com.example.nexus.identity` (established US-001; extended US-002).  
No new bounded context is required.

**Explicit non-goals:**
- MFA challenge step
- SSO / OAuth2 / OIDC redirect flows
- "Remember me" duration options
- Logout (US-005+)
- Password reset (US-007+)
- Account lockout from failed login attempts (US-006+; the `failed_attempt_count` / `locked_until`
  columns are already in the schema but the business logic is out of scope here)

---

## 2. Reuse-First Survey

### What US-001 / US-002 built that US-003 consumes directly

| Artifact | Location | Reuse Plan |
|----------|----------|------------|
| `User` entity — `passwordHash`, `status`, `tokenVersion`, `emailHmac`, `tenantId`, `lockedUntil`, `failedAttemptCount`, `emailVerifiedAt` | `identity.domain.User` | Lookup by `(tenantId, emailHmac)` + credential check; `status=ACTIVE` gate |
| `RefreshToken` entity — `id`, `userId`, `tokenHash`, `familyId`, `expiresAt`, `revokedAt` | `identity.domain.RefreshToken` | Fully defined by US-001; just needs a `revoke()` method and a persistence port |
| `AuthEvent` entity — append-only audit trail | `identity.domain.AuthEvent` | New event types: `LOGIN_SUCCESS`, `LOGIN_FAILURE`, `LOGIN_PENDING_ACCOUNT` |
| `UserRegistrationPort` — `findByTenantAndEmailHmac()`, `findById()`, `save()` | `identity.application.port.out` | Reuse for user lookup; login does not write `users` rows so no new write method needed |
| `AuthEventPort.record()` | `identity.application.port.out` | Unchanged; new event types plug in without modification |
| `PasswordHasherPort` (`Argon2PasswordEncoder::encode`) | `identity.application.port.out` | Reuse `Argon2PasswordEncoder`; **also need `matches()`** — a new `PasswordVerifierPort` (or a second method on the existing port) is required |
| `EmailBlindIndexService.blindIndex()` | `identity.application` | Blind-index the supplied email for the DB lookup |
| `TokenGenerator.generate()` | `identity.application` | Generate the raw refresh token (32-byte random hex) |
| `TokenHasher.hash()` | `identity.application` | SHA-256 the refresh token before storage |
| `GlobalExceptionHandler` + `DomainException` hierarchy | `common.web` + `common.domain` | New `AuthenticationException` (→ 401 AUTH_001) and `AccountNotVerifiedException` (→ 403 AUTH_002) plug in with no handler changes needed; just new subclasses |
| `CorrelationIdFilter` + `RequestContext` | `common.web` + `common.domain` | IP + traceId enrichment of audit events; unchanged |
| `SecurityConfig` (stateless, default-deny, CORS, HSTS) | `config` | Replace HTTP Basic placeholder with JWT Bearer; add permit-all rules for `/api/v1/auth/login`, `/.well-known/jwks.json` |
| `RegistrationController` route prefix `/api/v1/auth` | `identity.interfaces.rest` | New `LoginController` shares the same prefix |
| `AuthService` (Angular) | `features/auth/auth.service.ts` | Extend with `login()`, `refresh()` |
| `auth.routes.ts` | `features/auth/auth.routes.ts` | Add `/auth/login` lazy route |
| `app.routes.ts` | root | `auth/` feature shell already wired; no change |
| `correlationIdInterceptor` | `core/http` | Unchanged |
| `apiErrorInterceptor` | `core/http` | Unchanged |
| `shared/ui` components (NxInput, NxButton, NxCard, NxToast) | `shared/ui` | LoginFormComponent built on these |
| `refresh_tokens` table (V2 migration) | DB | Fully defined; next migration is **V4** |
| `users` table — `password_hash` column (V3 migration) | DB | Ready for login credential check |

### What US-003 must create (nothing equivalent exists)

| Layer | New Artifact | Notes |
|-------|-------------|-------|
| **Domain** | `RefreshToken.revoke(Instant revokedAt)` | Domain method to mark revocation; currently no setter/method |
| **Domain** | Update `AuthConstants.AUTH_REFRESH_TOKEN_TTL_DAYS` from 7 → 14 | Story AC-1 says 14 days; constant currently says 7; must align before first use |
| **Application port** | `RefreshTokenPort` | Outbound port: `save()`, `findByTokenHash()`, `revokeFamily()`, `revokeByUserId()` |
| **Application port** | `PasswordVerifierPort` | `matches(rawPassword, encodedHash) → boolean`; adapter delegates to `Argon2PasswordEncoder.matches()` |
| **Application port** | `JwtPort` | `issue(User) → AccessTokenResult`, `verify(rawJwt) → Claims`; adapter uses JJWT or Spring Security OAuth2 JWT |
| **Application port** | `JwkSetPort` | `getPublicKeySet() → JwkSet`; serves the public key(s) for the JWKS endpoint |
| **Application** | `LoginUseCase` | Orchestrates: lookup → verify status → verify password → issue tokens → persist refresh token → audit |
| **Application** | `RefreshTokenUseCase` | Rotate refresh token (one-time use); revoke old; issue new pair |
| **Infrastructure** | `JpaRefreshTokenRepository` | Spring Data JPA for `refresh_tokens` |
| **Infrastructure** | `JpaRefreshTokenAdapter` implements `RefreshTokenPort` | |
| **Infrastructure** | `JwtRs256Service` implements `JwtPort` | RS256 sign/verify; key from configured RSA key pair |
| **Infrastructure** | `RsaKeyConfig` | Load RS256 private key (from env var PEM or generated dev key) |
| **Infrastructure** | `JwkSetAdapter` implements `JwkSetPort` | Builds RFC 7517 JWK Set from the active public key |
| **Infrastructure** | `JwtAuthenticationFilter` | Spring Security `OncePerRequestFilter`; extracts Bearer token, validates, sets `SecurityContextHolder` |
| **Infrastructure** | Rate-limiting filter for login | 5 attempts / 5-min window, per IP **and** per username; backed by `RateLimitStore` abstraction (in-memory default; Redis adapter added when `nexus.security.rate-limit.store-type=redis`) |
| **Infrastructure** | `PasswordVerifierAdapter` implements `PasswordVerifierPort` | Delegates to `Argon2PasswordEncoder.matches()` |
| **Interfaces** | `LoginController` | `POST /api/v1/auth/login`, `POST /api/v1/auth/refresh` |
| **Interfaces** | `JwksController` | `GET /.well-known/jwks.json` (public, no auth) |
| **Interfaces** | `UserProfileController` | `GET /api/v1/users/me` (authenticated); minimal: echoes JWT claims |
| **Interfaces** | DTOs | `LoginRequest`, `LoginResponse` (access token only in body; refresh token via Set-Cookie), `RefreshRequest` (empty body; reads httpOnly cookie), `MeResponse` |
| **Security** | `SecurityConfig` overhaul | Replace `httpBasic()` with `oauth2ResourceServer().jwt()` or custom filter; add JWT permit-all rules; expose CORS for `/api/**` and `/.well-known/**` |
| **DB** | V4 migration | `CREATE INDEX idx_refresh_tokens_token_hash ON refresh_tokens(token_hash)` if not already covered by UNIQUE constraint; confirm expiry/cleanup strategy |
| **Config** | Feature flag `feature.nexus-us003-auth-login.enabled` | `@ConditionalOnProperty` on new controllers |
| **Frontend** | `LoginFormComponent` (smart) | email + password form; signal state; error display |
| **Frontend** | `AuthInterceptor` | Attaches `Authorization: Bearer <access_token>` from in-memory signal; on 401 triggers refresh then retries once |
| **Frontend** | `AuthGuard` | `canActivate` protecting authenticated routes |
| **Frontend** | `AuthStore` (signal-based state) | Holds access token in memory; never in `localStorage`; clears on logout/expiry |
| **Frontend** | `auth.routes.ts` | Add `/auth/login` child route |
| **Frontend** | `AuthService` extensions | `login()`, `refresh()`, `logout()` |
| **Config (backend)** | RS256 key configuration | `NEXUS_JWT_PRIVATE_KEY_PEM` env var; dev profile generates an ephemeral key at startup |

### ADRs applicable (no new ADRs required; existing cover all decisions)

| ADR | Implication for US-003 |
|-----|------------------------|
| ADR-0002 Hexagonal | `LoginUseCase` in application; JWT infra in infrastructure; no cross-layer leakage |
| ADR-0003 Flyway | V4 migration must be additive; no edits to V1–V3 |
| ADR-0005 UUIDv7 | Inject `UuidGenerator` for `RefreshToken.id` and `familyId`; never call from entity |
| ADR-0006 Email blind index | Login lookup via `EmailBlindIndexService.blindIndex()` — same normalisation path as registration |

---

## 3. Impact Map

### Backend layers

| Layer | Changes |
|-------|---------|
| **Domain** | Add `RefreshToken.revoke()` method; update `AuthConstants.AUTH_REFRESH_TOKEN_TTL_DAYS`; no new entities |
| **Application** | Two new use-case services (`LoginUseCase`, `RefreshTokenUseCase`); four new outbound ports (`RefreshTokenPort`, `PasswordVerifierPort`, `JwtPort`, `JwkSetPort`) |
| **Infrastructure** | `JpaRefreshTokenRepository` + adapter; `JwtRs256Service`; `RsaKeyConfig`; `JwkSetAdapter`; `JwtAuthenticationFilter`; `PasswordVerifierAdapter`; rate-limiting filter; `SecurityConfig` overhaul |
| **Interfaces** | `LoginController` (2 endpoints); `JwksController` (1 endpoint); `UserProfileController` (1 endpoint); 4 DTO classes |

### Database

| Change | Migration | Risk |
|--------|-----------|------|
| Confirm `refresh_tokens.token_hash` UNIQUE index covers lookup (V2 already has `uq_refresh_tokens_token_hash`) | — | None; already indexed |
| Add `idx_refresh_tokens_expires_at` for token-cleanup queries | V4 (additive) | Low |
| No new tables; `refresh_tokens` fully defined in V2 | — | — |

### Frontend

| Area | Change |
|------|--------|
| `features/auth/login-form/` | New smart component |
| `core/http/auth.interceptor.ts` | New interceptor (bearer token + refresh-on-401) |
| `core/auth/auth.store.ts` | New signal-based token store |
| `core/auth/auth.guard.ts` | New route guard |
| `features/auth/auth.service.ts` | Add `login()`, `refresh()`, `logout()` |
| `features/auth/auth.routes.ts` | Add login lazy route |

### API — new / changed endpoints

| Endpoint | Method | Auth | Notes |
|----------|--------|------|-------|
| `/api/v1/auth/login` | POST | Public | Issues access token (body) + refresh token (Set-Cookie) |
| `/api/v1/auth/refresh` | POST | Public (reads cookie) | Rotates refresh token |
| `/.well-known/jwks.json` | GET | Public | Active public key set |
| `/api/v1/users/me` | GET | Bearer JWT | Echoes caller's JWT claims |

### Cross-context effects

- `SecurityConfig` is in `config` package (not `identity`) — changes there affect all bounded contexts.
- `JwtAuthenticationFilter` populates `SecurityContextHolder` — every other future endpoint relies on this.
- The **claims contract** (`sub`, `tenant_id`, `email_verified`, `roles[]`, `iat`, `exp`, `jti`, `token_version`) freezes at Sprint 2 end; a JSON schema contract test in CI enforces it. **Adding a new claim after the freeze requires a major version bump and stakeholder sign-off.**
- US-004, US-005, US-006, US-008 and all subsequent features are blocked until this story is merged and green.

---

## 4. Non-Functional & Risk

### Security

| Concern | Detail |
|---------|--------|
| RS256 algorithm | Asymmetric signing; private key signs, public key verifies. `alg=none` and symmetric algorithms (HS256) must be rejected at the filter level (see Test Scenario 4) |
| Access token storage | In memory only (Angular signal/store); **never** `localStorage` or `sessionStorage` |
| Refresh token storage | `HttpOnly; Secure; SameSite=Strict` cookie — never returned in JSON body; never logged |
| Anti-enumeration | Wrong password and unknown email must return the same `401 AUTH_001` with the same user-facing message; response-time delta < 50 ms — constant-time comparison via Argon2 inherent timing; unknown email must still run a constant-time dummy hash |
| PENDING account | Returns `403 AUTH_002` with `resend-verification` action; must not run Argon2 (short-circuit is acceptable here since a different error code is exposed) |
| Rate limiting | **5 attempts / 5-min window per IP AND per username** (SECURITY.md rule; overrides story's 10/min). Implemented via a `RateLimitStore` interface: `InMemoryRateLimitStore` (default, Sprint 2) and `RedisRateLimitStore` (future). Storage type is config-driven: `nexus.security.rate-limit.store-type=memory\|redis`. On limit hit: `429 RATE_LIMIT_EXCEEDED`. |
| `jti` uniqueness | Use UUIDv7 as `jti`; store in `refresh_tokens.id` for revocation check (access token `jti` is not persisted — short TTL makes it acceptable; refresh token `jti` IS persisted) |
| Refresh token rotation | One-time use: upon `POST /refresh`, revoke old token, issue new pair, persist new refresh token. On reuse detection (already-revoked token presented), revoke entire family |
| Key material | Private key from `${NEXUS_JWT_PRIVATE_KEY_PEM}` (prod); dev profile generates ephemeral RSA-2048 key at startup so local runs need no secret |
| `tenant_id` in JWT | Comes from `User.tenantId` — never from request body or path (per SECURITY.md §3) |
| Token version | `User.tokenVersion` embedded in access token; a future forced-logout story can bump the version to invalidate all in-flight tokens |

### Performance

- Argon2id hash check at login: ~100–500 ms. Same thread-pool sizing concern as registration (AC-1 says p95 < 300 ms — tighter than registration's 500 ms budget).
- 100 RPS sustained 10 min (QA scenario 5). With Argon2id at ~200 ms, 100 RPS needs ~20 threads at minimum. Virtual threads (already configured) handle this.
- Unknown-email path must still run a dummy Argon2 hash to maintain constant timing — this is the same CPU cost as the happy path.
- JWKS endpoint: effectively static; should be cached with short `Cache-Control: max-age` (60s) — no DB hit on each request.

### Observability

| Signal | Detail |
|--------|--------|
| `auth_events` rows | `LOGIN_SUCCESS`, `LOGIN_FAILURE`, `LOGIN_PENDING_ACCOUNT`, `TOKEN_REFRESH_SUCCESS`, `TOKEN_REFRESH_FAILURE` |
| Micrometer counters | `nexus_auth_login_requests_total{status}`, `nexus_auth_refresh_requests_total{status}` |
| Micrometer histogram | `nexus_auth_login_duration_seconds` (covers Argon2 verify time); alert if p95 > 300 ms |
| MDC | `userId`, `tenantId` added to MDC after successful authentication |
| INFO log | `LOGIN_SUCCESS userId=xxx tenantId=xxx email=u***@example.com` |
| WARN log | `LOGIN_FAILURE email=u***@example.com ip=1.2.3.4 reason=INVALID_CREDENTIALS` |

### Feature flag

Flag name: `feature.nexus-us003-auth-login.enabled`  
Mechanism: `@ConditionalOnProperty` on `LoginController`, `JwksController`, `UserProfileController`  
Default: `false` in `application.yml`; `true` in `application-dev.yml`  
Note: `JwtAuthenticationFilter` must be active regardless of the flag (it only validates tokens; when the flag is off, no token is issued, so it is harmlessly a no-op on all routes).

---

## 5. Open Questions — Resolved at Gate 1 (2026-06-21)

All questions below were resolved with explicit approval. Decisions are binding for design and implementation.

| # | Question | **Decision** |
|---|----------|-------------|
| Q1 | Refresh token TTL: `AuthConstants` says 7 days; story says 14 days | ✅ **14 days** — story is canonical; update `AuthConstants.AUTH_REFRESH_TOKEN_TTL_DAYS` to 14 |
| Q2 | RS256 key in dev: ephemeral vs required env var | ✅ **Ephemeral in dev/test** — `RsaKeyConfig` auto-generates RSA-2048 `KeyPair` when `NEXUS_JWT_PRIVATE_KEY_PEM` absent and profile is `dev` or `test`; prod fails fast if env var missing |
| Q3 | Rate-limit rule and storage | ✅ **SECURITY.md rule: 5/5-min per IP + per username**. Use a `RateLimitStore` interface: `InMemoryRateLimitStore` (default; Sprint 2) and `RedisRateLimitStore` (future). Switched via `nexus.security.rate-limit.store-type=memory\|redis` — zero code change needed to migrate to Redis |
| Q4 | `roles[]` claim value | ✅ **Hardcoded `["USER"]`** for all ACTIVE users; documented in contract test; separate `user_roles` table deferred |
| Q5 | `/refresh` request shape | ✅ **Cookie-only** for Sprint 2; mobile body-field variant deferred |
| Q6 | `/users/me` scope | ✅ **Claims echo only** — re-serialises JWT fields (`sub`, `tenant_id`, `email_verified`, `roles[]`, `token_version`); decrypted email/profile deferred |
| Q7 | Key rotation in Sprint 2 | ✅ **Single key + `kid` field from day 1**; multi-key rotation mechanism deferred; contract documented in `03-design.md` |
| Q8 | V4 migration | ✅ **No V4 for US-003** unless design phase uncovers a gap; V4 slot reserved for next schema story |

---

## 6. Acceptance Criteria Mapping

| AC# | Criterion | Backend note | Frontend note |
|-----|-----------|-------------|---------------|
| AC-1 | Valid credentials → 200 + RS256 access token (15 min) + httpOnly refresh cookie (14 days); p95 < 300 ms | `LoginUseCase`; `JwtPort.issue()`; `Set-Cookie` on response | Form submit → access token stored in `AuthStore`; redirect to dashboard |
| AC-2 | Access token claims match frozen contract | `JwtRs256Service` includes all 8 claims; JSON schema contract test in CI | Optionally decode and display `email_verified`, `roles` |
| AC-3 | Wrong password + unknown email → same 401 AUTH_001; delta < 50 ms | Unknown email still runs dummy Argon2; same response body | Show "Invalid email or password" message |
| AC-4 | PENDING account → 403 AUTH_002 + resend action | `LoginUseCase` checks `status == PENDING` before password check | Show prompt to check email + resend link |
| AC-5 | JWKS endpoint publishes active public key | `JwksController` returns `{ keys: [{kid, kty, alg, n, e}] }`; `kid` present for future rotation | — |
| AC-6 | Protected routes enforce JWT | `JwtAuthenticationFilter`; SecurityConfig default-deny; tampered/expired → 401 | `AuthGuard` redirects unauthenticated users to `/auth/login` |

---

## 7. Test Scenarios (preview for Phase 4)

| # | Scenario | Type |
|---|----------|------|
| 1 | Happy path: login → GET /api/v1/users/me → claims echoed | E2E (Playwright) |
| 2 | Same email, two different tenants → each gets correct tenant context in JWT | Integration |
| 3 | PENDING account login → 403 + resend action | Integration |
| 4 | Security: `alg=none`, modified `tenant_id`, expired token, wrong-key signature → all 401 | Security / Unit |
| 5 | Unknown email → 401 (same message as wrong password; timing delta < 50 ms) | Unit + Security |
| 6 | Refresh token rotation: use once → new pair; reuse revoked token → revoke family | Integration |
| 7 | JWKS endpoint: GET `/.well-known/jwks.json` → 200, `kid` present | Unit |
| 8 | JWT filter: missing token → 401; valid token → 200 on protected route | Unit |
| 9 | Claims schema contract test: parse access token → validate against JSON schema | Contract (CI) |
| 10 | Load: 100 RPS sustained 10 min, p95 < 300 ms | Performance |

---

## 8. Dependencies & Constraints

| Item | Status |
|------|--------|
| US-001 merged & green | ✅ Done |
| US-002 merged & green | ✅ Done (cbd9fb0) |
| `refresh_tokens` table in schema | ✅ Already in V2 migration |
| `users.password_hash` column | ✅ Already in V3 migration |
| `users.token_version` column | ✅ Already in V2 migration |
| `users.status` ENUM includes ACTIVE/PENDING | ✅ Already in V2 migration |
| Argon2id encoder bean configured | ✅ `PasswordEncoderConfig` present; `.matches()` method available |
| RS256 private key infrastructure | ❌ Not in stack — open question Q2 |
| Redis (rate-limit store) | ℹ️ Not in Docker Compose — in-memory default used for Sprint 2; Redis adapter added when `nexus.security.rate-limit.store-type=redis` (no code change, config only) |
| JWT library (`jjwt` or Spring Security OAuth2 JWT) | ❌ Not in `pom.xml` — must add in design phase |
| `UserRegistrationPort` — no `findByEmailHmac` returning decrypted email | ⚠️ Login needs `findByTenantAndEmailHmac()` only — already present; no gap |
| US-004, US-005, US-006, US-008 | ❌ All blocked on this story |
