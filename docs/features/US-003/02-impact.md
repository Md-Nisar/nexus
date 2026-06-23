# Impact Analysis — US-003
## Authenticate Users via Login Issuing JWT Access and Refresh Tokens

**Status:** DRAFT — awaiting Gate 2
**Date:** 2026-06-21
**Author:** Architect (Claude Code)

---

## 1. Scope of Change

US-003 adds the login flow to the existing `com.example.nexus.identity` bounded context (no new
context). It consumes the already-merged identity data model from US-001/US-002 — `users`,
`refresh_tokens`, and `auth_events` tables, the `User`/`RefreshToken` entities,
`EmailBlindIndexService`, `TokenGenerator`/`TokenHasher`, the Argon2 encoder, and the RFC 7807
error stack — and layers on top of it: RS256 JWT issuance/verification (a brand-new capability
not present in the stack), a stateful refresh-token persistence/rotation path, a JWKS endpoint, a
`/users/me` claims-echo endpoint, a `JwtAuthenticationFilter` that populates
`SecurityContextHolder` for every future endpoint, an IP+username rate limiter behind a
`RateLimitStore` abstraction, and the corresponding Angular login form, auth store, bearer
interceptor, and route guard. The two highest-blast-radius touchpoints are the `SecurityConfig`
overhaul (in the shared `config` package — affects all contexts) and the **frozen JWT claims
contract** that every downstream story (US-004/005/006/008) will depend on.

---

## 2. Backend Impact

### 2.1 Files to MODIFY (existing files that change)

| File path | Layer | Change description | Risk |
|-----------|-------|--------------------|------|
| `identity/domain/AuthConstants.java` | Domain | `AUTH_REFRESH_TOKEN_TTL_DAYS` 7 → 14 (Gate-1 Q1). Trivial but load-bearing for cookie Max-Age + DB `expires_at` | Low |
| `identity/domain/RefreshToken.java` | Domain | Add `revoke(Instant revokedAt)` domain method (sets `revokedAt`); no new fields | Low |
| `config/SecurityConfig.java` | Config (cross-cutting) | Remove `.httpBasic()`; register `JwtAuthenticationFilter` before `UsernamePasswordAuthenticationFilter`; add permit-all for `/api/v1/auth/login`, `/api/v1/auth/refresh`, `/.well-known/jwks.json`; keep default-deny `anyRequest().authenticated()`; extend CORS to `/.well-known/**` and expose `Set-Cookie` | **High** — affects every context; mis-rule = open or locked-out API |
| `src/main/resources/application.yml` | Config | Add `feature.nexus-us003-auth-login.enabled` (default false), `nexus.security.jwt.*` (issuer, kid, access TTL, private-key PEM env), `nexus.security.rate-limit.*` (store-type=memory, window, max-attempts) | Medium — secret wiring; prod fail-fast |
| `src/main/resources/application-dev.yml` | Config | Set flag `true`; allow ephemeral RSA key when `NEXUS_JWT_PRIVATE_KEY_PEM` absent | Low |
| `src/test/resources/application-test.yml` | Config | Set flag `true`; ephemeral key for `*IT` suites | Low |
| `pom.xml` | Build | Add JWT/JOSE library (see §2.3) | Medium — supply-chain + CVE surface |

> Note: `GlobalExceptionHandler`, `AuthEventPort`, `UserRegistrationPort`, `RequestContext`,
> `CorrelationIdFilter`, and `RateLimitException` need **no changes** — new exception subclasses
> and event types plug in through existing extension points. The existing
> `@ExceptionHandler(RateLimitException.class)` already emits `429 + Retry-After`, so the full
> 429 path is reused at no cost.

### 2.2 Files to CREATE (net new)

#### Domain / Common

| File path | Layer | Purpose |
|-----------|-------|---------|
| `common/domain/AuthenticationException.java` | Common domain | extends `DomainException`, code `AUTH_001` → 401; needs new handler entry in `GlobalExceptionHandler` |
| `common/domain/AccountNotVerifiedException.java` | Common domain | code `AUTH_002` → 403; PENDING-account path |
| `identity/domain/AccessTokenResult.java` | Domain | Value object wrapping raw JWT string + `expiresIn` |

#### Application Ports

| File path | Layer | Purpose |
|-----------|-------|---------|
| `identity/application/port/out/RefreshTokenPort.java` | Application port | `save()`, `findByTokenHash()`, `revokeFamily(UUID familyId, Instant)`, `revokeByUserId(UUID userId, Instant)` |
| `identity/application/port/out/PasswordVerifierPort.java` | Application port | `matches(rawPassword, encodedHash) → boolean` |
| `identity/application/port/out/JwtPort.java` | Application port | `issue(User) → AccessTokenResult`, `verify(rawJwt) → JwtClaims` |
| `identity/application/port/out/JwkSetPort.java` | Application port | `getPublicKeySet() → JwkSet` (RFC 7517) |
| `identity/application/port/out/RateLimitStore.java` | Application port | `tryConsume(key, windowSeconds, maxAttempts) → RateLimitResult`; extensibility seam for Sprint-2 (memory) vs future (Redis) |

#### Application Use-Cases

| File path | Layer | Purpose |
|-----------|-------|---------|
| `identity/application/LoginUseCase.java` | Application | lookup → status gate → password verify (constant-time dummy on unknown email) → issue tokens → persist refresh token → audit; `@Transactional` |
| `identity/application/RefreshTokenUseCase.java` | Application | one-time rotation; revoke old; issue new pair; revoke-family on reuse detection; `@Transactional` |

#### Infrastructure

| File path | Layer | Purpose |
|-----------|-------|---------|
| `identity/infrastructure/persistence/JpaRefreshTokenRepository.java` | Infrastructure | Spring Data JPA for `refresh_tokens` |
| `identity/infrastructure/persistence/JpaRefreshTokenAdapter.java` | Infrastructure | implements `RefreshTokenPort` |
| `identity/infrastructure/security/JwtRs256Service.java` | Infrastructure | implements `JwtPort`; RS256 sign/verify; rejects `alg=none` and HS256 |
| `identity/infrastructure/security/RsaKeyConfig.java` | Infrastructure | Loads PEM from env in prod; generates ephemeral RSA-2048 in dev/test; exposes `kid` deterministically |
| `identity/infrastructure/security/JwkSetAdapter.java` | Infrastructure | implements `JwkSetPort`; builds RFC 7517 JWK Set from active public key |
| `identity/infrastructure/security/JwtAuthenticationFilter.java` | Infrastructure | `OncePerRequestFilter`; extracts Bearer, verifies, populates `SecurityContextHolder`; no-op when no token present |
| `identity/infrastructure/security/PasswordVerifierAdapter.java` | Infrastructure | implements `PasswordVerifierPort` via `Argon2PasswordEncoder.matches()` |
| `identity/infrastructure/security/InMemoryRateLimitStore.java` | Infrastructure | default `RateLimitStore` implementation (Sprint 2); `ConcurrentHashMap`-backed; expiry via sliding window |
| `identity/infrastructure/security/LoginRateLimitFilter.java` | Infrastructure | `OncePerRequestFilter` on login route; enforces 5/5-min per IP **and** per username via `RateLimitStore`; throws `RateLimitException` on limit |

#### Interfaces

| File path | Layer | Purpose |
|-----------|-------|---------|
| `identity/interfaces/rest/LoginController.java` | Interfaces | `POST /api/v1/auth/login`, `POST /api/v1/auth/refresh`; `@ConditionalOnProperty` |
| `identity/interfaces/rest/JwksController.java` | Interfaces | `GET /.well-known/jwks.json`; `Cache-Control: max-age=60` |
| `identity/interfaces/rest/UserProfileController.java` | Interfaces | `GET /api/v1/users/me`; echoes JWT claims; `@ConditionalOnProperty` |
| `identity/interfaces/rest/dto/LoginRequest.java` | DTO | `email`, `password` (Bean Validation) |
| `identity/interfaces/rest/dto/LoginResponse.java` | DTO | `accessToken`, `tokenType`, `expiresIn`; refresh token in `Set-Cookie` header only |
| `identity/interfaces/rest/dto/RefreshRequest.java` | DTO | empty body; refresh token read from httpOnly cookie |
| `identity/interfaces/rest/dto/MeResponse.java` | DTO | `sub`, `tenantId`, `emailVerified`, `roles`, `tokenVersion` |

#### Tests (mirroring existing `*IT` and unit conventions)

`LoginUseCaseTest`, `RefreshTokenUseCaseTest`, `JwtRs256ServiceTest` (alg=none / HS256 / expired
/ wrong-key rejection), `LoginControllerIT`, `JwksControllerIT`, `UserProfileControllerIT`,
`RefreshTokenRotationIT`, `LoginRateLimitIT`, and a **claims JSON-schema contract test** (CI gate,
test scenario 9).

### 2.3 Dependencies to ADD (pom.xml)

| Dependency | Version | Reason | Alternative considered |
|------------|---------|--------|----------------------|
| `io.jsonwebtoken:jjwt-api` + `jjwt-impl` + `jjwt-jackson` | 0.12.x | RS256 sign/verify + JWKS building; small focused API | `spring-boot-starter-oauth2-resource-server` (Nimbus) pulls a larger surface and steers toward JwtDecoder/JwtEncoder autoconfig that conflicts with the custom SecurityConfig; issuance use-case needs only a JWT builder, not a full resource-server stack. **ADR decision — flag at Gate 2.** |

> **No Redis dependency added in this story.** `RateLimitStore` ships with `InMemoryRateLimitStore`
> only. Do NOT add `spring-boot-starter-data-redis` here.

> **Supply-chain gate:** run `./mvnw verify -Psecurity` (OWASP dependency-check, fail on CVSS ≥ 7)
> before merge (part of `/pre-pr-check`).

### 2.4 Database Impact

| Migration | Change | Additive? | Risk |
|-----------|--------|-----------|------|
| (none required) | `refresh_tokens` fully defined in V2; `uq_refresh_tokens_token_hash` UNIQUE covers `findByTokenHash`; `idx_refresh_tokens_user_id_revoked_at` + `idx_refresh_tokens_family_id` cover revocation queries | n/a | None |
| **V4 (optional)** | `CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at)` — only if design adds a token-expiry cleanup sweep query | Additive | Low |

**Verdict: no required schema change.** `RefreshToken.revoke()` writes only the existing
`revoked_at` column; `ddl-auto=validate` remains satisfied. V4 slot is reserved per Gate-1 Q8.

---

## 3. Frontend Impact

### 3.1 Files to MODIFY

| File path | Change description | Risk |
|-----------|--------------------|------|
| `src/app/app.config.ts` | Register new `authInterceptor` in `withInterceptors([...])` — order: after `correlationIdInterceptor`, around `apiErrorInterceptor` (bearer attach before send; refresh-retry on 401) | Medium — interceptor ordering bugs are subtle |
| `src/app/features/auth/auth.service.ts` | Add `login()`, `refresh()`, `logout()`; `login()` and `refresh()` must use `withCredentials: true` for the httpOnly cookie | Medium |
| `src/app/features/auth/auth.routes.ts` | Add `login` lazy child route | Low |

### 3.2 Files to CREATE

| File path | Purpose |
|-----------|---------|
| `src/app/features/auth/login-form/login-form.component.ts` (+ `.spec.ts`) | Smart standalone component; signal form state; `shared/ui` primitives (NxInput/NxButton/NxCard/NxToast); shows `AUTH_001` "Invalid email or password" and `AUTH_002` resend prompt |
| `src/app/core/auth/auth.store.ts` | Signal-based in-memory access-token store; **never** localStorage/sessionStorage; clears on expiry/logout |
| `src/app/core/auth/auth.guard.ts` | `canActivate` functional guard; redirects unauthenticated → `/auth/login` |
| `src/app/core/http/auth.interceptor.ts` (+ `.spec.ts`) | Attaches `Authorization: Bearer` from `AuthStore`; on 401 triggers single `refresh()` call then retries the original request once; sets `withCredentials: true` for auth calls |
| `src/app/shared/types/jwt-claims.ts` | Typed claims record (no `any`); used by `AuthStore` and `MeResponse` mapper |

> The existing `apiErrorInterceptor` and `AppError` shape already handle RFC 7807 bodies including
> `429`/`Retry-After`; the login form reads `AppError.code` directly — no error-pipeline change.

---

## 4. Cross-Cutting Impact

### 4.1 Security Config changes

`SecurityConfig.apiSecurity` (the single filter chain) is rewritten:

- **Removed:** `.httpBasic(Customizer.withDefaults())` — HTTP Basic placeholder.
- **Added:** `.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)`. The filter is registered **unconditionally** (independent of the feature flag) — when the flag is off no token is ever issued, making it a harmless no-op.
- **Permit-all (public):** `/api/v1/auth/login`, `/api/v1/auth/refresh`, `/.well-known/jwks.json` added alongside existing registration/verification routes and actuator/swagger rules.
- **Authenticated (default-deny preserved):** `/api/v1/users/me` and all other routes via `anyRequest().authenticated()`.
- Stateless session, CSRF-disabled, HSTS posture — **unchanged** (correct for Bearer tokens).
- CORS: extended to cover `/.well-known/**` and to expose `Set-Cookie` (needed for httpOnly cookie delivery to Angular).

> `SecurityConfig` lives in the shared `config` package, so this change has the **largest blast
> radius of any file in the story** — it affects all current and future bounded contexts. It is
> excluded from JaCoCo (`**/config/**`), so its behaviour must be covered by `*IT` security tests.

### 4.2 Claims contract freeze

Access JWT carries exactly: `sub`, `tenant_id`, `email_verified`, `roles[]` (hardcoded `["USER"]`,
Gate-1 Q4), `iat`, `exp`, `jti` (UUIDv7), `token_version`. `tenant_id` sourced from
`User.tenantId` only (SECURITY.md §3 — never from request body or path). `kid` is embedded in the
JWT header from day 1 (Gate-1 Q7) even though rotation is deferred, so the header shape is
stable. The contract is enforced by a **JSON-schema contract test in CI** (test scenario 9) and
**freezes at end of Sprint 2**. Downstream: US-004/005/006/008 all read these claims from
`SecurityContextHolder`; adding/renaming a claim post-freeze requires a major version bump and
stakeholder sign-off.

### 4.3 RateLimitStore abstraction

`RateLimitStore` (application outbound port, inner layer) is the Sprint-2 extensibility seam:

- `InMemoryRateLimitStore` — default; no new dependencies.
- `RedisRateLimitStore` — future; added with **zero application-code change**, activated via:
  ```yaml
  nexus.security.rate-limit.store-type: redis
  ```
- Rule enforced: **5 attempts / 5-min window per IP AND per username** (SECURITY.md, Gate-1 Q3).
- On limit: throws existing `RateLimitException(code=RATE_LIMIT_EXCEEDED, retryAfterSeconds)` →
  `GlobalExceptionHandler` returns `429` + `Retry-After`.

---

## 5. Integration Points (what downstream features depend on)

| Downstream story | Depends on | If US-003 changes this later... |
|------------------|-----------|---------------------------------|
| US-004+ (all authed endpoints) | `JwtAuthenticationFilter` → `SecurityContextHolder` principal/claims | Any change to principal shape breaks every protected endpoint |
| US-004/005/006/008 | Frozen claims contract (8 claims) | Post-freeze claim change = major version bump + stakeholder sign-off |
| US-005 (logout) | `RefreshToken.revoke()`, `RefreshTokenPort.revokeByUserId()`, `token_version` bump | Reuses revocation primitives built here |
| US-006 (failed-login lockout) | `User.failed_attempt_count`/`locked_until` (schema ready) + `LoginUseCase` status gate | Lockout slots into the existing status-check branch in `LoginUseCase` |
| JWKS consumers (gateways/services) | `GET /.well-known/jwks.json` shape + `kid` | Rotation must keep old `kid` published during the overlap window |
| Frontend protected routes | `AuthGuard` + `AuthStore` + `authInterceptor` | Token-storage policy change ripples to all guarded routes |

---

## 6. Breaking Changes

- **`SecurityConfig`: HTTP Basic → JWT Bearer.** HTTP Basic was an explicit placeholder; no
  existing client uses it. External contract: unchanged. Internal: `*IT` tests that authenticated
  via `httpBasic`/`@WithMockUser` against the live chain may need to mint a test JWT instead.
- **No API contract breaks:** all four endpoints are net-new; `/register`, `/verify-email`,
  `/resend-verification` are untouched.
- **No DB breaking changes:** all migrations remain additive; no V1–V3 edits.

**Net: No externally breaking changes.** One internal test-infrastructure adjustment.

---

## 7. Top Risks

1. **SecurityConfig blast radius (High).** A wrong matcher or filter ordering either exposes
   `/users/me` publicly or locks out the whole API for all contexts. It is JaCoCo-excluded so unit
   coverage won't catch it. Mitigation: dedicated security `*IT` suite (missing-token→401,
   valid→200, permit-all paths→200 unauthenticated, tampered/expired/alg=none→401) before merge;
   review matcher ordering explicitly at Gate 2.

2. **Anti-enumeration timing (High, security).** Unknown email must run a constant-time dummy
   Argon2 hash so the response-time delta vs wrong-password stays < 50 ms; the PENDING short-
   circuit (AUTH_002 before Argon2) is acceptable since a different code is returned. Mitigation:
   implement dummy-hash branch in `LoginUseCase`; cover with timing test (scenario 5) asserting
   identical `AUTH_001` body for both unknown-email and wrong-password paths.

3. **RS256 key fail-fast mis-wiring (High).** Prod must hard-fail if `NEXUS_JWT_PRIVATE_KEY_PEM`
   is absent; dev/test use ephemeral keys. A missed profile check risks either shipping an
   ephemeral key to prod (catastrophic) or crashing dev environments. Mitigation: `RsaKeyConfig`
   keys off Spring profile + env-var presence; explicit startup assertion; `alg=none`/HS256
   downgrade rejection must be unit-proven (scenario 4).

4. **New 401 mapping gap (Medium).** `GlobalExceptionHandler` currently has no 401 handler
   (`DomainException` hierarchy handles 404/409/410/422/429/403). `AuthenticationException`→401
   needs a new `@ExceptionHandler` entry. Easy to overlook. Mitigation: add the handler;
   assert `AUTH_001` → 401 body shape in `LoginControllerIT`.

5. **JWT library choice is ADR-worthy (Medium).** JJWT vs Spring-native Nimbus affects future
   resource-server work; swapping later is costly. Mitigation: decide at Gate 2 with a written ADR;
   run OWASP dependency-check (`-Psecurity`) on whichever is chosen.

6. **Refresh-token rotation concurrency (Medium).** One-time-use rotation with reuse-
   detection→revoke-family is concurrency-sensitive; the `@Version` optimistic lock must be
   leveraged to avoid double-spend. Mitigation: `RefreshTokenRotationIT` covering concurrent
   presentation of the same refresh token → only one succeeds; the other triggers family revocation.

---

## 8. What is NOT touched

- No new bounded context; no new DB table.
- No V1–V3 migration edits; no required V4 (optional expiry index only).
- `RegisterUserUseCase`, `RegistrationController`, `AuthTokenPort`, `auth_tokens` table — unchanged.
- `EmailBlindIndexService`, `TokenGenerator`, `TokenHasher`, email-encryption/HMAC stack, mail subsystem — unchanged.
- `GlobalExceptionHandler` body — only a new `@ExceptionHandler(AuthenticationException.class)` added; no existing handler modified.
- `AuthEventPort`, `UserRegistrationPort`, `RequestContext`, `CorrelationIdFilter` — unchanged.
- Frontend: `apiErrorInterceptor`, `AppError`, `correlationIdInterceptor`, `shared/ui` — unchanged.
- No Redis dependency, no Docker Compose change this sprint.
- Out of scope: MFA, SSO/OAuth2/OIDC, "remember me", logout (US-005), password reset (US-007+),
  failed-login lockout (US-006), multi-key rotation (mechanism deferred; `kid` present from day 1),
  `user_roles` table (`roles` hardcoded `["USER"]`).
