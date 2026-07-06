# Requirements & Discovery — US-002
## Enable Self-Service Registration with Email Verification

**Status:** DRAFT — awaiting Gate 1 approval  
**Date:** 2026-06-16  
**Author:** Business Analyst (Claude Code)  
**Inputs:** `docs/story/1-authentication/US-002.md`, `docs/features/US-001/03-design.md`,
`docs/ARCHITECTURE.md`, `SECURITY.md`, `docs/observability-standards.md`,
`docs/deployment-process.md`, all ADRs 0001–0006

---

## 1. Problem Statement

US-002 delivers the first user-facing identity flow: a B2C end consumer can create an account
with email + password, receive a verification email, and activate the account by clicking the link.
Verification is required before any subsequent login succeeds (US-003). The consent capture at
signup satisfies the platform's GDPR posture.

**Bounded context:** `com.example.nexus.identity` (established by US-001).  
**Explicit non-goals (this story only):**
- B2B invite flow (Epic 3)
- Social login / OAuth2 / OIDC
- Admin-created user accounts
- Login, refresh, logout (US-003+)
- Password reset (US-007+)
- Account lockout from failed logins (US-006+)

---

## 2. Reuse-First Survey

### What US-001 already built that US-002 consumes directly

| Artifact | Location | Reuse Plan |
|----------|----------|------------|
| `User` entity with `status=PENDING`, `email_verified_at`, `consent_accepted_at`, `failed_attempt_count`, `locked_until`, `token_version` | `identity.domain.User` | Extend with `passwordHash`; remaining columns land for free |
| `AuthToken` entity with `consumed_at`, `expires_at`, `token_hash` | `identity.domain.AuthToken` | Used as-is for VERIFICATION tokens |
| `AuthTokenType.VERIFICATION` | `identity.domain.AuthTokenType` | Used as-is |
| `UserStatus.PENDING` / `ACTIVE` | `identity.domain.UserStatus` | State transitions: PENDING → ACTIVE on verify |
| `AuthConstants.AUTH_VERIFICATION_TOKEN_TTL = 24h` | `identity.domain.AuthConstants` | Token expiry pre-defined |
| `EmailBlindIndexService.blindIndex()` | `identity.application` | Duplicate-email lookup & anti-enumeration timing |
| `JpaUserRepository.findByTenantIdAndEmailHmac()` | `identity.infrastructure.persistence` | Existence check for duplicate email |
| `GlobalExceptionHandler` (RFC 7807) | `common.web` | New error codes plug in with zero change |
| `DomainException` hierarchy | `common.domain` | New `RegistrationException` extends this |
| `CorrelationIdFilter` + MDC `traceId` | `common.web` | Audit events and log correlation already wired |
| `users`, `auth_tokens`, `auth_events` tables | V2 migration | All columns for US-002 already present **except** `password_hash` |
| `NxInput`, `NxButton`, `NxCard`, `NxToast` | `shared/ui` | Registration form built on these |
| `AppError` + `apiErrorInterceptor` | `core/http` | Error handling on form submission already present |

### What US-002 must create (nothing equivalent exists)

| Layer | New Artifact | Notes |
|-------|-------------|-------|
| DB | **V3 migration** — add `password_hash VARCHAR(255) NOT NULL` to `users` | Only missing column from the schema |
| Domain | `PasswordHash` value type (analogous to `EmailCipher`) | Typed seam; prevents accidental plain-text storage |
| Application | `RegisterUserCommand` + `RegisterUserUseCase` | Orchestrates blind-index, hash, persist, emit token, send mail |
| Application | `VerifyEmailUseCase` | Marks token consumed, transitions user PENDING→ACTIVE |
| Application | `ResendVerificationUseCase` | Issues new token; enforces throttle AC-5 |
| Application port | `UserRegistrationPort` | Outbound port wrapping repo operations |
| Application port | `AuthTokenPort` | Outbound port for token read/write |
| Application port | `MailSender` | Interface — provider not yet selected (AC background) |
| Application | Password policy validator | Min 12 chars + breached-password check; emits `AUTH_PWD_001` |
| Infrastructure | `JpaAuthTokenRepository` | Spring Data for `auth_tokens` |
| Infrastructure | `JpaUserRegistrationAdapter` | Implements `UserRegistrationPort` |
| Infrastructure | `MailHogMailSender` (dev) / `LoggingMailSender` (test) | Dev/test stub; real provider in US-008+ |
| Interfaces | `RegistrationController` (`POST /api/v1/auth/register`, `/verify-email`, `/resend-verification`) | First `identity.interfaces` package |
| Security | `PasswordEncoder` bean (Argon2id) | Spring Security's `Argon2PasswordEncoder` (already transitively available via `spring-security-crypto`) |
| Security | `SecurityConfig` update | `permitAll` on the three new endpoints |
| Frontend | `RegistrationFormComponent` (smart) | Signals-based, reactive form, WCAG 2.1 AA |
| Frontend | `PasswordStrengthMeterComponent` (dumb) | Advisory only; text+icon, not color alone (AC-7) |
| Frontend | `VerificationLandingComponent` (smart) | Handles `/auth/verify-email?token=xxx` |
| Frontend | `AuthService` | HTTP calls; wraps `AppError` |
| Frontend | Routes `/auth/register`, `/auth/verify-email` | New route shell |
| Config | Feature flag property `feature.nexus-us002-auth-registration.enabled` | `@ConditionalOnProperty` guard on controller |

### ADRs already applicable

| ADR | Implication for US-002 |
|-----|------------------------|
| ADR-0002 Hexagonal | Use-cases in `application`; no domain import of infrastructure |
| ADR-0003 Flyway | V3 migration for `password_hash` must be append-only |
| ADR-0005 UUIDv7 | Inject `UuidGenerator` to mint token IDs; never call generator from entities |
| ADR-0006 Email blind index | Use `EmailBlindIndexService` for every email lookup; do not add a second normalisation path |
| ADR-0004 Angular Material | Registration form uses `--nx-*` tokens; no `@angular/material` direct imports in feature components |

---

## 3. Impact Map

### Backend layers

| Layer | Changes |
|-------|---------|
| **Domain** | Add `passwordHash` field to `User`; add `PasswordHash` value type; add state-transition methods (`verify()`, `recordConsent()`) |
| **Application** | Three new use-case services; two new outbound ports (`UserRegistrationPort`, `AuthTokenPort`); `MailSender` port; password-policy validator |
| **Infrastructure** | `JpaAuthTokenRepository`; `JpaUserRegistrationAdapter`; `MailHogMailSender`; `Argon2PasswordEncoder` bean; `SecurityConfig` update |
| **Interfaces** | `RegistrationController` (3 endpoints); request/response DTOs; OpenAPI annotations |

### Database

| Change | Migration | Risk |
|--------|-----------|------|
| Add `password_hash VARCHAR(255) NOT NULL DEFAULT ''` to `users` | V3 — additive | Low; default `''` satisfies NOT NULL for existing rows (if any); populated on first register; column is immediately required for new rows |
| No other table/column changes | — | US-001 schema already included all other needed columns |

### Frontend

| Area | Change |
|------|--------|
| `app.routes.ts` | Add lazy-loaded `auth/` feature shell with `register` and `verify-email` child routes |
| New feature module | `src/app/features/auth/registration/` |
| `AuthService` | New service in `src/app/features/auth/` |

### API — new endpoints

| Endpoint | Method | Auth |
|----------|--------|------|
| `/api/v1/auth/register` | POST | Public |
| `/api/v1/auth/verify-email` | POST | Public |
| `/api/v1/auth/resend-verification` | POST | Public |

### Cross-context effects

- No other bounded contexts are touched.
- US-003 (login) depends on `status=ACTIVE` being set here — the state machine must be correct.
- `auth_events` audit rows will be written for the first time; tests must verify insertion but not mutation/deletion (trigger already enforced by US-001's `AuthEventsAppendOnlyIT`).

---

## 4. Non-Functional & Risk

### Security

| Concern | Detail |
|---------|--------|
| Password hashing | Argon2id via Spring Security's `Argon2PasswordEncoder`; store in `password_hash`; never log |
| Breached-password check | HIBP k-Anonymity API (online, privacy-preserving) vs. embedded static top-10k denylist — **open question Q2** |
| Anti-enumeration (AC-4) | Both paths (new email + duplicate email) must take the same wall-clock time ±50 ms; email dispatch is async; blind-index lookup is constant-time via index |
| Verification token | Generated as 32 random bytes (256-bit), hex-encoded → 64 chars; stored as SHA-256 hash (already `token_hash VARCHAR(64)`) |
| Single-use token | `consumed_at` checked + set in same optimistic-locked transaction; second use returns 410 + `AUTH_VRF_002` |
| Resend throttle (AC-5) | Rate-limit state stored in `auth_tokens` (count records per user/type/window) — avoids new dependencies; see Q3 |
| Consent | `consent_accepted_at` written at registration; missing → 400 |
| PII in logs | Email must be masked `u***@example.com` in all log statements |
| STRIDE | Full threat model deferred to Phase 3 (03b-threat-model.md) |

### Performance

- Registration p95 < 500 ms (AC-1). Argon2id is intentionally slow (~100–500 ms); email dispatch must be **async** (Spring `@Async` or ApplicationEvent). The hash is the hot path.
- 50 RPS sustained (QA scenario 5). Argon2id at default params is ~200 ms → 50 RPS requires at least 10 threads. Confirm thread pool sizing.
- No N+1 risk: registration is a single-row insert. Email lookup uses the existing UNIQUE index.

### Observability

Per `docs/observability-standards.md`:

| Signal | Detail |
|--------|--------|
| `auth_events` audit rows | `REGISTRATION_INITIATED`, `REGISTRATION_DUPLICATE_EMAIL`, `VERIFICATION_SUCCESS`, `VERIFICATION_FAILED`, `RESEND_REQUESTED`, `RESEND_THROTTLED` |
| Micrometer counters | `nexus_auth_register_requests_total{status}`, `nexus_auth_verify_requests_total{status}`, `nexus_auth_resend_requests_total{status}` |
| Micrometer histogram | `nexus_auth_register_duration_seconds` (covers Argon2id hash time) |
| MDC fields | `userId` (after creation), `tenantId` — available after user row is persisted |
| INFO log | User created (`userId=xxx`, `email=u***@example.com`, `tenantId=xxx`) |

### Feature flag

Flag name: `feature.nexus-us002-auth-registration.enabled`  
Mechanism: `@ConditionalOnProperty(name = "feature.nexus-us002-auth-registration.enabled", havingValue = "true")`  
Default in application.yml: `false`; dev/staging overrides: `true`

---

## 5. Open Questions (Gate 1 blockers)

| # | Question | Impact if unresolved | Assumption if approved without answer |
|---|----------|---------------------|--------------------------------------|
| Q1 | **Tenant ID at B2C registration:** How is the tenant identified when a self-service consumer registers? Is there a fixed system/default tenant UUID, or does the request carry a tenant identifier? | Drives whether `tenant_id` comes from a request header, JWT pre-auth token, path param, or config constant | Assume a single **default B2C tenant** UUID stored in config (`nexus.identity.default-tenant-id`). The architect must confirm or override. |
| Q2 | **Breached-password check strategy:** HIBP k-Anonymity API (online call per registration) vs. embedded static top-10k denylist (bundled file, no network)? | HIBP: requires HTTP client, latency/availability risk; Static: simpler but staler coverage | Assume **embedded static denylist** (top 10k SHA1 prefixes in a resource file) until provider selection; can swap behind the port later. |
| Q3 | **Resend throttle storage:** Count `auth_tokens` rows (DB-based, no new dep) vs. in-memory `ConcurrentHashMap` (ephemeral, lost on restart) vs. Redis (not yet in stack)? | Correctness under horizontal scaling; Redis not currently in Docker Compose | Assume **DB-based** (count `auth_tokens` by user/type/window); simplest, correct under restart, no new infra. |
| Q4 | **MailHog on Docker Compose:** Is MailHog already wired in `docker-compose.yml`, or does it need to be added? Spring Mail starter (`spring-boot-starter-mail`) is not in `pom.xml`. | Both Docker Compose and pom.xml need updating | Need to add `spring-boot-starter-mail` to `pom.xml` and a MailHog service to Docker Compose. |
| Q5 | **`password_hash` column default for V3 migration:** Existing `users` rows (none in production yet, but present in staging/dev after US-001 deploys) will need a value. Using `DEFAULT ''` (empty string) is semantically wrong — those phantom rows can never log in, which is fine since no registrations have occurred. Should V3 use `DEFAULT ''` (safe, harmless) or `NOT NULL` with a backfill script (none needed since table is empty)? | Schema correctness vs. migration portability | Use `DEFAULT ''` with an immediate `ALTER TABLE` to drop the default after migration (two-statement additive migration). |
| Q6 | **Argon2id parameters:** `Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8()` (t=1, m=16384, p=1, ~50–80 ms per hash) or a stronger profile? AC-1 requires p95 < 500 ms; 50 RPS sustained means concurrent hashing. | Performance budget for the hash step | Use Spring Security v5.8 defaults; add a configurable `nexus.identity.argon2.*` override property so parameters can be tuned post-deploy without code changes. |

---

## 6. Acceptance Criteria Mapping

| AC# | Criterion | Backend implementation note | Frontend note |
|-----|-----------|----------------------------|---------------|
| AC-1 | Valid registration → 201, PENDING, email dispatched | `RegisterUserUseCase`; async mail; p95 < 500 ms | Form submit; show "check your email" state |
| AC-2 | Password policy enforced | `PasswordPolicyValidator`; `AUTH_PWD_001` | Client strength meter (advisory) |
| AC-3 | Token single-use, expires 24h | `VerifyEmailUseCase`; `consumed_at` + optimistic lock; 410 + `AUTH_VRF_002` | `VerificationLandingComponent` handles all states |
| AC-4 | No account enumeration | Duplicate email → same 201 response, different async email; timing ±50 ms | UI must not reveal whether email exists |
| AC-5 | Resend throttled (P1) | `ResendVerificationUseCase`; DB rate-limit; 429 + `Retry-After` | Resend button with cooldown indicator |
| AC-6 | Consent recorded | `consent_accepted_at` column; missing consent → 400 | Required consent checkbox |
| AC-7 | WCAG 2.1 AA | — | Labels, `aria-describedby` on errors, strength meter via text+icon |

---

## 7. Test Scenarios (preview for Phase 4 task breakdown)

| # | Scenario | Type |
|---|----------|------|
| 1 | Happy path: register → verify → status=ACTIVE | E2E (Playwright) |
| 2 | Duplicate email: same 201, "account exists" email sent | Integration |
| 3 | Expired token: 410, resend path | Integration |
| 4 | Token already consumed: 410 + AUTH_VRF_002 | Integration |
| 5 | Email provider down: account stays PENDING; resend later succeeds | Integration |
| 6 | Resend throttle: 6th resend within 24h → 429 + Retry-After | Integration |
| 7 | Password < 12 chars → 400 + AUTH_PWD_001 | Unit |
| 8 | Breached password → 400 + AUTH_PWD_001 | Unit |
| 9 | Missing consent → 400 | Unit |
| 10 | Anti-enumeration timing: both paths within ±50 ms | Security |
| 11 | XSS/SQLi payloads in email/password fields rejected/escaped | Security |
| 12 | 50 RPS sustained; p95 < 500 ms | Performance |
| 13 | WCAG axe scan: zero critical issues | Accessibility |

---

## 8. Dependencies & Constraints

| Item | Status |
|------|--------|
| US-001 merged & green | ✅ Done (branch US-001 merged as #9) |
| `email_verified_at`, `consent_accepted_at` columns in schema | ✅ Already in V2 migration |
| `auth_tokens` table and `VERIFICATION` type | ✅ Already in V2 migration |
| Transactional email provider selection | ❌ Not selected — MailHog dev stub covers this story |
| `spring-boot-starter-mail` in pom.xml | ❌ Missing — needed for `JavaMailSender` |
| MailHog in Docker Compose | ❌ Not confirmed — open question Q4 |
| US-003 (login) | Blocks: US-002 must be merged first |
