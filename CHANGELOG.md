# Changelog

All notable changes to Nexus are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) · Versioning: [SemVer](https://semver.org/).

---

## [Unreleased]

### Added — US-013 (Implement Angular permission guard and directive)

**Frontend**
- `permissionGuard` — functional route guard (`CanActivateFn`, mirrors the existing `authGuard` pattern); redirects to `/access-denied` (never `/auth/login`) when the current user's `AuthStore.permissions` signal lacks the route's `data.permission`. Fails open (allows navigation) on a missing/invalid `data.permission` — a deliberate, documented misconfiguration response, not a security decision, since this guard is UX only.
- `HasPermissionDirective` (`*appHasPermission`) — the first `@Directive` in this codebase; a reactive structural directive (`effect()` + `computed()` short-circuit + a plain `hasView` boolean) that shows/hides its host element based on the same permission signal. Degrades gracefully to "hidden" on an empty/absent permission list — never throws.
- `AccessDeniedComponent` — new public, unguarded, WCAG 2.1 AA page at `/access-denied`, reusing the existing `NxErrorState` component; owns its own `<main>`/`<h1>` (visually hidden, focus-managed on route entry) since `NxErrorState`'s `title` renders as a `<p>`, not a heading.
- `AuthStore.permissions` — new computed signal, and `AuthUser.permissions`/`MeApiResponse.permissions` wiring through `buildSession()` — connects the already-shipped backend `permissions[]` field (US-010) to the frontend for the first time; frozen for immutability, defaults to `[]` (never `undefined`) so downstream consumers never need a null check.
- `AppError.requiredPermission` — new optional field threading the backend's `RBAC_001` 403 field (US-011) through `api-error.interceptor.ts` for developer diagnostics; explicitly never rendered to end users.
- **Mechanical route-table contract** (`permission-guard-contract.spec.ts`) replaces two documentation-only invariants with a build-time check: every route using `permissionGuard` must declare a non-empty `data.permission` and compose `authGuard` (same `canActivate`/`canActivateChild` array or an ancestor route) — deliberately not an ESLint rule (trivially defeated by aliasing). Statically visible routes only: a `loadChildren`-loaded feature's own route table needs an equivalent contract test local to that module. Vacuously green today; becomes load-bearing the moment a real route adopts the guard.
- Shipped as **infrastructure only** — no existing route or component uses either the guard or the directive yet; the first real behavior change lands with the first Epic 3 route that adopts them.
- No backend change, no database migration, no feature flag (design's own explicit assessment: this story adds code nothing yet calls, so a flag would gate nothing).
- Threat model: PASS WITH REQUIRED FOLLOW-UPS (0 Blocker/High, 4 Medium, 6 Low), all 6 required mitigations closed. Security review: APPROVED (0 Blocker/High/Medium, 3 Low) — 2 of 3 Low findings (SEC-1 fragment stripping, SEC-2 `canActivateChild` coverage) remediated and re-tested; the third (SEC-3, `GlobalErrorHandler`'s wholesale `JSON.stringify` fallback) is accepted and ticketed, not closed, gated on landing before any remote error-tracking sink is wired. Independently re-verified that neither the guard's nor the directive's output is readable by application code, foreclosing the story's own top-named risk (mistaking this for real authorization) by construction, not just by documentation.
- 29/29 frontend test files, 208/208 tests passing; `npm run lint` and `npm run build` clean.
- ADR: none required — the one candidate (clarifying `*appHasPermission` doesn't violate `ARCHITECTURE.md`'s "no `*ngIf`/`*ngFor`" non-negotiable) was resolved with a one-clause doc edit instead of a new ADR.

### Added — US-012 (Enable role assignment and revocation API)

**Backend**
- First controller in the `rbac` bounded context: `POST`/`GET`/`DELETE /api/v1/users/{userId}/roles[/{roleId}]`, gated by `@RequiresPermission("user:write"/"user:read")` (US-011) plus service-layer tenant-isolation (AC4), last-admin lockout (AC5), and self-escalation (AC8) guards — `TenantAwarePermissionEvaluator` checks only flat JWT `permissions[]` membership and cannot express any of the three.
- `RoleAssignmentService` — the sole enforcement point for AC4/AC5/AC8; new outbound ports `UserRoleAssignmentPort`, `UserDirectoryPort`, `RbacAuditPort` (declared in `rbac.application.port.out`, implemented in `identity.infrastructure`, preserving the existing `identity → rbac` dependency direction — never the reverse — now mechanically enforced by a new ArchUnit rule).
- AC5's lockout guard and AC8's live-admin check are both DB-level locking reads (`FOR UPDATE`/`FOR SHARE`) driven by the FK-indexed `role_id`, never the unindexed `tenant_id` — closes a TOCTOU race and a full-table-lock DoS hazard identified pre-implementation.
- `RBAC_002` (409, last-admin lockout) and `RBAC_004` (409, duplicate active assignment) — new domain exceptions with static-literal messages (never echo a caught constraint-violation message, which would otherwise leak raw user/role ids into the client-visible response).
- `ROLE_ASSIGNED`/`ROLE_REVOKED` added to `AuthEventType`, routed through the retry-buffer's `PRIORITY` lane (not `STANDARD`) so a correlated `LOGIN_FAILURE` flood cannot silently drop a role-change audit record.
- New feature flag `feature.nexus-us012-rbac-role-assignment.enabled`, default `false` — overrides this story's own "no flag" text, since this is the platform's only control against a Critical self-escalation threat and a config flip is the fastest kill switch if a bypass is ever found.
- No new Flyway migration — `V5__rbac_schema.sql` already carried every column/index/constraint this story needed. No new `nexus_app` DB grants required.
- **Bug found and fixed in Phase 8 (test-validate):** `JpaUserRoleAssignmentAdapter.assign()` used `save()` instead of `saveAndFlush()`, letting a concurrent duplicate-assignment's `DataIntegrityViolationException` escape the adapter's own translation `try/catch` (Hibernate deferred the physical INSERT to a later auto-flush one call frame away) — would have surfaced as an unhandled 500 instead of a clean 409 under a real race. Fixed; caught by a new 8-thread concurrency test.
- ADR: none required — every design decision traces to an already-accepted ADR (0002, 0003, 0005, 0013, 0014, 0015, 0016); confirmed still accurate after implementation, including the Phase 8 fix (a correctness fix, not a new architectural decision).
- 429/429 backend tests passing; JaCoCo bundle + package gates met; SpotBugs 0 bugs; code review APPROVE WITH NITS (2 Medium/4 Low); security review APPROVED (3 Medium/10 Low, zero Blocker/High).

**Frontend**
- None — zero frontend impact (no client anywhere in `nexus-frontend/src` calls this endpoint family; `/users/me` is untouched).

### Added — US-009 (RBAC data model and seed system roles/permissions)

**Backend**
- New bounded context `com.example.nexus.rbac`: `Permission`, `Role`, `RolePermission` (+ `RolePermissionId`, `@EmbeddedId`), `UserRole` entities + 4 Spring Data repositories, mirroring `identity`'s hexagonal layout.
- `V5__rbac_schema.sql` — 4 new tables (`permissions`, `roles`, `role_permissions`, `user_roles`); a `STORED` generated column (`active_key`) + unique index enforcing "one active role assignment per (user, role)" at the DB level (MySQL 8.4 has no partial/filtered unique index, so this replaces that Postgres-only feature); a `CHECK` constraint guarding against backdated revocation; a `BEFORE DELETE`-only trigger (append-only `user_roles`, `revoked_at` remains the sole soft-delete path).
- Seeded: 7 code-defined permissions (`resource:action` naming), 2 system roles (`TENANT_ADMIN` — all permissions, `MEMBER` — `user:read` only), scoped to a bootstrap default tenant.
- Least-privilege `nexus_app` DB grants for all 4 new tables added across all 3 provisioning artifacts (dev init SQL, Testcontainers, prod runbook), including a column-scoped `GRANT UPDATE (revoked_at)` on `user_roles` — every other column on that table remains grant-level immutable, matching the `auth_events` posture.
- ADR 0013 (RBAC model, permission naming, `active_key` technique), ADR 0014 (bootstrap tenant sourcing, `nexus_app` grants), ADR 0015 (Gate-2 threat-model hardening: column-scoped grant, non-prod-only tenant fallback).
- Schema-only story — no runtime API, no enforcement, no feature flag. Hard gate for Epic 3 (Tenant Management) kickoff once `TENANT_ADMIN` is reachable; permission enforcement (US-011), JWT population (US-010), and the assignment/management APIs (US-012/US-015) are separate, upcoming stories.
- 606/607 backend tests passing (1 unrelated pre-existing skip); AC9 grant smoke-verified end-to-end against real Docker MySQL 8.4, not just Testcontainers.

### Added — US-007 (Self-service password reset via email)

**Backend**
- `POST /api/v1/auth/password/forgot` — accepts an email address and, if the account is registered, sends a single-use reset link (256-bit token, 1-hour TTL). Always returns 202 regardless of account existence (anti-enumeration, AC-1).
- `POST /api/v1/auth/password/reset` — validates the reset token, enforces password policy, updates the credential, and revokes all existing sessions (AC-2 through AC-6).
- `ForgotPasswordUseCase` — throttle: 3 reset emails per account per hour; `PASSWORD_RESET_REQUESTED` / `PASSWORD_RESET_THROTTLED` audit events in `REQUIRES_NEW` sub-transaction.
- `ResetPasswordUseCase` — SHA-256 token hash lookup; optimistic-lock single-use enforcement (`markConsumed + flush`); Argon2 password hashing via `PasswordHasherPort`; `revokeAllUserSessions` (REQUIRES_NEW); `PASSWORD_RESET_FAILED` / `PASSWORD_CHANGED` audit events; session-revocation failure is swallowed with a WARN log.
- `TokenGenerator` — 32-byte `SecureRandom` → 64-char hex (256-bit entropy).
- `PasswordResetEmailEvent` — `toString()` redacts raw token and masks email address (SEC-3 compliance).
- `MailEventListener.onPasswordReset` — `@Async @TransactionalEventListener(AFTER_COMMIT)` prevents phantom emails on rollback.
- `LoginRateLimitFilter` — extended to cover `/password/forgot` (per-IP `FORGOT_IP:` + per-email-HMAC `FORGOT_USER:` buckets) and `/password/reset` (per-IP `RESET_IP:` bucket). New config: `nexus.security.rate-limit.forgot-ip-max-attempts` (default 10), `reset-ip-max-attempts` (default 20).
- `User.applyPasswordReset()` — password hash update + `tokenVersion++` + ACTIVE transition + lockout reset.
- `SecureEventService.revokeAllUserSessions()` — REQUIRES_NEW sub-transaction; revokes all `REFRESH`-type tokens for a user.
- No new Flyway migration: index `idx_auth_tokens_user_id_type_created_at` on `auth_tokens(user_id, type, created_at)` was already created in V3 for `ResendVerificationUseCase`; it doubles as the reset throttle query index.
- ADR 0010: password-reset token delivery as URL query parameter.
- 369 backend tests (0 failures).

**Frontend**
- `ForgotPasswordComponent` (`/auth/forgot-password`) — email form; confirmation text is identical regardless of whether the account exists (anti-enumeration).
- `ResetPasswordComponent` (`/auth/reset-password?token=<hex>`) — reads token from query parameter, strips it from URL via `replaceUrl:true` on init (Referer-leak mitigation); `Validators.maxLength(256)` to match backend DTO; error handling for all 4 documented error codes.
- `LoginFormComponent` — "Forgot password?" link; success banner when redirected with `?reset=true`.
- `AuthService.forgotPassword()` — `Observable<void>` (anti-enumeration: no response body consumed).
- `AuthService.resetPassword()` — `Observable<{message: string}>`.
- Frontend test suite: 87.46% statement, 82.09% branch coverage.

### Added — US-006 (Brute-force lockout & password policy split)

**Backend**
- Account lockout: 5 consecutive failed login attempts transition a user to `LOCKED` status for 15 minutes (`User.lockAccount`, `User.unlockIfExpired`, `SecureEventService.persistFailedAttempt`).
- Auto-expiry: expired locks auto-clear on the next successful login without admin intervention.
- `AccountLockedException` in `common.domain` — maps to HTTP 423 with `AUTH_LCK_001` error code and `Retry-After` header (RFC 7807 compliant).
- `GlobalExceptionHandler.handleAccountLocked` — 423 response with `retryAfterSeconds` in body and `Retry-After` header.
- REQUIRES_NEW transaction boundary in `SecureEventService` so counter writes commit independently of the outer login transaction rollback (ADR 0009).
- JPQL bulk UPDATE `resetFailedAttemptsDirect` on `JpaUserRepository` to avoid `@Version` collision when resetting the counter on successful login (M-OL-1 fix).
- Audit events: `ACCOUNT_LOCKED`, `ACCOUNT_UNLOCKED`, `ACCOUNT_LOCKED_WRITE_FAILED` added to `auth_events`.
- `PasswordPolicyService` error code split: `AUTH_PWD_001` (length) and `AUTH_PWD_002` (denylist) — previously both used the same code.
- Rate-limit config split: `ip-max-attempts`, `ip-window-seconds`, `user-max-attempts`, `user-window-seconds`, `refresh-max-attempts` (replaces the old single `max-attempts` / `window-seconds`).
- 6 new unit/integration test files; 13 coverage gaps closed; total backend tests: 325.

**Frontend**
- `login-form.component.ts`: `AUTH_LCK_001` error code maps to "Too many attempts. Try again later or reset your password." message.
- Frontend test suite: 130 tests passing.

**Documentation**
- ADR 0009: REQUIRES_NEW + bulk UPDATE pattern for lockout counter writes.
- `docs/features/US-006/` artifacts: requirements, impact, design, threat model, tasks, code review, security review, test audit, technical doc, deployment, rollback, monitoring, runbook.

---

## [0.5.0] — 2026-05-20 (US-005 Logout with refresh token revocation)

### Added
- `POST /api/v1/auth/logout` — revokes the caller's refresh token family.
- `SecureEventService.revokeFamily` for family revocation in REQUIRES_NEW TX.
- Audit event `REFRESH_FAMILY_REVOKED` on logout.
- Tokenless logout (no body) returns 204.

---

## [0.4.0] — 2026-04 (US-004 Email verification)

### Added
- Email verification token flow (`POST /api/v1/auth/verify`).
- PENDING → ACTIVE status transition on verification.
- Verification token expiry (24 h), re-send endpoint.

---

## [0.3.0] — 2026-03 (US-003 Login with JWT + refresh token)

### Added
- `POST /api/v1/auth/login` → access JWT (RS256, 15 min) + refresh token (14 days, rotated).
- `POST /api/v1/auth/refresh` → rotate refresh token.
- IP rate-limiting at Servlet layer (`LoginRateLimitFilter`).
- `auth_events` table for audit trail.

---

## [0.2.0] — 2026-02 (US-002 User registration)

### Added
- `POST /api/v1/auth/register` — tenant-scoped user registration.
- Argon2id password hashing (19 MiB / 2 iterations / 1 parallelism).
- AES-256-GCM email encryption + HMAC blind index.
- Flyway V2 schema: `users`, `refresh_tokens`, `auth_events`.

---

## [0.1.0] — 2026-01 (US-001 Project bootstrap)

### Added
- Spring Boot 4 / Java 25 / Maven modular monolith skeleton.
- Angular 21 standalone-component frontend skeleton.
- Hexagonal architecture with ArchUnit enforcement.
- Flyway V1 schema: `tenants` table.
- CI: GitHub Actions build + test + OWASP Dependency-Check.
