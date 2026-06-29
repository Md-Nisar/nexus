# Changelog

All notable changes to Nexus are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) · Versioning: [SemVer](https://semver.org/).

---

## [Unreleased]

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
