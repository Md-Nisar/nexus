# Threat Model — US-002
## Enable Self-Service Registration with Email Verification

**Status:** DRAFT — awaiting Gate 2 approval  
**Date:** 2026-06-16  
**Author:** Security Reviewer  
**Methodology:** STRIDE  
**Inputs:** `docs/features/US-002/03-design.md`, `SECURITY.md`, `docs/observability-standards.md`

---

## 1. System Under Analysis

### Components

| ID | Component | Layer |
|----|-----------|-------|
| C1 | Angular `RegistrationFormComponent` / `VerificationLandingComponent` | Frontend |
| C2 | `RegistrationController` | interfaces.rest |
| C3 | `RegisterUserUseCase` | application |
| C4 | `VerifyEmailUseCase` | application |
| C5 | `ResendVerificationUseCase` | application |
| C6 | `PasswordPolicyService` + `PasswordHasherPort` | application / infrastructure |
| C7 | `EmailBlindIndexService` | application |
| C8 | `JpaUserRegistrationAdapter` / `JpaAuthTokenAdapter` | infrastructure |
| C9 | `MailEventListener` + `SmtpMailSenderAdapter` | infrastructure |
| C10 | MySQL (`users`, `auth_tokens`, `auth_events`) | Database |
| C11 | MailHog / SMTP provider | External |

### Trust Boundaries

| ID | Boundary | Between |
|----|----------|---------|
| TB1 | Internet ↔ API | Unauthenticated callers → `RegistrationController` |
| TB2 | API ↔ Application | `RegistrationController` → use-cases |
| TB3 | Application ↔ Database | JPA adapters → MySQL |
| TB4 | Application ↔ Mail Provider | `SmtpMailSenderAdapter` → SMTP |
| TB5 | Browser ↔ API | Angular HTTP client → backend endpoints |

---

## 2. STRIDE Analysis

### S — Spoofing

| ID | Threat | Component | Existing Mitigation | Required Mitigation | Residual Risk |
|----|--------|-----------|--------------------|--------------------|---------------|
| T-S1 | Attacker registers with a victim's email, intercepts verification link to take ownership | C2, C9 | Token has 256-bit entropy; only correct email recipient receives the link | Token sent only to the email address supplied; victim's inbox is the second factor; no further mitigation needed | **Low** |
| T-S2 | Attacker crafts a plausible verification URL (guessing token) | C4, C10 | 256-bit token (2²⁵⁶ keyspace); SHA-256 stored (can't reverse from DB read) | — | **Negligible** |
| T-S3 | Attacker reuses a valid but not-yet-clicked token they observed in transit | C4 | HTTPS required in all non-local environments (TLS in transit) | Enforce HTTPS via `Strict-Transport-Security` header on all responses (see T-S3 task below) | **Low** |

**T-S3 task:** Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` response header in `SecurityConfig` for non-local profiles.

---

### T — Tampering

| ID | Threat | Component | Existing Mitigation | Required Mitigation | Residual Risk |
|----|--------|-----------|--------------------|--------------------|---------------|
| T-T1 | Token modified in URL | C4 | SHA-256 hash lookup; tampered token produces a different hash; no matching row → 410 | — | **Negligible** |
| T-T2 | SQL injection via email or password fields | C2, C8 | JPA `@Query` / derived queries use parameterized JDBC; Hibernate never interpolates user input | — | **Negligible** |
| T-T3 | Log injection (CRLF) via email or password fields | C2, C3 | Not yet implemented | **REQUIRED:** Sanitise all user-supplied strings before logging using `sanitize(input)` from `docs/observability-standards.md`; mask email as `u***@example.com` | **Med without mitigation; Low after** |
| T-T4 | XSS via registration form fields (stored, reflected) | C1, C2 | Angular template escaping prevents stored XSS on render; Bean Validation rejects excessively long inputs | Server-side: `@NotBlank @Size(max=N)` on all string fields already planned; no HTML rendered from user content in email templates | **Low** |
| T-T5 | Tampering with `consent_accepted_at` by bypassing the form | C2, C3 | `@AssertTrue` on DTO; use-case validates before creating user | Ensure `consentAcceptedAt` is always set to server `Instant.now()` — never accepted from client | **Low** |

---

### R — Repudiation

| ID | Threat | Component | Existing Mitigation | Required Mitigation | Residual Risk |
|----|--------|-----------|--------------------|--------------------|---------------|
| T-R1 | User denies registering | C3, C10 | `REGISTRATION_INITIATED` audit event written to append-only `auth_events` (US-001 triggers prevent deletion) | Include `ip_address` and `traceId` in `metadata` JSON | **Low** |
| T-R2 | User denies accepting consent | C3, C10 | `consent_accepted_at` persisted at exact registration instant; immutable after insert | `consent_accepted_at` must be server-side `Instant.now()` (confirmed in T-T5 above) | **Low** |
| T-R3 | Attacker denies token verification attempt | C4, C10 | `VERIFICATION_FAILED` audit event written with `tokenId` and IP | — | **Low** |
| T-R4 | No record of resend throttle abuse | C5, C10 | `RESEND_THROTTLED` audit event written | — | **Low** |

---

### I — Information Disclosure

| ID | Threat | Component | Existing Mitigation | Required Mitigation | Residual Risk |
|----|--------|-----------|--------------------|--------------------|---------------|
| T-I1 | Email enumeration via registration timing (new vs duplicate) | C2, C3 | Argon2id hash always computed on both paths (~150 ms equalizes them); same 201 response | Assert in `RegistrationControllerIT` that both paths respond within ±50 ms | **Low** |
| T-I2 | Email enumeration via resend endpoint (found vs not found) | C5 | Non-found and non-PENDING paths both return 200 silently (no email sent) | — | **Low** |
| T-I3 | Email addresses leaked in application logs | C3, C5, C9 | Not yet implemented | **REQUIRED:** All log statements must use email masking helper: `maskEmail(email)` returning `u***@example.com`. Never log raw email. | **High without mitigation; Low after** |
| T-I4 | Raw verification token leaked in logs | C3, C5 | Not yet implemented | **REQUIRED:** Never log `rawToken`; only log `tokenId` (the UUID PK of the `auth_tokens` row) | **High without mitigation; Low after** |
| T-I5 | `password_hash` returned in API response | C2 | DTOs exclude `passwordHash`; `User` entity never returned from controller | — | **Negligible** |
| T-I6 | Internal error details (stack traces, SQL, class names) leaked in API response | C2 | `GlobalExceptionHandler` maps all exceptions; `handleUnexpected` returns only generic message | Verify no new exception type escapes the handler without explicit mapping | **Low** |
| T-I7 | `auth_tokens.token_hash` exposed via DB read (insider threat) | C10 | SHA-256(raw bytes) stored — cannot be reversed to raw token; raw token has already been sent and consumed | — | **Low** |
| T-I8 | Verification email intercepted in transit | C9, C11 | HTTPS for API call; email transit encryption (STARTTLS) for MailHog/SMTP | Enforce `spring.mail.properties.mail.smtp.starttls.enable=true` in staging/prod config | **Med in transit; Low after STARTTLS** |

---

### D — Denial of Service

| ID | Threat | Component | Existing Mitigation | Required Mitigation | Residual Risk |
|----|--------|-----------|--------------------|--------------------|---------------|
| T-D1 | Mass registration (50 RPS+) to exhaust Argon2id threads / DB connections | C2, C3, C10 | Feature flag kill switch; Argon2id is also expensive for attacker (self-limiting); Spring thread pool bounds concurrency | Document recommended thread-pool sizing in deployment checklist; API gateway rate limiting (outside US-002 scope) | **Med** |
| T-D2 | Mass email flooding via repeat registration of known addresses | C3, C9 | Each request sends at most 1 email (verification or account-exists); resend throttle limits secondary floods | — | **Low** |
| T-D3 | Resend endpoint spam for known pending accounts → email flooding | C5 | AC-5: max 1/60s, 5/24h; 429 + `Retry-After` | — | **Low** |
| T-D4 | Very long password input sent to exhaust Argon2id memory | C2, C6 | `@Size(max=1024)` on password field prevents arbitrarily long inputs | Max 1024 chars is sufficient; document this limit in API contract (already in §7.1) | **Low** |
| T-D5 | `common-passwords.txt` causes OOM if file is very large | C9 infra, `PasswordPolicyConfig` | File is bounded (top-10k common passwords ≈ 80 KB); loaded once at startup into `HashSet<String>` | Verify file size before publishing; fail-fast if > 1 MB (guard in `PasswordPolicyConfig`) | **Low** |

---

### E — Elevation of Privilege

| ID | Threat | Component | Existing Mitigation | Required Mitigation | Residual Risk |
|----|--------|-----------|--------------------|--------------------|---------------|
| T-E1 | Account takeover via verification token brute-force | C4, C10 | 256-bit token entropy; SHA-256 stored; UNIQUE constraint; single-use | — | **Negligible** |
| T-E2 | Bypass email verification to access ACTIVE account directly | C4 | `UserStatus.PENDING` enforced at login (US-003 responsibility, but documented here as a dependency); `verify()` is the only state transition to ACTIVE | Ensure `verify()` method enforces `status == PENDING` invariant with `IllegalStateException` (already in design §4.1) | **Low** |
| T-E3 | Replay of a consumed verification token (race condition) | C4, C10 | Optimistic lock (`@Version`) on `AuthToken`; `consumed_at` checked in same transaction; second concurrent request sees version conflict | Test concurrent consumption in `VerificationTokenIT` with two threads | **Low** |
| T-E4 | Attacker skips consent checkbox (direct API call without `consentAccepted=true`) | C2, C3 | `@AssertTrue` on DTO → 400; use-case double-checks before creating user | — | **Negligible** |
| T-E5 | Feature flag bypass — accessing disabled endpoint | C2 | `@ConditionalOnProperty` removes bean; Spring MVC returns 404; no code path reachable | Verify in `RegistrationControllerIT` with flag=false | **Low** |
| T-E6 | `auth_events` tampered to erase audit trail | C10 | US-001 BEFORE UPDATE/DELETE triggers (`SIGNAL SQLSTATE '45000'`) prevent mutation | — | **Negligible** |
| T-E7 | Password policy bypass via whitespace/encoding tricks | C6 | `PasswordPolicyService` checks `rawPassword.length()` (char count, not byte count); no trimming before length check | Explicitly test Unicode characters; ensure `@Size(max=1024)` on DTO is byte-count aware (Spring's `@Size` counts chars, Java String — safe) | **Low** |

---

## 3. Threats Requiring Design Changes

The following threats require changes to `03-design.md` before implementation begins:

| ID | Change Required | Severity |
|----|----------------|----------|
| **T-S3** | Add `Strict-Transport-Security` header in `SecurityConfig` for non-local profiles | **Med** |
| **T-T3** | All log statements must sanitise CRLF and mask email (`u***@example.com`) — implement `LogMaskingUtil` in `common.web` | **Med** |
| **T-I3** | Same as T-T3 — email masking mandatory | **High** |
| **T-I4** | Never log `rawToken`; log `tokenId` (UUID of auth_tokens row) instead | **High** |
| **T-I8** | Require `spring.mail.properties.mail.smtp.starttls.enable=true` in staging/prod config | **Med** |

**Design verdict: no architectural redesign required.** The mitigations above are
implementation-level controls (config addition, logging discipline, a utility class) — they
do not change the sequence diagrams, API contract, or package structure in `03-design.md`.
They are added as explicit sub-tasks in the task breakdown (Phase 4).

---

## 4. Required Mitigations → Implementation Tasks

These must appear as explicit tasks in `04-tasks.md`:

| Task | Description |
|------|-------------|
| SEC-1 | Add `Strict-Transport-Security` header to `SecurityConfig` (conditional on non-local profile) |
| SEC-2 | Implement `LogMaskingUtil.maskEmail(String)` in `common.web` or `common.domain`; apply to all INFO/WARN log statements in registration use-cases and mail adapter |
| SEC-3 | In all use-cases: never log `rawToken`; only log `tokenId` (UUID of the saved `AuthToken`) |
| SEC-4 | Add `spring.mail.properties.mail.smtp.starttls.enable=true` and `starttls.required=true` to `application.yml` (active for all profiles except `smoke`/`test`) |
| SEC-5 | `RegistrationControllerIT`: assert both registration paths (new + duplicate) respond within ±50 ms of each other (anti-enumeration timing test) |
| SEC-6 | `VerificationTokenIT`: assert concurrent consumption of the same token — only one thread gets 200, the other gets 410 (optimistic lock test) |
| SEC-7 | `PasswordPolicyServiceTest`: assert Unicode passwords, whitespace-padded inputs, and passwords exactly at the boundary (11 chars → fail, 12 chars → pass) |

---

## 5. Security Acceptance Criteria

Before this feature is merged to `main`, the following must be green:

- [ ] `RegistrationControllerIT` timing assertion: both paths within ±50 ms (T-I1)
- [ ] `VerificationTokenIT` concurrent-consumption test: optimistic lock enforced (T-E3)
- [ ] No `rawToken` string appears in any log output (T-I4) — automated check in `RegistrationIT` by asserting log appender does not contain the token
- [ ] No raw email address in any log output (T-I3) — check in same IT
- [ ] `common-passwords.txt` loaded at startup; missing file causes startup failure (T-D5)
- [ ] Feature flag off → all 3 endpoints return 404 (T-E5)
- [ ] HSTS header present on all non-smoke responses (T-S3)

---

## 6. Residual Risks (accepted)

| Risk | Acceptance Rationale |
|------|---------------------|
| Email transit interception (T-I8) | STARTTLS required in prod config; full end-to-end email encryption (S/MIME, PGP) is out of scope for this story and this platform tier |
| Mass registration DoS at 50 RPS+ (T-D1) | Mitigated by Argon2id cost (self-limiting for attacker), feature flag kill switch, and future API gateway rate limiting (US-009+) |
| Common-password denylist staleness | Static list is updated per release cycle; HIBP integration planned for a future sprint behind the `BreachedPasswordPort` interface |
