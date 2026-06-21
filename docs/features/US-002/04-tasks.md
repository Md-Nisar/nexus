# Task Breakdown — US-002
## Enable Self-Service Registration with Email Verification

**Status:** DRAFT — awaiting Gate 3 approval  
**Date:** 2026-06-16  
**Author:** Principal Architect  
**Inputs:** `docs/features/US-002/03-design.md` (approved),
`docs/features/US-002/03b-threat-model.md` (approved, SEC-1–7 folded in)

**Implementation convention:** test-first. Each task writes tests before or alongside
production code. Unit tests are part of every task's DoD. Integration tests are task T-019.

**Implementation command:** `/implement US-002 T-001` (then T-002, T-003, … in order).

---

## Dependency graph (implementation order)

```
T-001 ─────────────────────────────────────────────────────────────┐
T-002 ──────────────────────────────────────────────────────────┐  │
T-003 ──────────────────────────────────────────────────────┐   │  │
T-004 (LogMaskingUtil) ──────────────────────────────────┐  │   │  │
                                                          │  │   │  │
T-005 (SecurityConfig) ─────────────────────────────┐   │  │   │  │
T-006 (Infra config)  ──────────────────────────┐   │   │  │   │  │
                                                │   │   │  │   │  │
T-007 (Domain changes) ◄── T-001, T-006 ────┐  │   │  │   │  │
T-008 (Ports + events) ◄── T-007 ────────┐  │  │   │  │   │  │
T-009 (Security infra) ◄── T-006, T-008  │  │  │   │  │   │  │
T-010 (App utilities)  ◄── T-008         │  │  │   │  │   │  │
T-011 (Mail infra)     ◄── T-006, T-008  │  │  │   │  │   │  │
T-012 (Persistence)    ◄── T-007, T-008  │  │  │   │  │   │  │
T-013 (RegisterUC)     ◄── all above ────┤  │  │   │  │   │  │
T-014 (VerifyUC)       ◄── T-008,T-010,T-012,T-004
T-015 (ResendUC)       ◄── T-008,T-010,T-012,T-011,T-004
T-016 (Controller)     ◄── T-002,T-003,T-005,T-013,T-014,T-015
T-017 (FE service)     (parallel with backend)
T-018 (FE registration component) ◄── T-017
T-019 (FE verification component) ◄── T-017
T-020 (Backend ITs)    ◄── T-016
T-021 (Controller IT + security) ◄── T-020
T-022 (E2E Playwright) ◄── T-021
```

---

## Epic: US-002 — Self-Service Registration with Email Verification

---

### ── Database ──────────────────────────────────────────────────

---

#### T-001 · V3 Flyway Migration
**Complexity:** S

**Description:**  
Create `V3__add_password_hash_to_users.sql` adding the `password_hash` column to `users` and
the `idx_auth_tokens_user_id_type_created_at` index to `auth_tokens`. Also create the
`common-passwords.txt` classpath resource used by `PasswordPolicyService`.

**Dependencies:** none

**Files created:**
- `nexus-backend/src/main/resources/db/migration/V3__add_password_hash_to_users.sql`
- `nexus-backend/src/main/resources/security/common-passwords.txt` (top-10k common passwords, one per line, UTF-8)

**Files impacted:** none

**Risks:**
- `DEFAULT ''` on `NOT NULL` column must not cause `ddl-auto=validate` to fail — it will not;
  default value is a constraint, not a column type mismatch.
- `common-passwords.txt` must be present at startup or `PasswordPolicyConfig` throws
  `IllegalStateException`; verify in `NexusSmokeTest`.

**Testing requirements:**
- Unit: none (pure SQL/resource)
- Integration: `IdentitySchemaMigrationIT` — add assertion that V3 applied, `password_hash`
  column exists with type `VARCHAR(255)`, and new index is present in `information_schema`
- Smoke: `NexusSmokeTest` implicitly verifies `common-passwords.txt` loads (once T-009 wires it)

**Definition of Done:**
- [ ] Migration file is syntactically valid MySQL 8.4 DDL
- [ ] `common-passwords.txt` contains ≥ 1000 entries, no blank lines at end
- [ ] `IdentitySchemaMigrationIT` updated to assert V3 column + index
- [ ] `mvn verify -DskipITs` green (Flyway checksum stable)

---

### ── Backend / Cross-Cutting ───────────────────────────────────

---

#### T-002 · Common Exception Types + GlobalExceptionHandler Update
**Complexity:** S

**Description:**  
Add three new `DomainException` subclasses in `common.domain`: `FieldValidationException`
(→ 400 with `details`), `TokenExpiredException` (→ 410), `RateLimitException` (→ 429 +
`Retry-After` header). Add corresponding `@ExceptionHandler` methods to
`GlobalExceptionHandler`.

**Dependencies:** none

**Files impacted:**
- `nexus-backend/src/main/java/com/example/nexus/common/web/GlobalExceptionHandler.java`

**Files created:**
- `…/common/domain/FieldValidationException.java`
- `…/common/domain/TokenExpiredException.java`
- `…/common/domain/RateLimitException.java`

**Risks:**
- `RateLimitException` handler must return `ResponseEntity<ProblemDetail>` (not plain
  `ProblemDetail`) to set the `Retry-After` response header.
- New handlers must appear BEFORE the `Exception.class` catch-all in `GlobalExceptionHandler`
  (method ordering matters in `@RestControllerAdvice`).

**Testing requirements:**
- Unit: extend `GlobalExceptionHandlerTest` with three new test methods — one per exception
  type; assert HTTP status code, `code` field, and (for 429) `Retry-After` header value.

**Definition of Done:**
- [ ] `FieldValidationException` → 400 with `{ code, detail, details: [{field, message}] }`
- [ ] `TokenExpiredException` → 410 with `{ code, detail }`
- [ ] `RateLimitException` → 429 with `Retry-After: N` header and `{ code, detail }`
- [ ] `GlobalExceptionHandlerTest` covers all three new handlers
- [ ] ArchUnit: `common.domain` has no Spring Web import (new classes must not import `jakarta.servlet` or `org.springframework.web`)

---

#### T-003 · Infrastructure Configuration
**Complexity:** S

**Description:**  
Wire all configuration changes required before any application code can run: `pom.xml`
(mail starter), `application.yml` / `application-dev.yml` / `application-smoke.yml`
(Argon2 params, default tenant UUID, mail SMTP, frontend base URL, STARTTLS, feature flag),
`docker-compose.yml` (MailHog service), `TestcontainersConfiguration` (IT property overrides).

This task also adds the `spring.mail.properties.mail.smtp.starttls.enable=true` and
`starttls.required=true` properties (SEC-4) to base application.yml for staging/prod safety.

**Dependencies:** none

**Files impacted:**
- `nexus-backend/pom.xml`
- `nexus-backend/src/main/resources/application.yml`
- `nexus-backend/src/main/resources/application-dev.yml`
- `nexus-backend/src/test/resources/application-smoke.yml`
- `nexus-backend/src/test/java/com/example/nexus/TestcontainersConfiguration.java`
- `docker-compose.yml`

**Files created:** none

**Risks:**
- `spring-boot-starter-mail` pulls in Spring Mail autoconfiguration; if `spring.mail.host`
  is absent and `JavaMailSender` is not conditionally created, the smoke context may fail.
  Mitigate: add `spring.mail.host: localhost` to `application-smoke.yml`.
- Argon2id params in dev (m=4096, t=1) must NOT be used in staging/prod; enforce via env
  var overrides (`NEXUS_ARGON2_MEMORY_KB`, etc.) with no prod-safe default.

**Testing requirements:**
- Integration: `NexusApplicationIT` boot context must remain green after pom.xml change.
- Smoke: `NexusSmokeTest` must boot with new config keys present.

**Definition of Done:**
- [ ] `spring-boot-starter-mail` in `pom.xml`; `mvn verify -DskipITs` compiles
- [ ] All new `application.yml` keys documented with inline comments
- [ ] MailHog service in `docker-compose.yml` with SMTP port 1025, UI port 8025
- [ ] `TestcontainersConfiguration` registers all new IT properties
- [ ] STARTTLS properties present in base `application.yml` (SEC-4)
- [ ] `NexusApplicationIT` and `NexusSmokeTest` remain green

---

#### T-004 · LogMaskingUtil  *(SEC-2, SEC-3)*
**Complexity:** S

**Description:**  
Implement `LogMaskingUtil` in `com.example.nexus.common.web` with two static helpers:
- `maskEmail(String email)` → `"u***@example.com"` pattern from `observability-standards.md`
- `sanitizeCrlf(String input)` → replaces `\r` and `\n` with `_` (log injection prevention)

This utility is a prerequisite for all use-cases and adapters that log email addresses or
user-supplied input (SEC-2 / SEC-3). Raw tokens must never be logged — this is enforced by
code review, not by a utility.

**Dependencies:** none

**Files created:**
- `nexus-backend/src/main/java/com/example/nexus/common/web/LogMaskingUtil.java`

**Files impacted:** none

**Risks:**
- `maskEmail` must handle edge cases: no `@` sign, single-char local part, null input.
- Must be a `final` class with a private constructor (utility class — same pattern as
  `AuthConstants`); ArchUnit `no_field_injection` rule is not at risk but double-check.

**Testing requirements:**
- Unit: `LogMaskingUtilTest` — `alice@example.com` → `a***@example.com`;
  `a@b.com` → `a***@b.com`; no `@` sign → unchanged; null → null;
  CRLF in input → `_` substitution.

**Definition of Done:**
- [ ] `maskEmail` + `sanitizeCrlf` implemented and tested
- [ ] `LogMaskingUtilTest` covers edge cases
- [ ] No dependency on Spring or external libraries (pure JDK)

---

### ── Backend / Domain ───────────────────────────────────────────

---

#### T-005 · User Entity Changes + AuthToken Factory
**Complexity:** M

**Description:**  
Extend `User` entity with `passwordHash` field, 6-arg constructor (replacing the 4-arg
constructor), and `verify(Instant)` state-transition method. Add `forVerification()` static
factory to `AuthToken`. Update all existing tests that call the old 4-arg constructor.

**Dependencies:** T-001 (confirms `password_hash` column exists in schema)

**Files impacted:**
- `nexus-backend/src/main/java/com/example/nexus/identity/domain/User.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/domain/AuthToken.java`
- `nexus-backend/src/test/java/com/example/nexus/identity/domain/UserTest.java`
- `nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/persistence/UserUniquenessIT.java`
- `nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/persistence/EmailCipherEncryptionIT.java`
- `nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/persistence/UserQueryPerformanceIT.java`

**Files created:** none

**Risks:**
- `verify()` must throw `IllegalStateException` (not a `DomainException`) if called on
  non-PENDING user — this is an internal invariant violation, not a user-facing error.
- `passwordHash` must not appear in `User.toString()` (Lombok's `@Getter` does not affect
  `toString` — `@ToString` is not on the class, so this is safe by default; confirm Lombok
  config does not add it).
- Changing the constructor signature will fail compilation immediately — CI enforces this.

**Testing requirements:**
- Unit: `UserTest` — assert 6-arg constructor sets all fields; `verify()` transitions
  PENDING→ACTIVE and sets `emailVerifiedAt`; `verify()` on ACTIVE throws
  `IllegalStateException`; `AuthTokenTest` — `forVerification()` factory sets correct type.
- Integration: all modified IT classes must still pass with updated constructor calls.

**Definition of Done:**
- [ ] `User` has `passwordHash` field (no setter, `@Column(nullable=false)`)
- [ ] `User` has 6-arg constructor; 4-arg constructor removed
- [ ] `User.verify(Instant)` enforces PENDING→ACTIVE invariant
- [ ] `AuthToken.forVerification(...)` factory method added
- [ ] All existing tests updated and green
- [ ] `ddl-auto=validate` alignment: `password_hash VARCHAR(255)` ↔ `String passwordHash`

---

### ── Backend / Application ──────────────────────────────────────

---

#### T-006 · Application Ports + Domain Events
**Complexity:** S

**Description:**  
Define all outbound ports and application events. These are pure interfaces / records — no
implementation. They form the contract between application and infrastructure layers.

Ports: `UserRegistrationPort`, `AuthTokenPort`, `PasswordHasherPort`, `AuthEventPort`.  
Events: `VerificationEmailEvent`, `AccountExistsEmailEvent`.

**Dependencies:** T-005 (domain types must exist to reference in port signatures)

**Files created:**
- `…/identity/application/port/out/UserRegistrationPort.java`
- `…/identity/application/port/out/AuthTokenPort.java`
- `…/identity/application/port/out/PasswordHasherPort.java`
- `…/identity/application/port/out/AuthEventPort.java`
- `…/identity/application/event/VerificationEmailEvent.java`
- `…/identity/application/event/AccountExistsEmailEvent.java`

**Files impacted:** none

**Risks:**
- All classes in `identity.application.*` must not import anything from
  `identity.infrastructure.*` or `identity.interfaces.*`; ArchUnit `application_must_not_depend_on_adapters` will catch violations immediately.
- `PasswordHasherPort` is a `@FunctionalInterface` (one abstract method `hash(String)`);
  confirm Spring can wire `Argon2PasswordEncoder::encode` as a lambda.

**Testing requirements:**
- Compile-time: ArchUnit test verifies no application→infrastructure dependency.
- No runtime tests needed at this stage (contracts only).

**Definition of Done:**
- [ ] 4 ports defined with correct method signatures matching design §5.1
- [ ] 2 event records defined with correct fields
- [ ] ArchUnit passes with new packages added to the analysis scope
- [ ] No import of Spring Web, infrastructure, or interfaces in any application class

---

#### T-007 · Application Utility Services
**Complexity:** S

**Description:**  
Implement three stateless application-layer services:
- `TokenGenerator`: `SecureRandom` 32-byte hex generation (64-char raw token)
- `TokenHasher`: SHA-256(raw bytes) → 64-char hex (stored hash)
- `PasswordPolicyService`: length ≥ 12 + breach denylist check; throws
  `FieldValidationException("AUTH_PWD_001", "password", "...")`

`PasswordPolicyService` receives `Set<String> commonPasswordSet` via constructor injection
(the `@Bean` produced by `PasswordPolicyConfig` in T-010).

**Dependencies:** T-006 (ports exist; `FieldValidationException` exists via T-002)

**Files created:**
- `…/identity/application/TokenGenerator.java`
- `…/identity/application/TokenHasher.java`
- `…/identity/application/PasswordPolicyService.java`

**Files impacted:** none

**Risks:**
- `TokenGenerator` must use `new SecureRandom()` as an instance field (thread-safe after
  construction; avoid static because `SecureRandom` seeding may block once).
- `TokenHasher.hash(String rawToken)` must accept the 64-char hex string, parse it back to
  32 bytes, then SHA-256 the raw bytes — not the hex string — for consistency with generation.
- `PasswordPolicyService` checks exact case (`rawPassword` not lowercased) for denylist;
  denylist file contains entries as-is.

**Testing requirements:**
- Unit: `TokenGeneratorTest` — 64 chars, lowercase hex regex, 1000 calls yield distinct tokens.
- Unit: `TokenHasherTest` — deterministic (same input → same hash), 64-char hex output,
  distinct inputs → distinct hashes.
- Unit: `PasswordPolicyServiceTest` — 11-char password → `AUTH_PWD_001`; 12-char → pass;
  denylist entry → `AUTH_PWD_001`; non-denylist 12-char → pass; Unicode char counting
  (Java `String.length()` counts UTF-16 code units; `"ñ".length() == 1` — document this);
  null input → `AUTH_PWD_001`; password at max boundary (1024 chars) → pass.

**Definition of Done:**
- [ ] All three services `@Service` annotated, constructor-injected, no field injection
- [ ] Unit tests green with ≥ 85% line coverage on these three classes
- [ ] `SHA-256` not using a shared mutable `MessageDigest` (fresh instance per call)
- [ ] `PasswordPolicyService` does not import any infrastructure class

---

### ── Backend / Infrastructure ───────────────────────────────────

---

#### T-008 · Security Infrastructure
**Complexity:** S

**Description:**  
- `PasswordEncoderConfig`: `@Bean Argon2PasswordEncoder` from `nexus.identity.argon2.*`
  properties; `@Bean PasswordHasherPort` that wraps `encoder::encode`.
- `PasswordPolicyConfig`: `@Bean Set<String>` loaded from `classpath:/security/common-passwords.txt`;
  fail-fast if resource not found (`IllegalStateException`).
- Add `@EnableAsync` on a `@Configuration` (either on `PasswordEncoderConfig` or a new
  `AsyncConfig`) to enable `@Async` support for `MailEventListener`.

**Dependencies:** T-003 (config properties present), T-006 (PasswordHasherPort interface)

**Files created:**
- `…/identity/infrastructure/security/PasswordEncoderConfig.java`
- `…/identity/infrastructure/security/PasswordPolicyConfig.java`

**Files impacted:** none (or add `@EnableAsync` to existing config class)

**Risks:**
- `PasswordPolicyConfig` produces a `Set<String>` bean; if any other `Set<String>` bean
  exists in the context, Spring will complain about ambiguous injection. Qualify with
  `@Qualifier("commonPasswordSet")` on both the bean and the `PasswordPolicyService`
  constructor parameter.
- `@EnableAsync` must be present exactly once in the application context.

**Testing requirements:**
- Unit: `PasswordEncoderConfigTest` — bean creation with valid properties; `hash()` returns
  an Argon2id-prefixed string (`{argon2}`); different calls produce different salts
  (non-deterministic).
- Integration: `NexusApplicationIT` implicitly validates these beans wire correctly.

**Definition of Done:**
- [ ] `Argon2PasswordEncoder` bean configured from `nexus.identity.argon2.*` props
- [ ] `PasswordHasherPort` bean wires as `encoder::encode`
- [ ] `PasswordPolicyConfig` fails fast if `common-passwords.txt` absent
- [ ] `@EnableAsync` present exactly once
- [ ] `NexusSmokeTest` remains green

---

#### T-009 · Mail Infrastructure
**Complexity:** M

**Description:**  
- `SmtpMailSenderAdapter`: implements `MailSenderPort`; delegates to Spring's `JavaMailSender`;
  builds `SimpleMailMessage` for both verification and account-exists emails; constructs
  the verification URL from `nexus.frontend.base-url`; `@ConditionalOnMissingBean(LoggingMailSenderAdapter.class)`.
- `LoggingMailSenderAdapter`: implements `MailSenderPort`; `@Profile("test")` (or
  `@ConditionalOnProperty(name="spring.mail.host", havingValue="disabled", matchIfMissing=true)`);
  logs masked email + token placeholder (never logs `rawToken`).
- `MailEventListener`: `@Component`; `@Async @TransactionalEventListener(AFTER_COMMIT)` on
  both `onVerificationEmail` and `onAccountExists`; injects `MailSenderPort`.

**Dependencies:** T-003 (mail config present), T-006 (event types), T-008 (`@EnableAsync`)

**Files created:**
- `…/identity/infrastructure/mail/SmtpMailSenderAdapter.java`
- `…/identity/infrastructure/mail/LoggingMailSenderAdapter.java`
- `…/identity/infrastructure/mail/MailEventListener.java`

**Files impacted:** none

**Risks:**
- `rawToken` must NEVER appear in any log statement in `MailEventListener` or either adapter.
  Use `maskEmail(toEmail)` in log lines; omit token entirely (SEC-3).
- `@Async` on a `@TransactionalEventListener` method requires the method to return `void`
  (or `Future<Void>`); Spring will warn and behave unexpectedly with return types.
- In IT tests, `SmtpMailSenderAdapter` will attempt a real SMTP connection to `localhost:1025`
  (MailHog). If MailHog is not running in IT context, mail send will fail silently in `@Async`
  context (exception in async thread does not propagate to test). Use `LoggingMailSenderAdapter`
  in the IT profile instead.

**Testing requirements:**
- Unit: `MailEventListenerTest` (with mocked `MailSenderPort`) — `onVerificationEmail` calls
  `sendVerificationEmail`; `onAccountExists` calls `sendAccountExistsEmail`; async execution
  (assert returns immediately without blocking).
- Unit: `SmtpMailSenderAdapterTest` — verify `SimpleMailMessage` fields are set correctly
  (to address, subject, body contains verification URL but not raw token in log).

**Definition of Done:**
- [ ] `MailSenderPort` injected into `MailEventListener` (not `JavaMailSender` directly)
- [ ] `rawToken` appears in email body (correct) but never in any log statement
- [ ] `LoggingMailSenderAdapter` active in test/smoke profiles
- [ ] `MailEventListener` methods are `void` return type

---

#### T-010 · Persistence Adapters
**Complexity:** M

**Description:**  
Create Spring Data repositories for `AuthToken` and `AuthEvent`, then create adapter classes
implementing the application outbound ports.

- `JpaAuthTokenRepository`: `findByTokenHash(String)`, `countByUserIdAndTypeAndCreatedAtAfter(UUID, AuthTokenType, Instant)`
- `JpaAuthEventRepository`: no custom methods (only `save`)
- `JpaUserRegistrationAdapter` implements `UserRegistrationPort`: delegates to existing `JpaUserRepository`
- `JpaAuthTokenAdapter` implements `AuthTokenPort`: delegates to `JpaAuthTokenRepository`; `markConsumed` sets `consumedAt` and saves
- `JpaAuthEventAdapter` implements `AuthEventPort`: delegates to `JpaAuthEventRepository`

**Dependencies:** T-005 (entity changes), T-006 (port interfaces)

**Files created:**
- `…/identity/infrastructure/persistence/JpaAuthTokenRepository.java`
- `…/identity/infrastructure/persistence/JpaAuthEventRepository.java`
- `…/identity/infrastructure/persistence/JpaUserRegistrationAdapter.java`
- `…/identity/infrastructure/persistence/JpaAuthTokenAdapter.java`
- `…/identity/infrastructure/persistence/JpaAuthEventAdapter.java`

**Files impacted:** none

**Risks:**
- `JpaAuthTokenRepository.countByUserIdAndTypeAndCreatedAtAfter` uses Spring Data method
  name derivation; verify the derived query generates the correct JPQL
  (`WHERE user_id = ?1 AND type = ?2 AND created_at > ?3`).
- `markConsumed` must use optimistic locking — simply load, set field, save; if
  `OptimisticLockException` is thrown (concurrent consumption), callers must handle it as
  a consumed-token scenario (410). Documented in `JpaAuthTokenAdapter` Javadoc.
- `JpaAuthEventAdapter.record()` must catch and log (WARN) any persistence exception — audit
  failure must not propagate to the caller and roll back a user-facing transaction.

**Testing requirements:**
- Unit: `JpaUserRegistrationAdapterTest`, `JpaAuthTokenAdapterTest` — mock repositories,
  verify delegation; `markConsumed` sets `consumedAt`.
- Integration: `RegistrationIT` (T-020) exercises all adapters end-to-end.

**Definition of Done:**
- [ ] All 5 classes created; `@Component` annotations present; constructor injection only
- [ ] `JpaAuthEventAdapter.record()` swallows persistence exceptions with WARN log
- [ ] `countByUserIdAndTypeAndCreatedAtAfter` verified via derived query (no `@Query` needed)
- [ ] ArchUnit: no application class imports these adapters

---

### ── Backend / Application (Use-Cases) ─────────────────────────

---

#### T-011 · `RegisterUserUseCase`
**Complexity:** L

**Description:**  
Implement the core registration use-case. Orchestrates: password policy validation →
email blind-index → Argon2id hash (both paths) → duplicate check → user creation OR
account-exists event → token creation → verification email event → audit.

Key invariants:
- Argon2id hash is computed on EVERY call regardless of duplicate check result
- `consentAcceptedAt` is always `Instant.now()` (server clock — never from client)
- Email is encrypted (`TextEncryptor.encrypt`) before constructing `EmailCipher`
- Both registration paths (`new user` and `duplicate`) return void; controller always responds 201

**Dependencies:** T-006, T-007, T-008, T-009, T-010, T-004 (LogMaskingUtil)

**Files created:**
- `…/identity/application/RegisterUserUseCase.java`

**Files impacted:** none

**Risks:**
- The `TextEncryptor` bean is in `identity.infrastructure.crypto`. The use-case must not
  import it directly. Wrap it behind a port or inject as `org.springframework.security.crypto.encrypt.TextEncryptor` (a Spring Security interface, not infrastructure). This is acceptable — Spring Security is a framework dependency, not an infrastructure adapter.
- `@Transactional` on `register()` covers user insert + token insert; email event is
  published but only dispatched AFTER_COMMIT (async). If the transaction rolls back, no
  email is sent.

**Testing requirements:**
- Unit: `RegisterUserUseCaseTest` — mock all ports:
  - Happy path: user saved, token saved, `VerificationEmailEvent` published
  - Duplicate path: no user saved, no token saved, `AccountExistsEmailEvent` published
  - Password policy failure: `FieldValidationException` thrown before any port call
  - Missing consent: caught by Bean Validation in controller (not tested here)
  - Verify `passwordHasher.hash()` called exactly once in both paths (anti-enumeration)
  - Verify `emailBlindIndexService.blindIndex()` called with normalised email

**Definition of Done:**
- [ ] `@Service @Transactional` on `RegisterUserUseCase`
- [ ] `passwordHasher.hash(rawPassword)` called before duplicate check
- [ ] `consentAcceptedAt` set to `Instant.now()` server-side
- [ ] Both paths publish exactly one event and nothing else to the mail channel
- [ ] All log statements use `LogMaskingUtil.maskEmail()` + `sanitizeCrlf()`; no raw email or token in logs
- [ ] Unit tests cover both paths + password-policy failure

---

#### T-012 · `VerifyEmailUseCase`
**Complexity:** M

**Description:**  
Implement token verification. Derives SHA-256 hash of raw token, looks up `auth_tokens`,
validates not expired and not consumed, atomically marks consumed and transitions user
PENDING→ACTIVE. All failure paths return the same `AUTH_VRF_002` message (anti-enumeration
for token states).

**Dependencies:** T-006, T-007, T-010, T-004

**Files created:**
- `…/identity/application/VerifyEmailUseCase.java`

**Files impacted:** none

**Risks:**
- Optimistic lock conflict on `AuthToken` (concurrent consumption by two parallel requests
  for the same token) must be caught and re-thrown as `TokenExpiredException("AUTH_VRF_002")`
  — the second caller should see 410, not 500.
- Uniform 410 message across all failure cases (not found, expired, consumed) is intentional
  — document in class Javadoc.

**Testing requirements:**
- Unit: `VerifyEmailUseCaseTest` — success; token not found → 410; token expired → 410;
  token consumed → 410; user not found after token lookup → 410 (defensive).
- Integration: `VerificationTokenIT` (T-020) — includes concurrent consumption test (SEC-6).

**Definition of Done:**
- [ ] `@Service @Transactional` on `VerifyEmailUseCase`
- [ ] `OptimisticLockException` on `markConsumed` caught and converted to `TokenExpiredException`
- [ ] All failure paths produce identical `AUTH_VRF_002` message
- [ ] `VERIFICATION_SUCCESS` / `VERIFICATION_FAILED` audit events written
- [ ] Unit tests cover all four failure paths

---

#### T-013 · `ResendVerificationUseCase`
**Complexity:** M

**Description:**  
Implement resend with anti-enumeration and two-window throttle. Non-PENDING accounts and
unknown emails return silently (void, no event, no exception). PENDING accounts that exceed
the 60s or 24h window get `RateLimitException("AUTH_RES_001", ..., retryAfterSeconds)`.

**Dependencies:** T-006, T-007, T-010, T-009 (mail event), T-004

**Files created:**
- `…/identity/application/ResendVerificationUseCase.java`

**Files impacted:** none

**Risks:**
- Anti-enumeration: the method must return normally (not throw) for non-existent / non-PENDING
  accounts. The controller returns 200 in all non-throttle cases.
- `retryAfterSeconds` for the 60s window should be a fixed 60; for the 24h window it can be
  3600 (conservative). Computing the exact seconds-until-reset requires an extra DB query;
  fixed values are simpler and acceptable (AC-5 only requires the header to be present).

**Testing requirements:**
- Unit: `ResendVerificationUseCaseTest` — success (event published); 2nd call within 60s →
  429; 6th call within 24h → 429; unknown email → void (no event); ACTIVE account → void;
  LOCKED account → void.

**Definition of Done:**
- [ ] `@Service @Transactional` on `ResendVerificationUseCase`
- [ ] Non-PENDING and not-found paths return without publishing any event
- [ ] Throttle: 60s window checked first; 24h window checked second
- [ ] `RESEND_THROTTLED` audit event written on both throttle scenarios
- [ ] Unit tests cover 6 scenarios

---

### ── Backend / Interfaces ───────────────────────────────────────

---

#### T-014 · SecurityConfig Update  *(SEC-1)*
**Complexity:** S

**Description:**  
Add `permitAll` for the three registration endpoints. Add `Strict-Transport-Security` header
via `HeadersConfigurer` for non-local profiles (SEC-1).

**Dependencies:** none (independent of use-case implementations)

**Files impacted:**
- `nexus-backend/src/main/java/com/example/nexus/config/SecurityConfig.java`

**Risks:**
- HSTS should be conditional: `@Profile("!local & !smoke")` or check
  `server.ssl.enabled=true`; do not apply in smoke/H2 contexts where HTTPS is not available.
- Ensure the path matcher for new endpoints exactly matches the controller's
  `@RequestMapping` — any mismatch causes 401 instead of 404 when flag is off.

**Testing requirements:**
- Unit: extend `SecurityConfigTest` (if it exists) or add to `RegistrationControllerIT`:
  assert unauthenticated requests to the 3 endpoints are not blocked by Spring Security
  (i.e., reach the controller).

**Definition of Done:**
- [ ] `permitAll` for `/api/v1/auth/register`, `/api/v1/auth/verify-email`, `/api/v1/auth/resend-verification`
- [ ] HSTS header present on responses in non-smoke profiles
- [ ] Existing `anyRequest().authenticated()` fallback unchanged
- [ ] All existing security tests pass

---

#### T-015 · `RegistrationController` + DTOs
**Complexity:** M

**Description:**  
Create the first `identity.interfaces.rest` class. Three endpoints, six DTOs, OpenAPI
annotations, `@ConditionalOnProperty` feature flag guard.

DTOs use Bean Validation:
- `RegisterRequest`: `@NotBlank @Email` on email, `@NotBlank @Size(max=1024)` on password,
  `@AssertTrue(message="Consent is required to register.")` on `consentAccepted`
- `VerifyEmailRequest`: `@NotBlank @Pattern(regexp="[0-9a-f]{64}")` on token
- `ResendVerificationRequest`: `@NotBlank @Email` on email

Responses are plain records (no JPA entity exposure).

**Dependencies:** T-002, T-003, T-011, T-012, T-013, T-014

**Files created:**
- `…/identity/interfaces/rest/RegistrationController.java`
- `…/identity/interfaces/rest/dto/RegisterRequest.java`
- `…/identity/interfaces/rest/dto/RegisterResponse.java`
- `…/identity/interfaces/rest/dto/VerifyEmailRequest.java`
- `…/identity/interfaces/rest/dto/VerifyEmailResponse.java`
- `…/identity/interfaces/rest/dto/ResendVerificationRequest.java`
- `…/identity/interfaces/rest/dto/ResendVerificationResponse.java`

**Files impacted:** none

**Risks:**
- `@ConditionalOnProperty` at class level: when `feature.nexus-us002-auth-registration.enabled=false`,
  the bean is absent — Spring MVC returns 404. Verify this is consistent with `SecurityConfig`
  (`permitAll` applies to path patterns; no bean means no handler → Spring returns 404, not 403).
- DTOs must be records or classes with no JPA annotations. Never expose `User` or `AuthToken`
  from any controller method.
- `@Valid` on `@RequestBody` parameters is required for Bean Validation to activate.

**Testing requirements:**
- Unit: none at this layer (controller logic is trivial delegation).
- Integration: `RegistrationControllerIT` (T-021) covers the HTTP contract end-to-end.

**Definition of Done:**
- [ ] `@ConditionalOnProperty` on class; flag off → 404 confirmed in IT
- [ ] `@Valid @RequestBody` on all three endpoint parameters
- [ ] All six DTOs are records (or final classes); no JPA annotations
- [ ] OpenAPI `@Operation` + `@ApiResponse` annotations on all endpoints
- [ ] No entity class returned from any controller method
- [ ] ArchUnit: `interfaces.rest` does not import `infrastructure` packages

---

### ── Frontend ────────────────────────────────────────────────────

---

#### T-016 · `AuthService` + Route Shell
**Complexity:** S

**Description:**  
Create `AuthService` (`register`, `verifyEmail`, `resendVerification` returning
`Observable<void>`), `auth.routes.ts` (two lazy routes), and update `app.routes.ts`.
All HTTP calls go through existing `apiErrorInterceptor`; components receive `AppError`,
never `HttpErrorResponse`.

**Dependencies:** none (can run parallel with backend after T-003)

**Files created:**
- `nexus-frontend/src/app/features/auth/auth.service.ts`
- `nexus-frontend/src/app/features/auth/auth.service.spec.ts`
- `nexus-frontend/src/app/features/auth/auth.routes.ts`

**Files impacted:**
- `nexus-frontend/src/app/app.routes.ts`
- `nexus-frontend/src/app/app.ts` (add `RouterOutlet` if absent)

**Risks:**
- `HttpClient` must be injected, not imported; tests use `provideHttpClientTesting()`.
- `resendVerification` response body may be `{message: "..."}` — map to `void` cleanly.

**Testing requirements:**
- Unit: `auth.service.spec.ts` — mock HTTP; assert each method calls the correct URL and
  HTTP verb; assert `AppError` is thrown on 4xx/5xx (via interceptor, not service).

**Definition of Done:**
- [ ] Three service methods returning `Observable<void>`
- [ ] Routes lazy-loaded; no eager imports of feature components in `app.routes.ts`
- [ ] Vitest unit tests green with `provideHttpClientTesting()`

---

#### T-017 · `RegistrationFormComponent` + `PasswordStrengthMeterComponent`
**Complexity:** M

**Description:**  
Smart container (`RegistrationFormComponent`) with signals state machine (`idle` →
`submitting` → `success` / `error`), reactive `FormGroup`, field-level error display via
`aria-describedby`, and a dumb `PasswordStrengthMeterComponent`.

Strength meter: score 0–4 based on length ≥ 12, uppercase, digit, special char. Conveys
level via text label + Material icon. Color bars are supplementary only (WCAG AC-7).

**Dependencies:** T-016

**Files created:**
- `…/features/auth/registration/registration-form.component.ts`
- `…/features/auth/registration/registration-form.component.html`
- `…/features/auth/registration/registration-form.component.scss`
- `…/features/auth/registration/registration-form.component.spec.ts`
- `…/features/auth/registration/password-strength-meter/password-strength-meter.component.ts`
- `…/features/auth/registration/password-strength-meter/password-strength-meter.component.spec.ts`

**Files impacted:** none

**Risks:**
- `@AssertTrue` on `consentAccepted` (backend) must be mirrored as `Validators.requiredTrue`
  on the frontend FormControl; mismatch causes confusing UX.
- WCAG AC-7: axe must report zero critical issues; test with `@axe-core/playwright` in E2E
  (T-022) or manually during review.
- Server-side field errors from `details[].field` must map to the correct `FormControl`
  to show inline error (e.g., `details[0].field === "password"` → set error on password
  control).

**Testing requirements:**
- Unit: `registration-form.component.spec.ts` — form invalid without consent; submit
  disabled while `submitting`; `success` state shown after `register()` resolves; `error`
  state with field errors shown after rejection; strength meter receives password value.
- Unit: `password-strength-meter.component.spec.ts` — score 0 for empty, 1 for `abc123`,
  4 for `Str0ng!Pass99`; aria-label contains text level; icon changes with score.

**Definition of Done:**
- [ ] Standalone component; no NgModule
- [ ] Signals for `state` and `error`; `@if`/`@switch` for template control flow
- [ ] `aria-describedby` links input to error paragraph for each field
- [ ] Strength meter uses text + icon (not color alone)
- [ ] No `any` types
- [ ] Vitest specs green; no `console.error` in test output

---

#### T-018 · `VerificationLandingComponent`
**Complexity:** S

**Description:**  
Smart component. Reads `?token=` from `ActivatedRoute` query params signal. On init, calls
`authService.verifyEmail(token)`. Renders three states: `verifying` (spinner), `success`
(check icon + "You can now log in" + link to `/auth/login`), `error` (icon + message;
if 410 `AUTH_VRF_002`, offer a resend link).

**Dependencies:** T-016

**Files created:**
- `…/features/auth/verification/verification-landing.component.ts`
- `…/features/auth/verification/verification-landing.component.html`
- `…/features/auth/verification/verification-landing.component.scss`
- `…/features/auth/verification/verification-landing.component.spec.ts`

**Risks:**
- Token absent from query params (user navigated directly) → show `error` state immediately
  with "Invalid verification link" message.
- Component uses `ActivatedRoute.snapshot.queryParams['token']` or `toSignal(route.queryParams)`
  — use the signals-based approach (Angular 21).

**Testing requirements:**
- Unit: `verification-landing.component.spec.ts` — `verifying` state on init; success
  state after resolve; 410 error shows resend option; missing token shows error immediately.

**Definition of Done:**
- [ ] Standalone component; signals state machine
- [ ] Token read from route query param (not from injectable service)
- [ ] 410 `AUTH_VRF_002` specifically shows resend link; other errors show generic message
- [ ] No `any` types
- [ ] Vitest specs green

---

### ── Tests ───────────────────────────────────────────────────────

---

#### T-019 · Backend Unit Test Suite (consolidated)
**Complexity:** M

**Description:**  
Verify all new application-layer and infrastructure classes at the unit level (no Spring
context, no DB). Each class under test has its dependencies mocked. This task consolidates
unit tests that weren't written inline with their implementation tasks (i.e., those that
require cross-class orchestration to test meaningfully).

Key additional assertions (security requirements from threat model):
- **SEC-5 (timing):** `RegisterUserUseCaseTest` already asserts `passwordHasher.hash()` is
  called on both paths. The real timing assertion (±50 ms) is in T-021 (controller IT).
- **SEC-7 (Unicode password boundary):** `PasswordPolicyServiceTest` must assert 11-char
  Unicode password (`"ñ".repeat(11)`) fails; 12-char passes.

**Dependencies:** T-007, T-011, T-012, T-013 (all use-cases and services implemented)

**Files impacted:** all `*Test.java` files created inline with T-007–T-013

**Risks:**
- Mocking `ApplicationEventPublisher` to verify event type published — use `ArgumentCaptor`.
- `@Transactional` in unit tests has no effect (no Spring context); verify transactional
  semantics in IT tests (T-020).

**Definition of Done:**
- [ ] All use-case unit tests passing
- [ ] JaCoCo: `identity.application` ≥ 85% line coverage
- [ ] No Spring context started in any `*Test.java` (all use `@ExtendWith(MockitoExtension.class)`)
- [ ] SEC-7: Unicode boundary test in `PasswordPolicyServiceTest`

---

#### T-020 · Backend Integration Tests
**Complexity:** L

**Description:**  
Full-stack integration tests using Testcontainers MySQL. Tests exercise the complete call chain from use-case through persistence to the real DB.

Test classes:
- **`RegistrationIT`**: register new user (status=PENDING, token row created); register duplicate
  (same 201, no new user row); V3 `password_hash` column validates under `ddl-auto=validate`.
- **`VerificationTokenIT`**: verify valid token (status→ACTIVE, `consumed_at` set,
  `email_verified_at` set); verify expired token (→ 410); verify consumed token (→ 410);
  **concurrent consumption (SEC-6)**: two threads consume same token simultaneously — assert
  exactly one succeeds and one gets 410.
- **`ResendVerificationIT`**: resend for new account (token created); 2nd within 60s (→ 429);
  6th within 24h (→ 429).
- **`IdentitySchemaMigrationIT` (update)**: assert V3 applied (`password_hash` column,
  `idx_auth_tokens_user_id_type_created_at` index).

**Dependencies:** T-003, T-005, T-010, T-011, T-012, T-013 (all backend complete)

**Files created:**
- `…/identity/infrastructure/persistence/RegistrationIT.java`
- `…/identity/infrastructure/persistence/VerificationTokenIT.java`
- `…/identity/infrastructure/persistence/ResendVerificationIT.java`

**Files impacted:**
- `…/identity/infrastructure/persistence/IdentitySchemaMigrationIT.java`

**Risks:**
- Concurrent consumption test (SEC-6) requires `CountDownLatch` or `CompletableFuture` to
  coordinate two threads; `@Transactional` on use-case ensures atomicity, but the test must
  run outside a shared transaction.
- Mail sends in IT context go to `LoggingMailSenderAdapter` (no real SMTP); use
  `@Profile("test")` or `@Primary` override in test config.
- Argon2id at IT params (m=4096, t=1) keeps test time reasonable; log warning if real params
  used accidentally.

**Definition of Done:**
- [ ] `RegistrationIT` green (new user, duplicate, V3 schema)
- [ ] `VerificationTokenIT` green including concurrent-consumption SEC-6 test
- [ ] `ResendVerificationIT` green (throttle both windows)
- [ ] `IdentitySchemaMigrationIT` updated and green
- [ ] `mvn verify` (with Docker) fully green

---

#### T-021 · Controller IT + Security Assertions
**Complexity:** M

**Description:**  
`@SpringBootTest(webEnvironment=RANDOM_PORT)` tests for the full HTTP contract plus
security-specific assertions.

- HTTP 201 for new registration; 201 for duplicate; 400 for policy failure; 400 for
  missing consent; 404 when feature flag off (SEC — T-E5).
- **SEC-5 (anti-enumeration timing):** time both registration paths 50 times each; assert
  `|mean_new - mean_dup| < 50ms` (use reduced Argon2 params in IT).
- 200 for valid verify; 410 for expired/consumed.
- 200 for resend (found/not-found); 429 for throttle with `Retry-After` header.
- Assert `Retry-After` header present and numeric on 429.
- **No raw email in logs (T-I3):** capture `ListAppender<ILoggingEvent>` and assert no log
  event contains the test email address verbatim.
- **No raw token in logs (T-I4):** assert no log event contains the 64-char hex raw token.

**Dependencies:** T-015, T-020

**Files created:**
- `…/identity/interfaces/rest/RegistrationControllerIT.java`

**Risks:**
- Timing test can be flaky under CI load; wrap in `@DisabledOnOs` for known-slow environments
  or increase tolerance to ±100 ms on CI and document why.
- Log assertion requires a configured test `ListAppender` or `CapturingAppender` on the
  root logger — add via `logback-test.xml` override.

**Definition of Done:**
- [ ] All HTTP contracts asserted
- [ ] SEC-5 timing assertion (both paths within ±50 ms at test params)
- [ ] SEC feature-flag-off → 404 confirmed
- [ ] Log assertions: no raw email, no raw token
- [ ] `Retry-After` header present on 429 responses

---

#### T-022 · E2E Playwright Test — Happy Path
**Complexity:** M

**Description:**  
Browser-level E2E test (Playwright) covering the golden path:
1. Navigate to `/auth/register`
2. Fill email, password (≥ 12 chars, strong), check consent → submit
3. Assert "check your email" success state shown
4. (If MailHog is available in E2E context) fetch verification link from MailHog API
5. Navigate to the verification link
6. Assert "Email verified" success page
7. Axe accessibility scan on the registration form (WCAG 2.1 AA — AC-7)

**Dependencies:** T-017, T-018, T-020

**Files created:**
- `nexus-frontend/e2e/auth/registration.e2e.ts` (or `*.spec.ts` per Playwright convention)

**Risks:**
- MailHog API polling in E2E requires the full stack to be running with MailHog. Mark test
  `@tag('e2e')` and skip in unit CI; run in dedicated E2E CI lane.
- Axe scan requires `@axe-core/playwright`; add as dev dependency.
- Password strength meter color-only check: Playwright cannot automatically detect this;
  review manually or check computed ARIA attributes.

**Testing requirements:**
- Playwright `test()` with `axe().analyze()` — assert zero critical violations on
  `/auth/register`.

**Definition of Done:**
- [ ] Happy-path E2E test green in local E2E run
- [ ] Axe scan: zero critical violations on registration form (AC-7)
- [ ] Test tagged appropriately for CI gating

---

### ── Documentation ───────────────────────────────────────────────

---

#### T-023 · Release Notes + Env-Var Documentation
**Complexity:** S

**Description:**  
Update `docs/features/US-002/` with operational artifacts: new env vars required, rollout
procedure, smoke-test checklist, flag removal criteria. Reference the feature-flag rollout
plan from `03-design.md §13`.

**Dependencies:** T-021 (all green)

**Files created:**
- `docs/features/US-002/05-release-notes.md` (env vars, rollout plan, smoke tests, flag removal)

**Definition of Done:**
- [ ] All new required env vars documented with purpose, example value, which envs need them
- [ ] Rollout plan (1% → 10% → 50% → 100%) documented
- [ ] Smoke-test checklist: `POST /api/v1/auth/register`, verify MailHog receives email,
  click link → 200
- [ ] Flag removal criteria: ≥ 24h at 100% with error rate < 0.1%

---

## Task Summary

| ID | Title | Complexity | Deps | Phase |
|----|-------|------------|------|-------|
| T-001 | V3 Flyway Migration | S | — | DB |
| T-002 | Common Exception Types | S | — | Backend/Cross-cutting |
| T-003 | Infrastructure Configuration | S | — | Backend/Cross-cutting |
| T-004 | LogMaskingUtil | S | — | Backend/Cross-cutting |
| T-005 | User Entity + AuthToken Factory | M | T-001 | Backend/Domain |
| T-006 | Application Ports + Events | S | T-005 | Backend/Application |
| T-007 | Application Utility Services | S | T-002, T-006 | Backend/Application |
| T-008 | Security Infrastructure | S | T-003, T-006 | Backend/Infrastructure |
| T-009 | Mail Infrastructure | M | T-003, T-006, T-008 | Backend/Infrastructure |
| T-010 | Persistence Adapters | M | T-005, T-006 | Backend/Infrastructure |
| T-011 | `RegisterUserUseCase` | L | T-004, T-006, T-007, T-008, T-009, T-010 | Backend/Application |
| T-012 | `VerifyEmailUseCase` | M | T-004, T-006, T-007, T-010 | Backend/Application |
| T-013 | `ResendVerificationUseCase` | M | T-004, T-006, T-007, T-009, T-010 | Backend/Application |
| T-014 | SecurityConfig Update | S | — | Backend/Interfaces |
| T-015 | RegistrationController + DTOs | M | T-002, T-003, T-011, T-012, T-013, T-014 | Backend/Interfaces |
| T-016 | Frontend AuthService + Routes | S | — | Frontend |
| T-017 | RegistrationFormComponent + StrengthMeter | M | T-016 | Frontend |
| T-018 | VerificationLandingComponent | S | T-016 | Frontend |
| T-019 | Backend Unit Test Suite | M | T-007–T-013 | Tests |
| T-020 | Backend Integration Tests | L | T-003, T-005, T-010–T-013 | Tests |
| T-021 | Controller IT + Security Assertions | M | T-015, T-020 | Tests |
| T-022 | E2E Playwright Test | M | T-017, T-018, T-020 | Tests |
| T-023 | Release Notes + Env-Var Docs | S | T-021 | Documentation |

**Total tasks: 23**  
**Recommended parallel streams:**
- Stream A (backend): T-001 → T-002 → T-003 → T-004 → T-005 → T-006 → T-007 → T-008 → T-009 → T-010 → T-011 → T-012 → T-013 → T-014 → T-015
- Stream B (frontend): T-016 → T-017 → T-018 (can start after T-003 unblocks config)
- Stream C (tests): T-019 → T-020 → T-021 → T-022 → T-023 (after backend complete)

---

*Jira sub-tasks: Atlassian MCP is not connected. To create matching sub-tasks under US-002,
connect the MCP (`claude mcp add atlassian npx -- @atlassian/mcp-server`) and re-run this
skill — it will offer to create them automatically.*
