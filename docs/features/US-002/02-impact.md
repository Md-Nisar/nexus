# Impact Analysis — US-002
## Enable Self-Service Registration with Email Verification

**Status:** APPROVED — Gate 1 passed; Q1–Q6 resolved  
**Date:** 2026-06-16  
**Author:** Principal Architect  
**Inputs:** `docs/features/US-002/01-requirements.md`, `docs/features/US-001/03-design.md`,
full codebase scan of `nexus-backend/` and `nexus-frontend/`

---

## 1. Backend Files — MODIFIED

| File | Change | Risk |
|------|--------|------|
| `nexus-backend/src/main/java/com/example/nexus/identity/domain/User.java` | Add `passwordHash` field (String, mapped `updatable=true`); add `verify(Instant)` state-transition method (PENDING→ACTIVE sets `emailVerifiedAt`); add constructor overload with `passwordHash` + `consentAcceptedAt` | **Med** — existing constructor callers (`UserTest`, `IdentitySchemaMigrationIT`, `UserUniquenessIT`, `EmailCipherEncryptionIT`) must be updated to supply the new required arguments |
| `nexus-backend/src/main/java/com/example/nexus/config/SecurityConfig.java` | Add `permitAll` for `/api/v1/auth/register`, `/api/v1/auth/verify-email`, `/api/v1/auth/resend-verification` | **Low** — additive; existing `anyRequest().authenticated()` fallback unchanged |
| `nexus-backend/src/main/java/com/example/nexus/common/web/GlobalExceptionHandler.java` | Add handler for new `FieldValidationException` → 400 with `details` array (field + message); add handler for new `TokenExpiredException` → 410 | **Low** — additive handler methods; existing handlers untouched |
| `nexus-backend/src/main/resources/application.yml` | Add `nexus.identity.default-tenant-id`, `nexus.identity.argon2.*` config keys; add `feature.nexus-us002-auth-registration.enabled: false`; add `spring.mail.*` keys (no prod default) | **Low** — additive config; fail-fast on missing required keys |
| `nexus-backend/src/main/resources/application-dev.yml` | Add MailHog SMTP config (`spring.mail.host: localhost`, `spring.mail.port: 1025`); add `feature.nexus-us002-auth-registration.enabled: true`; add `nexus.identity.default-tenant-id: <dev-uuid>`; add Argon2 dev params | **Low** — dev-only, no production effect |
| `nexus-backend/pom.xml` | Add `spring-boot-starter-mail` dependency | **Low** — standard Spring Boot starter; no transitive security concerns |
| `docker-compose.yml` | Add `mailhog` service (image: `mailhog/mailhog:v1.0.1`) with SMTP port 1025 and web UI port 8025 | **Low** — dev infrastructure only; additive |
| `nexus-backend/src/test/java/com/example/nexus/TestcontainersConfiguration.java` | Add `nexus.identity.default-tenant-id` and `nexus.identity.argon2.*` test properties to `DynamicPropertyRegistrar` | **Low** — test infrastructure only |

---

## 2. Backend Files — CREATED

### `identity.domain`

| File | Purpose |
|------|---------|
| *(no new domain files — all needed types already exist or are fields on `User`)* | |

### `identity.application`

| File | Purpose |
|------|---------|
| `identity/application/port/out/UserRegistrationPort.java` | Outbound port: `existsByTenantAndEmailHmac`, `save(User)`, `findByTenantAndEmailHmac` |
| `identity/application/port/out/AuthTokenPort.java` | Outbound port: `save(AuthToken)`, `findByTokenHash`, `countVerificationTokensSince` |
| `identity/application/port/out/MailSenderPort.java` | Outbound port: `sendVerificationEmail(String toEmail, String rawToken)`, `sendAccountExistsEmail(String toEmail)` |
| `identity/application/port/out/AuthEventPort.java` | Outbound port: `record(AuthEvent)` — fire-and-forget audit |
| `identity/application/RegisterUserUseCase.java` | Orchestrates: validate password → blind-index → check duplicate → hash password → persist User + AuthToken → fire mail (async) → record audit event; always runs Argon2id hash on both paths for anti-enumeration |
| `identity/application/VerifyEmailUseCase.java` | Loads token by SHA-256 hash → validates not consumed/expired → sets `consumed_at` + calls `user.verify()` in one `@Transactional` unit → records audit event |
| `identity/application/ResendVerificationUseCase.java` | Looks up user by email HMAC → checks status=PENDING → throttle checks (60s, 24h windows) → generates new token → sends mail → records audit event; non-PENDING / not-found paths return silently (anti-enumeration) |
| `identity/application/PasswordPolicyService.java` | Length ≥ 12 + breach denylist check; throws `FieldValidationException("AUTH_PWD_001")` |
| `identity/application/TokenGenerator.java` | `SecureRandom` 32-byte hex token generation |
| `identity/application/TokenHasher.java` | SHA-256(raw bytes) → 64-char hex; used by both issue and verify paths |

### `identity.infrastructure.persistence`

| File | Purpose |
|------|---------|
| `identity/infrastructure/persistence/JpaAuthTokenRepository.java` | `extends JpaRepository<AuthToken, UUID>`; `findByTokenHash`, `countByUserIdAndTypeAndCreatedAtAfter` |
| `identity/infrastructure/persistence/JpaAuthEventRepository.java` | `extends JpaRepository<AuthEvent, UUID>`; no custom methods needed (append-only via `save`) |
| `identity/infrastructure/persistence/JpaUserRegistrationAdapter.java` | Implements `UserRegistrationPort`; delegates to `JpaUserRepository` |
| `identity/infrastructure/persistence/JpaAuthTokenAdapter.java` | Implements `AuthTokenPort`; delegates to `JpaAuthTokenRepository` |
| `identity/infrastructure/persistence/JpaAuthEventAdapter.java` | Implements `AuthEventPort`; delegates to `JpaAuthEventRepository` |

### `identity.infrastructure.mail`

| File | Purpose |
|------|---------|
| `identity/infrastructure/mail/SmtpMailSenderAdapter.java` | Implements `MailSenderPort`; delegates to Spring's `JavaMailSender`; `@Async` methods; Thymeleaf or simple text templates |
| `identity/infrastructure/mail/LoggingMailSenderAdapter.java` | Implements `MailSenderPort`; `@Profile("test")` or `@ConditionalOnMissingBean`; logs email content masked |

### `identity.infrastructure.security`

| File | Purpose |
|------|---------|
| `identity/infrastructure/security/Argon2PasswordHasher.java` | Wraps `Argon2PasswordEncoder`; new `@Component` exposing `hash(String)` |
| `identity/infrastructure/security/PasswordPolicyConfig.java` | `@Configuration` loading `common-passwords.txt` classpath resource → `@Bean Set<String>` |
| `identity/infrastructure/security/PasswordEncoderConfig.java` | `@Bean Argon2PasswordEncoder` configured from `nexus.identity.argon2.*` properties |

### `identity.interfaces.rest` *(package created for first time)*

| File | Purpose |
|------|---------|
| `identity/interfaces/rest/RegistrationController.java` | `@RestController @RequestMapping("/api/v1/auth")`; 3 endpoints; `@ConditionalOnProperty` feature flag guard |
| `identity/interfaces/rest/dto/RegisterRequest.java` | `email`, `password`, `consentAccepted`; Bean Validation annotations |
| `identity/interfaces/rest/dto/RegisterResponse.java` | `message` field |
| `identity/interfaces/rest/dto/VerifyEmailRequest.java` | `token` (64-char hex) |
| `identity/interfaces/rest/dto/VerifyEmailResponse.java` | `message` field |
| `identity/interfaces/rest/dto/ResendVerificationRequest.java` | `email` |
| `identity/interfaces/rest/dto/ResendVerificationResponse.java` | `message` field |

### `common.domain` *(new shared exception types)*

| File | Purpose |
|------|---------|
| `common/domain/FieldValidationException.java` | `extends DomainException`; carries `field` name; `GlobalExceptionHandler` maps to 400 |
| `common/domain/TokenExpiredException.java` | `extends DomainException`; `GlobalExceptionHandler` maps to 410 |
| `common/domain/RateLimitException.java` | `extends DomainException`; carries `retryAfterSeconds`; `GlobalExceptionHandler` maps to 429 + `Retry-After` header |

### Resources

| File | Purpose |
|------|---------|
| `src/main/resources/security/common-passwords.txt` | Top-10k common passwords, one per line; loaded by `PasswordPolicyConfig` |
| `src/main/resources/db/migration/V3__add_password_hash_to_users.sql` | Adds `password_hash` column + new throttle index |

### New test files

| File | Purpose |
|------|---------|
| `identity/application/RegisterUserUseCaseTest.java` | Unit tests (mocked ports): happy path, duplicate email (same timing), password policy failure, consent missing |
| `identity/application/VerifyEmailUseCaseTest.java` | Unit: success, expired token, already consumed |
| `identity/application/ResendVerificationUseCaseTest.java` | Unit: success, throttle 60s, throttle 24h, non-pending account (silent) |
| `identity/application/PasswordPolicyServiceTest.java` | Unit: min-length, denylist hit, valid password |
| `identity/application/TokenGeneratorTest.java` | Unit: 64 chars, lowercase hex, distinct |
| `identity/application/TokenHasherTest.java` | Unit: deterministic, 64 chars, distinct input → distinct hash |
| `identity/infrastructure/persistence/RegistrationIT.java` | Integration (Testcontainers): full register flow, duplicate email, verify, resend throttle |
| `identity/interfaces/rest/RegistrationControllerIT.java` | `@SpringBootTest` web layer: HTTP contract, error codes, anti-enumeration timing, feature flag off → 404 |

---

## 3. Frontend Files — MODIFIED

| File | Change | Risk |
|------|--------|------|
| `nexus-frontend/src/app/app.routes.ts` | Add lazy-loaded `auth` route shell: `{ path: 'auth', loadChildren: () => import('./features/auth/auth.routes') }` | **Low** — additive route |
| `nexus-frontend/src/app/app.ts` | Add `RouterModule` or `RouterOutlet` import if not already present | **Low** — check required |

---

## 4. Frontend Files — CREATED

### Feature: `src/app/features/auth/`

| File | Purpose |
|------|---------|
| `features/auth/auth.routes.ts` | Child routes: `register` → `RegistrationFormComponent`, `verify-email` → `VerificationLandingComponent` |
| `features/auth/auth.service.ts` | `register()`, `verifyEmail()`, `resendVerification()` HTTP calls; wraps `AppError` |
| `features/auth/auth.service.spec.ts` | Vitest unit tests with `HttpClientTestingModule` |
| `features/auth/registration/registration-form.component.ts` | Smart component: reactive form (signals), submit handling, WCAG 2.1 AA |
| `features/auth/registration/registration-form.component.html` | Form template with `nx-input`, consent checkbox, `nx-button`, `PasswordStrengthMeterComponent` |
| `features/auth/registration/registration-form.component.scss` | Layout styles using `--nx-*` design tokens |
| `features/auth/registration/registration-form.component.spec.ts` | Vitest: form validation, submit states, error display, consent required |
| `features/auth/registration/password-strength-meter/password-strength-meter.component.ts` | Dumb component: input `password: string`, output score 0–4, text label + Material icon (no color-only — WCAG AC-7) |
| `features/auth/registration/password-strength-meter/password-strength-meter.component.spec.ts` | Vitest: score calculation, accessible label output |
| `features/auth/verification/verification-landing.component.ts` | Smart component: reads `?token=` query param, calls `authService.verifyEmail()`, renders success/error/expired states |
| `features/auth/verification/verification-landing.component.html` | Landing page template with `nx-card`, status states |
| `features/auth/verification/verification-landing.component.scss` | Layout using `--nx-*` tokens |
| `features/auth/verification/verification-landing.component.spec.ts` | Vitest: success, expired (410), already used |

---

## 5. Database Changes

### V3 migration — `V3__add_password_hash_to_users.sql`

```sql
-- V3__add_password_hash_to_users.sql
-- Adds password_hash column required by US-002 self-service registration.
-- Argon2id output fits comfortably in VARCHAR(255).
-- DEFAULT '' is a migration convenience: the users table is empty when V3 runs
-- (US-002 is the first registration flow). Rows with password_hash='' cannot
-- authenticate via any Argon2id verification.
-- Append-only migration (ADR-0003) — never edit after first apply.

ALTER TABLE users
    ADD COLUMN password_hash VARCHAR(255) NOT NULL DEFAULT '';

-- Throttle index for ResendVerificationUseCase rate-limit queries:
-- COUNT(*) WHERE user_id=? AND type='VERIFICATION' AND created_at > NOW()-INTERVAL ?
-- The existing idx_auth_tokens_user_id_type_consumed_at covers (user_id, type) but
-- not the created_at range scan; this index serves it optimally.
CREATE INDEX idx_auth_tokens_user_id_type_created_at
    ON auth_tokens (user_id, type, created_at);
```

**`ddl-auto=validate` alignment:**
- `password_hash VARCHAR(255) NOT NULL` ↔ `String passwordHash` in `User` entity — straightforward String mapping; no converter.
- New index is transparent to JPA validation.

**H2 smoke-test compatibility:**
- `VARCHAR(255) NOT NULL DEFAULT ''` is fully H2-compatible.
- Flyway is disabled on the `smoke` profile — H2 gets the column via `ddl-auto: create-drop` from the JPA mapping. Ensure `password_hash` field is mapped in `User` so H2 creates it.

---

## 6. Configuration Changes

### `nexus-backend/pom.xml`
```xml
<!-- Email sending — dev MailHog, prod SMTP (provider TBD) -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-mail</artifactId>
</dependency>
```

### `application.yml` additions
```yaml
# Default B2C tenant (resolved: Q1)
nexus:
  identity:
    default-tenant-id: ${NEXUS_IDENTITY_DEFAULT_TENANT_ID}  # required; no prod default

    # Argon2id parameters (OWASP 2023 minimum; resolved: Q6)
    argon2:
      memory-kb: ${NEXUS_ARGON2_MEMORY_KB:19456}      # 19 MiB
      iterations: ${NEXUS_ARGON2_ITERATIONS:2}
      parallelism: ${NEXUS_ARGON2_PARALLELISM:1}

# SMTP — required in every environment except test/smoke
spring:
  mail:
    host: ${MAIL_HOST}
    port: ${MAIL_PORT:587}
    username: ${MAIL_USERNAME:}
    password: ${MAIL_PASSWORD:}

# Feature flag (resolved: Q6 mechanics)
feature:
  nexus-us002-auth-registration:
    enabled: false   # default off; dev/staging override to true
```

### `application-dev.yml` additions
```yaml
nexus:
  identity:
    default-tenant-id: 00000000-0000-7000-8000-000000000001  # dev B2C tenant
    argon2:
      memory-kb: 4096    # reduced for dev speed; not production-safe
      iterations: 1
      parallelism: 1
spring:
  mail:
    host: localhost
    port: 1025           # MailHog SMTP
feature:
  nexus-us002-auth-registration:
    enabled: true
```

### `application-smoke.yml` addition
```yaml
nexus:
  identity:
    default-tenant-id: 00000000-0000-7000-8000-000000000001
    argon2:
      memory-kb: 4096
      iterations: 1
      parallelism: 1
spring:
  mail:
    host: localhost
    port: 1025
feature:
  nexus-us002-auth-registration:
    enabled: true
```

### `docker-compose.yml` addition
```yaml
  mailhog:
    image: mailhog/mailhog:v1.0.1
    container_name: nexus-mailhog
    ports:
      - "1025:1025"   # SMTP
      - "8025:8025"   # Web UI: http://localhost:8025
```

### `TestcontainersConfiguration.java` addition
```java
registry.add("nexus.identity.default-tenant-id",
    () -> "00000000-0000-7000-8000-000000000001");
registry.add("nexus.identity.argon2.memory-kb",  () -> "4096");
registry.add("nexus.identity.argon2.iterations", () -> "1");
registry.add("nexus.identity.argon2.parallelism", () -> "1");
registry.add("spring.mail.host", () -> "localhost");
registry.add("spring.mail.port", () -> "1025");
registry.add("feature.nexus-us002-auth-registration.enabled", () -> "true");
```

---

## 7. Existing Tests Affected

| Test | Impact | Action |
|------|--------|--------|
| `UserTest.java` | `User` constructor gains 2 new required args (`passwordHash`, `consentAcceptedAt`) | **Update** all `new User(...)` calls |
| `UserUniquenessIT.java` | Same constructor change | **Update** |
| `EmailCipherEncryptionIT.java` | Same constructor change | **Update** |
| `NexusApplicationIT.java` | Boot smoke now uses V3 schema; Testcontainers registrar needs new keys | **Update** registrar call + ensure `spring.mail.*` don't fail-fast in IT context |
| `IdentitySchemaMigrationIT.java` | V3 adds `password_hash` column + new index → checksum assertion covers V3 now | **Update** to assert V3 presence and `password_hash` column |
| `HexagonalArchitectureTest.java` | `identity.interfaces.rest` is the first `..interfaces..` package — all 5 ArchUnit rules become non-trivially active against it | **No change to the test** — controller must comply: no field injection, no `System.out`, no `java.util.logging`, no Spring Web in domain, no outer→inner imports from application |

---

## 8. Breaking Changes

**None.** US-002 is purely additive:
- V3 migration is additive (new column, new index).
- Three new public endpoints; no existing endpoint changes.
- `User` entity constructor change is internal; no public API contract broken.
- `SecurityConfig` change only adds `permitAll` rules; it does not restrict anything previously permitted.

The `User` constructor change is an **internal refactoring risk** (test breakage), not a breaking public-API change.

---

## 9. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| **Argon2id at 50 RPS exceeds p95 500 ms budget** | Med | High | Dev profile uses reduced params (m=4096, t=1) to prevent slow tests; IT suite uses same reduced params; performance test against OWASP params in dedicated `@Tag("perf")` IT; if budget is tight, reduce `parallelism=2` or increase thread pool (`spring.task.execution.pool.core-size`) |
| **Anti-enumeration timing drift** | Med | High | Both registration paths always run Argon2id hash; async email dispatch decoupled from response; `RegistrationControllerIT` asserts both paths respond within 50 ms of each other under load |
| **V3 migration on non-empty `users` table** | Low | Med | Table is empty when V3 first runs (US-002 introduces the first write path); `DEFAULT ''` handles hypothetical phantom rows; document in release checklist that V3 must run before any registration traffic |
| **`identity.interfaces` package ArchUnit activation** | Low | Med | `HexagonalArchitectureTest` rules use `allowEmptyShould(true)` — they were already active against US-001's packages. Creating `identity.interfaces.rest` is safe as long as the controller only imports `identity.application` ports and `common.*`. Field injection rule catches any accidental `@Autowired` field. |
| **H2 smoke-test `password_hash` column** | Low | Low | `VARCHAR(255) NOT NULL DEFAULT ''` is H2-compatible; Hibernate `create-drop` derives column from `String passwordHash` field mapping; smoke test will cover it on next `NexusSmokeTest` boot |
| **MailHog unavailability in IT context** | Med | Low | `LoggingMailSenderAdapter` activated in test profile — no real SMTP call in unit/IT tests; `SmtpMailSenderAdapter` only active in dev/staging |
| **`common-passwords.txt` classpath resource missing at startup** | Low | High | `PasswordPolicyConfig` must fail fast (throw `IllegalStateException`) if resource not found, same pattern as `IdentityCryptoConfig`; covered by `NexusSmokeTest` |

---

## 10. Resolved Design Decisions (Q1–Q6)

| # | Question | Resolution |
|---|----------|-----------|
| Q1 | B2C tenant ID | `nexus.identity.default-tenant-id` config property (UUID); fail-fast on missing; no request carries tenant |
| Q2 | Password breach check | Embedded `common-passwords.txt` (top-10k, classpath resource); `BreachedPasswordPort` interface deferred — logic stays inside `PasswordPolicyService` for now; HIBP swap is a later infrastructure swap |
| Q3 | Resend throttle storage | DB-based: query `auth_tokens` by `(user_id, type, created_at)` window; served by new `idx_auth_tokens_user_id_type_created_at` index added in V3 |
| Q4 | MailHog / mail starter | `spring-boot-starter-mail` added to pom.xml; MailHog service added to `docker-compose.yml`; `LoggingMailSenderAdapter` for test profile |
| Q5 | `password_hash` column default | `DEFAULT ''` in V3 migration; safe because table is empty; documented in release checklist |
| Q6 | Argon2id parameters | OWASP 2023 minimum (m=19456, t=2, p=1) in prod; reduced (m=4096, t=1, p=1) in dev/test via config props; exposed as `nexus.identity.argon2.*` |
