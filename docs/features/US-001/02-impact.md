# Impact Analysis — US-001

**Status:** Complete
**Feature:** US-001 — Establish tenant-aware identity data model and migrations
**Date:** 2026-06-14

---

## 1. Executive Summary

US-001 introduces the first real bounded context (`com.example.nexus.identity`) into a backend that
currently contains only cross-cutting scaffolding (`common`, `config`) and a comment-only Flyway
baseline (`V1__baseline.sql`). The change is **purely additive at the schema and package level** —
no existing table, column, class, or endpoint is modified — which keeps backward-compatibility risk
near zero. The non-trivial risk concentrates in three places:

1. **The four ArchUnit / JaCoCo gates that are currently dormant activate the moment the `identity`
   package is created.** This is by design (pom.xml anticipates it), but it means the first context
   must land with its full test suite or the build breaks.
2. **Crypto + secrets bootstrap.** `email_cipher` (AES-256-GCM) and `email_hmac` (HMAC-SHA256)
   require encryption/HMAC keys to be present at application startup in every environment. No key
   wiring exists today.
3. **The H2 smoke-test profile.** `application-test.properties` disables Flyway and uses
   `create-drop`; the MySQL-specific migration (BINARY(16), ENUM, triggers, SIGNAL) only ever
   executes under Testcontainers. The H2 context test (`NexusBackendApplicationTests`) will attempt
   JPA `validate`/`create-drop` against the new entities and must not break.

No frontend changes. No API changes. No new endpoints. Two ADRs (ADR-001 UUIDv7, ADR-002
blind-index + encryption) are **conditions of done**, not follow-ups, and ADR-001 explicitly
overrides `docs/coding-standards.md` line 29 ("prefer CHAR(26) ULID").

---

## 2. Backend Impact

### 2a. New files (by layer)

All under `nexus-backend/src/main/java/com/example/nexus/identity/`.

**`identity.domain`** (JaCoCo ≥ 90% line)

| Class | Responsibility |
|-------|----------------|
| `com.example.nexus.identity.domain.User` | JPA `@Entity` for `users`. Holds `email_cipher` (encrypted via converter), `email_hmac` (read-only — not entity-writable per FR-011), status, token_version, lockout fields, audit columns. UUIDv7 `id` as BINARY(16). |
| `com.example.nexus.identity.domain.RefreshToken` | `@Entity` for `refresh_tokens`. `token_hash`, `family_id`, `expires_at`, `revoked_at`. |
| `com.example.nexus.identity.domain.AuthToken` | `@Entity` for `auth_tokens`. `type` enum (VERIFICATION/RESET), `token_hash`, `consumed_at`. |
| `com.example.nexus.identity.domain.AuthEvent` | `@Entity` for `auth_events`. No `updated_at` (NFR-009). Append-only at DB layer. |
| `com.example.nexus.identity.domain.UserStatus` | Enum `PENDING / ACTIVE / LOCKED / DISABLED` mapped to the column ENUM. |
| `com.example.nexus.identity.domain.AuthTokenType` | Enum `VERIFICATION / RESET`. |
| `com.example.nexus.identity.domain.AuthConstants` | `AUTH_REFRESH_TOKEN_TTL_DAYS = 7` (FR-013). Also verification/reset TTLs. **Design flag:** a constants-only holder may not contribute to the 90% domain gate — see §5b. |

**`identity.application`** (JaCoCo ≥ 85% line)

| Class | Responsibility |
|-------|----------------|
| `com.example.nexus.identity.application.EmailBlindIndexService` | `HMAC-SHA256(LOWER(email), hmac_secret_key)` → hex (FR-003, NFR-003). Deterministic; key from vault/env. Unit-testable core for test scenarios 8 & 9. **Layer placement is a design question** (see §9) — stateless and deterministic (domain-like) but consumes an injected secret (application/policy-like). |

**`identity.infrastructure`** (JaCoCo ≥ 70% line)

| Class | Responsibility |
|-------|----------------|
| `com.example.nexus.identity.infrastructure.persistence.AttributeEncryptor` | JPA `@Converter` for `email_cipher`; delegates to `TextEncryptor` from `Encryptors.stronger()` (FR-010, FR-011, NFR-002). |
| `com.example.nexus.identity.infrastructure.persistence.UuidV7Converter` | `@Converter` for BINARY(16) ↔ `java.util.UUID`. Shared by all four entities. |
| `com.example.nexus.identity.infrastructure.crypto.IdentityCryptoConfig` | Spring `@Configuration` producing the `TextEncryptor` bean from env-sourced encryption password + salt. Key bootstrap — affects every IT. |
| `com.example.nexus.identity.infrastructure.persistence.JpaUserRepository` | Spring Data repository. *May be deferred to US-002 — design decision §9; the NFR-001 1M-row performance test may justify it now.* |

**`identity.interfaces`** — **none in US-001.** Package not created; `*.interfaces.rest` JaCoCo rule
stays dormant (correct behaviour).

**Resources**

| File | Purpose |
|------|---------|
| `nexus-backend/src/main/resources/db/migration/V2__identity_schema.sql` | Single-script Flyway migration creating all 4 tables + triggers. |

### 2b. Modified files

| File | Change | Risk |
|------|--------|------|
| `nexus-backend/pom.xml` | Add `com.github.f4b6a3:uuid-creator` (pinned) and explicit `org.springframework.security:spring-security-crypto`. JaCoCo per-layer rules and ArchUnit rules **activate** as a consequence. | LOW (edit) / MEDIUM (activation) |
| `nexus-backend/src/main/resources/application.yml` | Add `${ENV_VAR}` config keys for encryption password, salt, HMAC key under a `nexus.identity.*` namespace. No prod defaults. Comment each key per coding-standards §Configuration. | MEDIUM — missing key = fast-fail startup in all environments |
| `nexus-backend/src/main/resources/application-dev.yml` | Dev-only non-secret placeholder keys so `spring-boot:run` works locally without a vault. Must be clearly marked dev-only. | MEDIUM — risk of weak key leaking into a shared environment |
| `nexus-backend/src/test/resources/application-test.properties` | Provide test-only encryption/HMAC keys so the H2 context can build the encryptor bean. Flyway stays disabled; entities map against H2 `create-drop`. **Risk:** H2 has no BINARY(16) ↔ UUID, no MySQL ENUM, no `SIGNAL` — entities must map cleanly or the smoke test breaks. | **HIGH** — most likely silent breakage |
| `nexus-backend/src/test/java/com/example/nexus/NexusBackendApplicationTests.java` | No code change strictly required, but new entities will be discovered by Hibernate on the H2 profile. Must survive H2 `create-drop` or crypto keys must be provided as test properties. | **HIGH** — same root cause as above |
| `nexus-backend/src/test/java/com/example/nexus/NexusApplicationIT.java` | Implicitly validates V2 migration + JPA `validate` against new entities. Fails to boot if crypto keys are absent. Needs test keys via `@DynamicPropertySource` or a test config. | MEDIUM |
| `docs/coding-standards.md` (line 29) | Update ULID preference to point to ADR-001 (UUIDv7). Required by FR-012 to remove the standing contradiction. | LOW (doc only) |

**Files explicitly NOT modified:** `SecurityConfig.java`, `OpenApiConfig.java`, `CorrelationIdFilter.java`,
`GlobalExceptionHandler.java`, `DomainException` hierarchy, `app.routes.ts`, `app.config.ts`, any
frontend file.

### 2c. New Flyway migration — `V2__identity_schema.sql`

Must contain in order:

1. `CREATE TABLE users` — 14 columns per §6 of requirements; PK `id` BINARY(16); `status` ENUM with DEFAULT 'PENDING'; `email_cipher` TEXT NOT NULL; `email_hmac` VARCHAR(64) NOT NULL; `ON UPDATE CURRENT_TIMESTAMP` for `updated_at`. Indexes: `idx_users_tenant_id_email_hmac` (UNIQUE), `idx_users_tenant_id_status`.
2. `CREATE TABLE refresh_tokens` — FK `fk_refresh_tokens_users → users.id`. Indexes: `UNIQUE (token_hash)`, `idx_refresh_tokens_user_id_revoked_at`, `idx_refresh_tokens_family_id`.
3. `CREATE TABLE auth_tokens` — FK `fk_auth_tokens_users → users.id`; `type` ENUM. Indexes: `UNIQUE (token_hash)`, `idx_auth_tokens_user_id_type_consumed_at`.
4. `CREATE TABLE auth_events` — no FK (nullable user_id/tenant_id, no tenant table). Indexes: `idx_auth_events_user_id_created_at`, `idx_auth_events_tenant_id_created_at`, `idx_auth_events_event_type_created_at`.
5. Two triggers: `BEFORE UPDATE ON auth_events` and `BEFORE DELETE ON auth_events`, each `SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'auth_events is append-only'`.

**Migration watch items:**
- Trigger delimiter handling under flyway-mysql (most fragile SQL in the migration — §9 item 7).
- All index names must be within MySQL's 64-char identifier limit.
- `ddl-auto=validate` alignment: every entity mapping must exactly match the migrated column (ENUM, BINARY(16), nullability, length).
- File is frozen on first application (ADR 0003 append-only). The pre-included columns (`token_version`, `email_verified_at`, `failed_attempt_count`, `locked_until`) exist specifically to preserve the freeze.

### 2d. New pom.xml dependencies

| Dependency | Scope | Justification | License |
|------------|-------|---------------|---------|
| `com.github.f4b6a3:uuid-creator` | compile | UUIDv7 generation (ADR-001). No JDK-native UUIDv7 in Java 25. Pin explicit version; add to ADR-001 BOM entry. | MIT |
| `org.springframework.security:spring-security-crypto` | compile | `Encryptors.stronger()` + `KeyGenerators`. Currently transitive via `spring-boot-starter-security`. Making it explicit documents direct use; omit `<version>` to stay BOM-aligned. | Apache 2.0 |

---

## 3. Frontend Impact

**None.** `nexus-frontend/` is untouched. No new components, routes, services, guards, state, or
`APP_CONFIG` keys. The `auth_events` schema is a future consumer for EPIC-007 (Audit Log UI) but
that is downstream, not US-001.

---

## 4. Test Infrastructure Impact

### 4a. New integration tests needed

All `*IT` use Testcontainers MySQL 8.4 (`TestcontainersConfiguration` already wired).

| Test class | Type | Covers |
|------------|------|--------|
| `…identity.infrastructure.IdentitySchemaMigrationIT` | Integration | AC-1, AC-4, AC-6 / Scenario 1 — fresh MySQL → migrations → assert 4 tables + columns + indexes; Flyway checksum stable |
| `…identity.infrastructure.UserUniquenessIT` | Integration | AC-2 / Scenarios 2, 3 — duplicate `email_hmac` same tenant → constraint violation; different tenant → both persist |
| `…identity.infrastructure.EmailCipherEncryptionIT` | Integration / Security | AC-3 / Scenario 4 — persist user, read raw `email_cipher` via native query → ciphertext, not plaintext |
| `…identity.infrastructure.AuthEventsAppendOnlyIT` | Integration / Security | AC-5 / Scenarios 5, 6 — UPDATE and DELETE each raise SQLSTATE '45000'; row unchanged |
| `…identity.application.EmailBlindIndexServiceTest` | Unit | Scenarios 8, 9 — determinism and distinctness of HMAC output |
| `…identity.infrastructure.UserQueryPerformanceIT` | Performance | NFR-001 / Scenario 7 — 1M-row fixture, `(tenant_id, email_hmac)` lookup < 10 ms p95. **Heavyweight** — may need dedicated tag to run outside standard CI gate. |

### 4b. Changes to existing test infrastructure

| File | Change | Risk |
|------|--------|------|
| `TestcontainersConfiguration.java` | Likely no container change. May need a companion `@DynamicPropertySource` mechanism or shared base IT class to inject encryption/HMAC test keys. | MEDIUM |
| `NexusApplicationIT.java` | Now implicitly exercises V2 + JPA `validate`. Needs test keys present or it won't boot. | MEDIUM |
| `application-test.properties` | Must provide test keys and survive identity entity mapping under H2 `create-drop`, or identity must be excluded from the H2 component scan. | **HIGH** |
| `HexagonalArchitectureTest.java` | No edit required, but its rules **go live** — see §5a. |  |

---

## 5. Cross-cutting Concerns

### 5a. ArchUnit — rules go live

The four `allowEmptyShould(true)` rules were passing vacuously. `identity` is the first non-empty
bounded context; they now have real classes to evaluate. They pass **only if**:

- `domain` entities do not import `infrastructure` (the `AttributeEncryptor`, `UuidV7Converter`
  live in `infrastructure.persistence`). **Critical tension:** JPA entities reference
  `@Convert(converter = AttributeEncryptor.class)` — the entity in `domain` then references a class
  in `infrastructure`, which **violates rule 1**. This is the single most likely ArchUnit failure
  and must be resolved explicitly in the design (§9 item 1).
- `domain` does not import `org.springframework.web` / `jakarta.servlet` (safe — entities use
  `jakarta.persistence`).
- No field injection, no `System.out`, no `java.util.logging`.

### 5b. JaCoCo — per-layer rules activate

| Layer | Gate | Risk |
|-------|------|------|
| `identity.domain` | ≥ 90% | `AuthConstants` (constants-only), enums, Lombok-generated accessors can leave uncovered lines. Plan entity/enum behaviour tests or Lombok-aware coverage config. |
| `identity.application` | ≥ 85% | Covered by `EmailBlindIndexServiceTest`. |
| `identity.infrastructure` | ≥ 70% | Covered by IT suite exercising converters. |
| `identity.interfaces.rest` | ≥ 80% | **Dormant** — package not created in US-001. |
| Bundle | ≥ 80% | Entity boilerplate without matching tests could drag the bundle below 80%. |

### 5c. Checkstyle / SpotBugs

- **Checkstyle:** Watch line length in crypto code and Javadoc on the public `EmailBlindIndexService`
  port (coding-standards line 64 requires Javadoc on public ports).
- **SpotBugs:** Crypto code is a SpotBugs magnet — possible flags on `Encryptors`/HMAC usage,
  hardcoded-key false positives, or `Mac` reuse patterns. Expect possible findings on
  `AttributeEncryptor` / `EmailBlindIndexService` requiring correct patterns or justified
  suppressions.
- **`AuthConstants`** with only a private constructor is a common SpotBugs/Checkstyle nit (`final
  class`, private ctor pattern).

---

## 6. Breaking Changes

**None at runtime or API level.** The change set is purely additive:
- No existing table, column, or index altered or dropped.
- No existing Java class signature changed.
- No endpoint, DTO, or contract changed.
- No frontend contract changed.

**Build-time gate activations** (ArchUnit and JaCoCo per-layer rules going live) are intended
behaviour, not regressions — but they will fail the build if the new code arrives without its full
test suite or with an unresolved `domain → infrastructure` converter dependency.

**Documentation contradiction to resolve (not a code break):** `docs/coding-standards.md` line 29
("prefer CHAR(26) ULID") is superseded by ADR-001 (UUIDv7). FR-012 makes ADR-001 a condition of
done; the standard must be updated to reference it.

---

## 7. Dependency Chain (what US-001 unblocks)

| Story / Epic | What it needs from US-001 |
|---|---|
| US-002 (registration) | `users.email_verified_at`, `auth_tokens` (VERIFICATION), `consent_accepted_at` — pre-included |
| US-003 (JWT issuance) | `users.token_version` — pre-included (OQ-004) |
| US-004 / US-005 (refresh / logout) | `refresh_tokens`, `family_id`, `AuthConstants.AUTH_REFRESH_TOKEN_TTL_DAYS = 7` |
| US-006 (lockout) | `users.failed_attempt_count`, `users.locked_until` — pre-included |
| US-007 / US-008 | `auth_tokens` (RESET), `auth_events` append-only schema |
| EPIC-007 (Audit Log UI) | `auth_events` schema contract — must be stable from US-001 onward |

---

## 8. Top Risks (ordered by severity)

| # | Risk | Severity | Mitigation (for design phase) |
|---|------|----------|-------------------------------|
| 1 | **`domain → infrastructure` ArchUnit violation via `@Convert`** | HIGH | Decide converter placement (domain / infrastructure / `autoApply`) explicitly in §3 design before any code. |
| 2 | **H2 smoke-test profile breakage** | HIGH | Decide: make entities H2-tolerant + provide test keys, OR scope identity out of the H2 smoke context. Pick one approach. |
| 3 | **Crypto / HMAC key bootstrap absent everywhere** | HIGH | Design the `${ENV_VAR}` key contract, dev/test placeholder keys, and IT `@DynamicPropertySource` injection in §3. |
| 4 | **MySQL trigger SQL in Flyway** | MEDIUM-HIGH | Validate trigger syntax against flyway-mysql; `AuthEventsAppendOnlyIT` is the guardrail. |
| 5 | **JaCoCo 90% domain gate on boilerplate/constants** | MEDIUM | Plan entity/enum tests; consider JaCoCo exclusions only with justification. |
| 6 | **ADR-001 / ADR-002 sign-off gates the merge** | MEDIUM | Draft both in parallel pre-sprint — they are conditions of done, not follow-ups. |
| 7 | **`ddl-auto=validate` entity-column mismatch** | MEDIUM | Lock entity mappings to the §6 column list precisely; IT catches any drift. |
| 8 | **HMAC key rotation re-hashes all `email_hmac` values** | LOW-MED | Document rotation runbook in ADR-002 (required). |
| 9 | **`uuid-creator` not yet on approved dependency list** | MEDIUM | Add to ADR-001 BOM; verify MIT licence + clean `-Psecurity` CVE scan. |

---

## 9. Open Items for Design Phase

1. **Converter placement vs. hexagonal purity (Risk #1).** Where do `AttributeEncryptor` and
   `UuidV7Converter` live so that `domain` entities can use `@Convert` without a
   `domain → infrastructure` import? Options: converters in `domain`, `autoApply = true`
   registration, or a split where the entity field type is abstract and the converter is registered
   separately. This is the binding architectural decision of US-001.
2. **`EmailBlindIndexService` layer.** `domain` or `application`? Placement decides which JaCoCo
   gate (90% vs 85%) applies.
3. **Repositories in US-001 or deferred to US-002?** No use cases exist yet, but the NFR-001 1M-row
   performance test needs a query path. Decide whether `UserRepository` lands now or the perf test
   uses `EntityManager`.
4. **`email_hmac` non-writability mechanism (FR-011).** Exact JPA strategy so the entity setter
   cannot write a raw email-derived value; only `EmailBlindIndexService` populates it.
5. **H2 smoke-test strategy (Risk #2).** One approach, documented.
6. **Key bootstrap contract (Risk #3).** Env-var names, `Encryptors.stronger(password, salt)`
   parameters, dev/test placeholder keys, IT injection, and HMAC key rotation runbook (ADR-002).
7. **Trigger SQL form (Risk #4).** Confirm flyway-mysql handles `CREATE TRIGGER … SIGNAL` without
   explicit `DELIMITER`; settle the exact SQL shape.
8. **`AuthConstants` coverage (Risk #5).** Confirm whether a constants class can meet the 90%
   domain gate or needs structural decisions.
9. **UUIDv7 generation seam.** Where is UUIDv7 minted (entity factory, application service,
   generator bean) so it stays testable with an injected generator (not `new` per forbidden patterns).
10. **`identity.interfaces` package.** Confirm it is simply not created in US-001 (keeps
    `*.interfaces.rest` JaCoCo rule dormant), rather than created empty.
