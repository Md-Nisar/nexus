# Implementation Task Breakdown — US-001

**Feature:** US-001 — Establish tenant-aware identity data model and migrations
**Source design:** `docs/features/US-001/03-design.md` (APPROVED, Gate 2 passed)
**Source threat model:** `docs/features/US-001/03b-threat-model.md` (SEC-T1–T10 folded in below)
**Date:** 2026-06-14

> All file paths are absolute from the repo root `C:\entomo\AI\nexus`. Backend package root: `com.example.nexus.identity.{domain, application, infrastructure.persistence, infrastructure.crypto}`.

> **Scope note:** Story AC #1 references `password_hash` and `identity_provider` columns on `users`.
> Both are **intentionally deferred** per the approved technical design (section 4a):
> `password_hash` arrives in the US-002 Argon2id migration; `identity_provider` is a future-epic
> column. This does not represent a gap in US-001 — it is a recorded design decision.

## Sequencing summary (critical path)

```
T-001 (pom deps) ─┐
T-002 (migration) ─┼─► T-010..T-014 (domain entities/enums/value types/port/constants) ─┐
                   │                                                                      │
T-001 ────────────►├─► T-020 (IdentityCryptoConfig) ─► T-021 (AttributeEncryptor) ───────┤
                   │                                  └► T-022 (EmailBlindIndexService) ──┤
                   ├─► T-023 (UuidV7Converter) ◄── needs UUID (JDK only)                  │
                   └─► T-024 (UuidV7Generator) ◄── needs T-013 UuidGenerator port         │
                                                                                          ▼
T-030 (config wiring) ─► T-031 (actuator masking) ───────────────────► T-040..T-045 (*IT suite)
T-050/T-051 (ADRs, parallel) ───────────────────────────────────────► merge before PR
```

Parallelisable once unblocked: all domain types (T-010–T-014) after T-002; the two ADRs (T-050, T-051) at any time. Integration tests (T-040–T-045) require all implementation tasks complete.

---

## Epic: US-001 — Establish tenant-aware identity data model and migrations

---

## ├─ Database

### T-002 — Flyway migration `V2__identity_schema.sql`

**Description:** Create the single append-only Flyway migration that creates all four tables (`users`, `refresh_tokens`, `auth_tokens`, `auth_events`), their indexes/constraints, and the two append-only `BEFORE UPDATE` / `BEFORE DELETE` triggers on `auth_events`. SQL is already authored verbatim in design §6a — the implementer copies it exactly (single-statement `SIGNAL` triggers, no `DELIMITER`, no `BEGIN…END`). Add a column comment on `users.password_hash` stating only Argon2id values may be written (SEC-T4). This unblocks every domain/IT task. Never edit after first apply (ADR 0003); any later change is a new `V3`.
**Dependencies:** none (can start immediately; SQL is pre-written in §6a)
**Complexity:** M
**Files impacted (modify):** none
**Files created (new):** `nexus-backend/src/main/resources/db/migration/V2__identity_schema.sql`
**Security mitigations included:** SEC-T4 (column comment: `password_hash` accepts Argon2id only — the least-privilege grant + TRUNCATE bypass narrative lives in ADR-0006 / T-051)
**Testing requirements:**
- Unit: none (validated by T-040 and the existing context-boot smoke).
- Integration (*IT): covered by `IdentitySchemaMigrationIT` (T-040) and `AuthEventsAppendOnlyIT` (T-043).
**Definition of Done:**
- [ ] All four `CREATE TABLE` statements match the explicit column lists in requirements §6 and design §6a (types, nullability, defaults, charset/collation `utf8mb4_0900_ai_ci`, `ENGINE=InnoDB`).
- [ ] Indexes named per `idx_<table>_<columns>`; FKs per `fk_<from>_<to>`; all identifiers ≤ 64 chars.
- [ ] `UNIQUE (tenant_id, email_hmac)`, `UNIQUE (token_hash)` on both token tables present; `tenant_id` is the leading column on composite `users` indexes (NFR-007).
- [ ] Two single-statement `SIGNAL SQLSTATE '45000'` triggers on `auth_events`; no `DELIMITER`, no `BEGIN…END`.
- [ ] `auth_events` has no `updated_at`, no `@Version` column, no FK, no `email`/`email_hmac`/`email_cipher` column (NFR-010).
- [ ] `password_hash` carries a SQL comment restricting it to Argon2id output (SEC-T4).
- [ ] No literal secret/key anywhere in the SQL (NFR-006); `secret-scan` hook passes on the `.sql` file.
- [ ] Migration applies clean-forward on a fresh Testcontainers MySQL 8.4 (verified by T-040).

---

## ├─ Backend

### │   ├─ Domain

### T-010 — `EmailCipher` value record (+ PII-safe `toString`)

**Description:** Create the immutable `record EmailCipher(String value)` domain value type that the auto-applied `AttributeEncryptor` keys on. Override `toString()` to return `"EmailCipher[REDACTED]"` so the wrapped plaintext email can never leak via logs, stack traces, or debugger output (SEC-T3). This type is the typed seam that prevents a raw `String` being assigned to `email_cipher`.
**Dependencies:** T-002 (migration defines the column it maps to)
**Complexity:** S
**Files impacted (modify):** none
**Files created (new):** `nexus-backend/src/main/java/com/example/nexus/identity/domain/EmailCipher.java`
**Security mitigations included:** SEC-T3 (override `toString()` → redacted)
**Testing requirements:**
- Unit: `EmailCipherTest` — assert `toString()` returns `"EmailCipher[REDACTED]"` and never contains the wrapped value; assert `value()` accessor returns the original; assert record equality.
- Integration (*IT): exercised indirectly by `EmailCipherEncryptionIT` (T-042).
**Definition of Done:**
- [ ] `record EmailCipher(String value)` in `identity.domain`, no `infrastructure` imports.
- [ ] `toString()` overridden to a constant redacted string; unit test proves the value is absent from it.
- [ ] Contributes to the 90% domain JaCoCo gate.

### T-011 — Identity enums: `UserStatus`, `AuthTokenType`

**Description:** Create `UserStatus { PENDING, ACTIVE, LOCKED, DISABLED }` and `AuthTokenType { VERIFICATION, RESET }`, both mapped via `@Enumerated(STRING)` from their owning entities. Pure JDK enums, no framework imports.
**Dependencies:** T-002
**Complexity:** S
**Files impacted (modify):** none
**Files created (new):** `nexus-backend/src/main/java/com/example/nexus/identity/domain/UserStatus.java`, `nexus-backend/src/main/java/com/example/nexus/identity/domain/AuthTokenType.java`
**Security mitigations included:** —
**Testing requirements:**
- Unit: `UserStatusTest`, `AuthTokenTypeTest` — assert the exact value set and any helper behaviour (contributes to 90% domain gate).
- Integration (*IT): persisted-value round-trip covered by entity persistence in T-041/T-042.
**Definition of Done:**
- [ ] Both enums declared with exactly the literals in design §4b; literal lengths fit the `@Column(length=N)` mappings (20).
- [ ] Unit tests cover all enum constants.

### T-012 — `AuthConstants` (TTL constants holder)

**Description:** Create the `final` `AuthConstants` class with `AUTH_REFRESH_TOKEN_TTL_DAYS = 7`, `AUTH_VERIFICATION_TOKEN_TTL = Duration.ofHours(24)`, `AUTH_RESET_TOKEN_TTL = Duration.ofMinutes(60)`, and a `private` constructor throwing `AssertionError`. Prevents magic numbers in US-002/004/005/007. No JaCoCo exclusion — coverage achieved via reflective ctor invocation in the test (§2.8).
**Dependencies:** T-002 (logical grouping; no hard dependency on schema)
**Complexity:** S
**Files impacted (modify):** none
**Files created (new):** `nexus-backend/src/main/java/com/example/nexus/identity/domain/AuthConstants.java`
**Security mitigations included:** — (the ≥128-bit token-entropy precondition that this class documents is captured as a cross-story note in ADR-0006 / T-051, per SEC-T10)
**Testing requirements:**
- Unit: `AuthConstantsTest` — assert each constant's value; reflectively invoke the private constructor and assert it throws `AssertionError` (covers the ctor line for the 90% gate).
**Definition of Done:**
- [ ] `final` class, `private` ctor throws `AssertionError`, constant values match design §4c.
- [ ] `AuthConstantsTest` covers all constants and the private ctor.

### T-013 — `UuidGenerator` port

**Description:** Create the `UuidGenerator` functional interface (`UUID newId();`) in `identity.domain` — the injectable seam for UUIDv7 generation. Entities receive their `id` as a constructor argument and never call the generator internally; callers/tests inject the bean (or a fixed-UUID stub).
**Dependencies:** T-002
**Complexity:** S
**Files impacted (modify):** none
**Files created (new):** `nexus-backend/src/main/java/com/example/nexus/identity/domain/UuidGenerator.java`
**Security mitigations included:** —
**Testing requirements:**
- Unit: covered via its infrastructure implementation test (T-024) and any domain test that stubs it; no standalone test required for the interface.
**Definition of Done:**
- [ ] Single-method interface `UUID newId();`, no outer-layer imports.

### T-014 — JPA entities: `User`, `RefreshToken`, `AuthToken`, `AuthEvent`

**Description:** Create the four `@Entity` classes mapping exactly to the migrated columns (`ddl-auto=validate` must pass). Follow design §4a precisely: constructor injection of values, no field/`@Autowired` injection, no `@Convert` annotations (auto-applied converters resolve at the persistence-unit level — preserves ArchUnit purity, §2.1), `@Enumerated(STRING)` for enum columns, `UUID` typed PK/FK fields (no `@ManyToOne`), audit timestamps `insertable=false updatable=false`, `@Version` on `User`/`RefreshToken`/`AuthToken` only. `User.emailCipher` is typed `EmailCipher`; `User.emailHmac` is a plain `String` with `@Column(updatable=false)`, **no setter, and no Lombok `@Setter`/`@Data` exposing a mutator** (FR-011, §2.4, SEC-T9). `AuthEvent` has no `updated_at`/`@Version` (append-only).
**Dependencies:** T-010, T-011, T-013 (entity field types); T-002 (column shapes)
**Complexity:** L
**Files impacted (modify):** none
**Files created (new):** `nexus-backend/src/main/java/com/example/nexus/identity/domain/User.java`, `…/domain/RefreshToken.java`, `…/domain/AuthToken.java`, `…/domain/AuthEvent.java`
**Security mitigations included:** SEC-T9 (no `@Setter`/`@Data` mutator on `email_hmac`; field is `updatable=false`)
**Testing requirements:**
- Unit: `UserTest` (or equivalent) asserting via reflection that no public/package mutator exists for `emailHmac` (SEC-T9); constructor/accessor behaviour for each entity contributing to the 90% domain gate. Configure `lombok.config` `lombok.addLombokGeneratedAnnotation=true` so JaCoCo ignores generated accessors.
- Integration (*IT): persistence + `validate` alignment covered by T-041/T-042 and the existing `NexusApplicationIT` boot.
**Definition of Done:**
- [ ] All four entities map every migrated column; `mvn` boot under `validate` reports zero schema-mismatch (verified by T-044 boot).
- [ ] No entity declares `@Convert`; no entity imports `AttributeEncryptor` or `UuidV7Converter` (ArchUnit `HexagonalArchitectureTest` green — FR-009).
- [ ] `User.emailHmac` has `@Column(updatable=false)`, no setter, no `@Setter`/`@Data`; reflection test asserts absence of a mutator (SEC-T9).
- [ ] `AuthEvent` has no `updated_at` and no `@Version`.
- [ ] No `@Autowired`, no `System.out`, no `new Date()`/`java.util.logging` (ArchUnit/coding-standards).
- [ ] Domain layer imports nothing from `infrastructure`/`interfaces`.

---

### │   ├─ Application

### T-022 — `EmailBlindIndexService`

**Description:** Create the `@Service` in `identity.application` that computes the deterministic email blind index: normalise `trim → NFC → toLowerCase(Locale.ROOT)`, then `HMAC-SHA256(normalised, key)` using a **fresh `javax.crypto.Mac` instance per call** (no shared mutable field — avoids SpotBugs concurrency flag and cross-thread bleed, SEC-T9), returning lowercase 64-char hex. The validated HMAC key `byte[]` is constructor-injected from `IdentityCryptoConfig` (the bean from T-020). Javadoc the public method documenting the normalisation contract (cross-story: US-002 must index identically to look up). Imports only JDK crypto + Spring `@Service` — zero `infrastructure` imports (ArchUnit `application_must_not_depend_on_adapters`).
**Dependencies:** T-020 (`identityHmacKey` bean must exist to wire)
**Complexity:** M
**Files impacted (modify):** none
**Files created (new):** `nexus-backend/src/main/java/com/example/nexus/identity/application/EmailBlindIndexService.java`
**Security mitigations included:** SEC-T9 (fresh `Mac` per call; NFC + `Locale.ROOT` normalisation pinned and asserted)
**Testing requirements:**
- Unit: `EmailBlindIndexServiceTest` (pure, no Spring context — constructed with a literal test key) asserting: determinism (same email → same 64-char hex; Scenario 9); distinctness (different emails → different hash; Scenario 8); case/whitespace normalisation (`"A@B.COM "` ≡ `"a@b.com"`); **NFC normalisation and `Locale.ROOT`** (Turkish-İ dotted/dotless `I` does not diverge — SEC-T9); output is exactly 64 lowercase hex chars.
- Integration (*IT): not required at application layer; the persisted `email_hmac` path is covered by T-041.
**Definition of Done:**
- [ ] Public `String blindIndex(String email)` with normalisation Javadoc.
- [ ] Fresh `Mac` per call; no shared mutable `Mac`/`SecretKeySpec` instance field (code review + test).
- [ ] `EmailBlindIndexServiceTest` covers determinism, distinctness, normalisation, NFC + `Locale.ROOT`, hex format — meets the 85% application gate (NFR-011).
- [ ] No `infrastructure` import; ArchUnit green.

---

### │   └─ Infrastructure

### T-001 — Build dependencies: pin `uuid-creator`, make `spring-security-crypto` explicit

**Description:** Add the two new dependencies to the backend `pom.xml`: `com.github.f4b6a3:uuid-creator` pinned to an **exact** version (no range, MIT), and `org.springframework.security:spring-security-crypto` declared explicitly (currently transitive via the security starter). Confirm via `dependency:tree` that `Encryptors.stronger()` resolves AES-256-GCM through the JDK-native `SunJCE` provider with **no Bouncy Castle required** (already verified in the Gate 2 resolution; this task records the proof). Run `mvn verify -Psecurity` (OWASP dependency-check, fail CVSS ≥ 7) clean for the new `uuid-creator` artifact (SEC-T7). No `bcprov-jdk18on` is added (SEC-T1 resolution: JDK-native GCM).
**Dependencies:** none (entry point of the build)
**Complexity:** S
**Files impacted (modify):** `nexus-backend/pom.xml`
**Files created (new):** none
**Security mitigations included:** SEC-T7 (exact pin + dependency-check), SEC-T1 (confirm JDK-native GCM provider; no BC fallback)
**Testing requirements:**
- Unit: none.
- Integration (*IT): the AEAD/GCM behaviour proof lives in `EmailCipherEncryptionIT` (T-042, SEC-T1/T8).
**Definition of Done:**
- [ ] `uuid-creator` pinned to an exact version (no version range); version + MIT license recorded in ADR-0005 (T-050).
- [ ] `spring-security-crypto` declared explicitly.
- [ ] `mvn dependency:tree` confirms no Bouncy Castle on the classpath; recorded in ADR-0005/ADR-0006.
- [ ] `mvn verify -Psecurity dependency-check:check` is clean (no CVSS ≥ 7) including `uuid-creator`.

### T-020 — `IdentityCryptoConfig` (key bootstrap, validation, fail-fast, dev-key guard)

**Description:** Create the `@Configuration` in `identity.infrastructure.crypto` that reads the three `nexus.identity.*` properties and exposes two beans: `@Bean TextEncryptor identityTextEncryptor()` → `Encryptors.text(password, salt)` (AES-256-GCM via JDK-native GCM, SEC-T1), and `@Bean byte[] identityHmacKey()` (validated key for `EmailBlindIndexService`). Validate **all three** keys at startup, throwing `IllegalStateException` whose message contains the **property name only, never the value** (SEC-T2/§10): `encryption.password` non-empty ≥ 16 chars; `encryption.salt` valid lowercase hex ≥ 32 hex chars (16 bytes); `hmac-key` decodes to ≥ 32 bytes. Add a boot guard that rejects startup under any non-`dev`/non-`test` profile if a known committed dev/test key value is detected (SEC-T5). Log an INFO line on successful init recording the **fact + key-length category only**, never the value (§10). Lives in `infrastructure.crypto`, NOT `com.example.nexus.config`, so it is subject to the 70% infrastructure gate.
**Dependencies:** T-001 (`spring-security-crypto` explicit; classpath confirmed)
**Complexity:** M
**Files impacted (modify):** none
**Files created (new):** `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/crypto/IdentityCryptoConfig.java`
**Security mitigations included:** SEC-T1 (JDK-native GCM via `Encryptors`), SEC-T2 (password + salt validation, property-name-only errors), SEC-T5 (dev-key-under-prod boot guard)
**Testing requirements:**
- Unit: `IdentityCryptoConfigTest` — for each of (missing/empty password, password < 16 chars, missing/short/non-hex salt, missing/short hmac-key) assert bean creation throws `IllegalStateException` whose message contains the property name and **not** the value; assert the dev-key guard throws under a simulated prod profile when a committed dev key value is supplied (SEC-T5); assert valid keys produce both beans.
- Integration (*IT): startup-fails-fast assertion per absent/short key validated in `IdentityCryptoBootIT` (T-045).
**Definition of Done:**
- [ ] Both beans produced for valid keys; AES-256-GCM via `Encryptors.text` (JDK-native GCM confirmed).
- [ ] All three keys validated with bounds in §2 resolution; every error message includes the property name and excludes the value.
- [ ] Boot guard rejects known dev/test key values under non-dev/test profiles (SEC-T5).
- [ ] Startup INFO log records fact + key-length category only (no value/salt logged); no `log.info(key)`/`log.info(salt)` anywhere.
- [ ] Class resides in `identity.infrastructure.crypto` (subject to 70% infra gate, not `**/config/**` excluded).

### T-021 — `AttributeEncryptor` (AES-256-GCM JPA converter, PII-safe errors)

**Description:** Create the `@Converter(autoApply = true)` implementing `AttributeConverter<EmailCipher, String>` in `identity.infrastructure.persistence`, constructor-injecting the `TextEncryptor` bean from T-020. `convertToDatabaseColumn(EmailCipher)` → `textEncryptor.encrypt(value.value())` (random IV per call → non-deterministic ciphertext, hex output); `convertToEntityAttribute(String)` → `new EmailCipher(decrypt(cipher))`; null-safe both ways. Auto-apply keys on the `EmailCipher` Java type so only `email_cipher` is encrypted and `email_hmac` (plain `String`) is untouched (§2.4). On encrypt/decrypt failure, throw a typed exception with **no plaintext email and no ciphertext in the message or logs** (SEC-T3). Decryption of a tampered ciphertext must fail (GCM AEAD), never return null/plaintext (SEC-T1/T8).
**Dependencies:** T-010 (`EmailCipher`), T-020 (`TextEncryptor` bean)
**Complexity:** M
**Files impacted (modify):** none
**Files created (new):** `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/persistence/AttributeEncryptor.java`
**Security mitigations included:** SEC-T1 (AEAD GCM tamper detection on decrypt), SEC-T3 (typed errors, no PII/ciphertext in messages or logs)
**Testing requirements:**
- Unit: `AttributeEncryptorTest` — round-trip `EmailCipher → ciphertext → EmailCipher`; null-safety both directions; assert that an injected decrypt failure produces a typed exception whose message contains neither the plaintext nor the ciphertext (SEC-T3).
- Integration (*IT): ciphertext-at-rest, transparent decrypt, two-encryptions-differ, and tamper-fails-decrypt covered by `EmailCipherEncryptionIT` (T-042, SEC-T1/T8).
**Definition of Done:**
- [ ] `@Converter(autoApply = true)` keyed on `EmailCipher`; `email_hmac` (`String`) provably untouched.
- [ ] Constructor-injects `TextEncryptor`; null-safe both directions.
- [ ] Encrypt/decrypt failure messages and logs contain no plaintext and no ciphertext (SEC-T3).
- [ ] No domain entity references this class (ArchUnit green).

### T-023 — `UuidV7Converter` (UUID ↔ BINARY(16))

**Description:** Create the `@Converter(autoApply = true)` implementing `AttributeConverter<UUID, byte[]>` in `identity.infrastructure.persistence`. `convertToDatabaseColumn(UUID)` → 16-byte big-endian; `convertToEntityAttribute(byte[])` → reconstructed `UUID`; null-safe both ways. Auto-applies to every `UUID` field across the four entities → `BINARY(16)` under MySQL and portable `VARBINARY(16)` under H2 (no `columnDefinition`). Stateless/thread-safe; domain entities never import it.
**Dependencies:** T-002 (column type); depends only on `java.util.UUID` (JDK) — can run in parallel with crypto tasks
**Complexity:** S
**Files impacted (modify):** none
**Files created (new):** `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/persistence/UuidV7Converter.java`
**Security mitigations included:** —
**Testing requirements:**
- Unit: `UuidV7ConverterTest` — round-trip `UUID → byte[16] → UUID`; null-safety; asserts 16-byte length and big-endian ordering (pure coverage toward the 70% infra gate).
- Integration (*IT): exercised by every persistence IT (T-041/T-042).
**Definition of Done:**
- [ ] Round-trip and null-safety correct; emits 16 big-endian bytes.
- [ ] No `columnDefinition` (stays H2-portable, §2.5).
- [ ] `UuidV7ConverterTest` green.

### T-024 — `UuidV7Generator` (`UuidGenerator` implementation)

**Description:** Create the `@Component` in `identity.infrastructure.crypto` implementing the `UuidGenerator` port, delegating `newId()` to `UuidCreator.getTimeOrderedEpoch()` (UUIDv7). Confirm the library seeds from `SecureRandom` (per spec; UUIDv7 leaks creation time by design — accepted for internal PKs, §3.10 of the threat model).
**Dependencies:** T-001 (`uuid-creator` on classpath), T-013 (`UuidGenerator` port)
**Complexity:** S
**Files impacted (modify):** none
**Files created (new):** `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/crypto/UuidV7Generator.java`
**Security mitigations included:** — (supply-chain pin/scan handled in T-001/SEC-T7)
**Testing requirements:**
- Unit: `UuidV7GeneratorTest` — successive `newId()` calls return distinct, non-null UUIDs that are time-ordered (later call ≥ earlier when compared); version nibble is 7.
- Integration (*IT): used as the ID source in persistence ITs (T-041/T-042).
**Definition of Done:**
- [ ] Implements `UuidGenerator`; delegates to `getTimeOrderedEpoch()`.
- [ ] Unit test asserts uniqueness, version 7, and time-ordering.

### T-025 — `JpaUserRepository`

**Description:** Create the Spring Data interface `JpaUserRepository extends JpaRepository<User, UUID>` in `identity.infrastructure.persistence` with one derived query: `Optional<User> findByTenantIdAndEmailHmac(UUID tenantId, String emailHmac)` — served by the `uq_users_tenant_id_email_hmac` UNIQUE index. No application port wraps it in US-001 (deliberate minimal deviation, recorded as a note, not an ADR; the port arrives in US-002). Provides the exact production query path for the NFR-001 perf test.
**Dependencies:** T-014 (`User` entity)
**Complexity:** S
**Files impacted (modify):** none
**Files created (new):** `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/persistence/JpaUserRepository.java`
**Security mitigations included:** — (parameter-bound derived query — A03 injection PASS)
**Testing requirements:**
- Unit: none (no logic).
- Integration (*IT): uniqueness (T-041), and the p95 + `EXPLAIN`-uses-index assertion (T-044 perf).
**Definition of Done:**
- [ ] Single derived method `findByTenantIdAndEmailHmac`; no `@Query`, no dynamic SQL.
- [ ] Drives the unique-index path proven by `UserQueryPerformanceIT` (T-044).

---

## ├─ Cross-cutting (security, config, observability)

### T-030 — Configuration: base / dev / test crypto keys + IT key injection

**Description:** Wire the `nexus.identity.*` key contract across all profiles per design §7. Add the three keys to base `application.yml` as `${ENV_VAR}` with **no prod default** (fast-fail when unset, NFR-006); add non-secret dev placeholders to `application-dev.yml` (≥ 16-char password, 32-char hex salt, ≥ 32-byte HMAC key so validation/T-020 passes); add test keys to `application-test.properties` for the H2 smoke profile. For `*IT`, inject the same test keys via `@DynamicPropertySource` added to (or alongside) `TestcontainersConfiguration` so the Testcontainers context boots with valid crypto material. All placeholder values must satisfy the T-020 validation bounds (SEC-T2) and be ≥ 32 bytes for the HMAC key (SEC-T5 dev-key sizing).
**Dependencies:** T-020 (validation bounds the placeholders must satisfy)
**Complexity:** S
**Files impacted (modify):** `nexus-backend/src/main/resources/application.yml`, `nexus-backend/src/main/resources/application-dev.yml`, `nexus-backend/src/test/resources/application-test.properties`, `nexus-backend/src/test/java/com/example/nexus/TestcontainersConfiguration.java`
**Files created (new):** none (or `AbstractIdentityIT` base class if the team prefers a shared `@DynamicPropertySource` host — implementer's choice per §2.6)
**Security mitigations included:** SEC-T2 (dev/test placeholders satisfy validation), SEC-T5 (dev HMAC placeholder ≥ 32 bytes; values are the ones the T-020 guard recognises as dev-only)
**Testing requirements:**
- Unit: none.
- Integration (*IT): the existing `NexusApplicationIT` and all new `*IT` boot with injected keys (proves wiring); `IdentityCryptoBootIT` (T-045) proves fail-fast when a key is removed.
**Definition of Done:**
- [ ] Base `application.yml` has `${NEXUS_IDENTITY_ENCRYPTION_PASSWORD}`, `${NEXUS_IDENTITY_ENCRYPTION_SALT}`, `${NEXUS_IDENTITY_HMAC_KEY}` with no defaults and inline comments.
- [ ] Dev + test placeholders are non-secret, profile-scoped, commented "MUST NOT be used in shared/staging/prod", and satisfy all T-020 validation bounds.
- [ ] `*IT` context boots via `@DynamicPropertySource` test keys; `secret-scan` hook passes (committed keys are clearly dev/test placeholders).

### T-031 — Actuator key sanitisation

**Description:** Ensure `nexus.identity.hmac-key`, `nexus.identity.encryption.salt`, and `nexus.identity.encryption.password` are masked in `/actuator/env` and `/actuator/configprops`. Spring's default sanitisation masks names matching `password|secret|key`, which already covers `password` and `hmac-key`; explicitly register `salt` (and confirm the others) so no crypto material can leak via the env endpoint (SEC-T6). Add the property names to `management.endpoint.env.keys-to-sanitize` (or the current Spring Boot 4 equivalent / `SanitizingFunction` bean).
**Dependencies:** T-030 (properties must exist to sanitise)
**Complexity:** S
**Files impacted (modify):** `nexus-backend/src/main/resources/application.yml` (or a small `@Configuration`/`SanitizingFunction` bean under `identity.infrastructure.crypto` if config-only masking is insufficient in Boot 4)
**Files created (new):** none expected (add a `SanitizingFunction` bean only if YAML config cannot mask `salt`)
**Security mitigations included:** SEC-T6 (actuator masking for `hmac-key` + `salt` + `password`)
**Testing requirements:**
- Unit: none.
- Integration (*IT): `ActuatorEnvMaskingIT` (folded here) — hit `/actuator/env` in the Testcontainers context (authenticated per baseline) and assert all three `nexus.identity.*` values render as `"******"`, not their literals.
**Definition of Done:**
- [ ] `/actuator/env` masks `nexus.identity.encryption.password`, `encryption.salt`, and `hmac-key`.
- [ ] `ActuatorEnvMaskingIT` asserts masking for all three (SEC-T6).

---

## ├─ Tests

### T-040 — `IdentitySchemaMigrationIT`

**Description:** Testcontainers MySQL 8.4 IT proving the V2 migration applies clean-forward and produces the exact schema. Asserts all four tables exist, every column per requirements §6, and every index/constraint via `information_schema`; asserts the Flyway V2 checksum is stable on re-run (AC-1, AC-4, AC-6 / Scenarios 1; SEC-T-migration tamper guard from threat §3.8).
**Dependencies:** T-002; all entity tasks complete (T-014) so the `validate` boot is meaningful
**Complexity:** M
**Files impacted (modify):** none
**Files created (new):** `nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/persistence/IdentitySchemaMigrationIT.java`
**Security mitigations included:** — (supports SEC-T migration checksum-stability from threat §3.8)
**Testing requirements:**
- Integration (*IT): `should_createAllTables_when_migrationsApplied`, `should_createExpectedIndexes_when_migrationsApplied`, `should_keepFlywayChecksumStable_when_rerun`.
**Definition of Done:**
- [ ] All 4 tables, all columns, all indexes asserted from `information_schema`.
- [ ] Flyway V2 checksum stability asserted; uses Testcontainers MySQL 8.4 (never H2).

### T-041 — `UserUniquenessIT`

**Description:** Testcontainers IT proving per-tenant email uniqueness via the blind index. Inserts duplicate `(tenant_id, email_hmac)` → constraint violation; same `email_hmac` under a different `tenant_id` → both persist (AC-2 / Scenarios 2, 3). Uses `JpaUserRepository`, `UuidV7Generator`, and `EmailBlindIndexService` end-to-end.
**Dependencies:** T-014, T-022, T-023, T-024, T-025, T-002
**Complexity:** M
**Files impacted (modify):** none
**Files created (new):** `nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/persistence/UserUniquenessIT.java`
**Security mitigations included:** —
**Testing requirements:**
- Integration (*IT): `should_rejectDuplicate_when_sameTenantSameEmailHmac`, `should_persistBoth_when_sameEmailHmacDifferentTenant`.
**Definition of Done:**
- [ ] Duplicate `(tenant_id, email_hmac)` raises a constraint violation; cross-tenant duplicate persists.

### T-042 — `EmailCipherEncryptionIT` (AEAD GCM proof + tamper + non-determinism)

**Description:** Testcontainers IT proving at-rest encryption and AEAD integrity. A native SQL read of `email_cipher` returns ciphertext ≠ plaintext; a JPA reload decrypts transparently to the original email (AC-3 / Scenario 4). Add the two security assertions: two encryptions of the same email produce **different** ciphertext (random IV — SEC-T8), and a tampered `email_cipher` value **fails decryption** (proves GCM AEAD is active, not a bare/CBC mode — SEC-T1/T8). This IT is the runtime proof of the SEC-T1 GCM-provider resolution.
**Dependencies:** T-010, T-014, T-021, T-020, T-025, T-024, T-002
**Complexity:** M
**Files impacted (modify):** none
**Files created (new):** `nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/persistence/EmailCipherEncryptionIT.java`
**Security mitigations included:** SEC-T1 (tampered ciphertext fails decryption → AEAD active), SEC-T8 (two encryptions differ; tamper detection)
**Testing requirements:**
- Integration (*IT): `should_storeCiphertext_when_userPersisted`, `should_decryptTransparently_when_userLoaded`, `should_produceDifferentCiphertext_when_sameEmailEncryptedTwice`, `should_failDecryption_when_emailCipherTampered`.
**Definition of Done:**
- [ ] Raw column is ciphertext (≠ plaintext); reload decrypts to original.
- [ ] Two encryptions of the same email differ (SEC-T8).
- [ ] Tampered ciphertext throws on decrypt, never returns null/plaintext (SEC-T1/T8).

### T-043 — `AuthEventsAppendOnlyIT`

**Description:** Testcontainers IT proving the append-only triggers both parsed (migration applied) and fire. `UPDATE` and `DELETE` on an `auth_events` row each raise `SQLSTATE '45000'`; after a rejected `UPDATE`, the row is **byte-identical** (AC-5 / Scenarios 5, 6; threat §3.3 row-unchanged requirement).
**Dependencies:** T-002 (triggers); a way to insert an `auth_events` row (entity T-014 or native insert)
**Complexity:** M
**Files impacted (modify):** none
**Files created (new):** `nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/persistence/AuthEventsAppendOnlyIT.java`
**Security mitigations included:** — (validates NFR-005 / threat §3.3 trigger enforcement)
**Testing requirements:**
- Integration (*IT): `should_rejectUpdate_when_authEventModified`, `should_rejectDelete_when_authEventDeleted`, `should_leaveRowUnchanged_when_updateRejected` — each asserting the exact `SQLSTATE '45000'`.
**Definition of Done:**
- [ ] UPDATE and DELETE both rejected with `SQLSTATE '45000'`; row unchanged after rejected UPDATE.

### T-044 — `UserQueryPerformanceIT` (`@Tag("perf")`)

**Description:** Testcontainers IT loading a 1M-row `users` fixture and asserting `findByTenantIdAndEmailHmac` p95 < 10 ms, with `EXPLAIN` confirming `uq_users_tenant_id_email_hmac` is used (NFR-001 / Scenario 7). Tagged `perf` to run in a dedicated CI lane.
**Dependencies:** T-025, T-014, T-040 (schema must be correct), T-002
**Complexity:** L
**Files impacted (modify):** `nexus-backend/pom.xml` (only if a `perf`-tag failsafe lane / surefire group config is needed to isolate the tag)
**Files created (new):** `nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/persistence/UserQueryPerformanceIT.java`
**Security mitigations included:** —
**Testing requirements:**
- Integration (*IT): `should_lookupUnder10msP95_when_1MRowFixture`; asserts p95 < 10 ms and `EXPLAIN` index usage. Bulk-load fixture efficiently (batched inserts) so the lane stays viable.
**Definition of Done:**
- [ ] 1M-row fixture loads; p95 < 10 ms asserted; `EXPLAIN` confirms the unique index is chosen.
- [ ] Test is `@Tag("perf")` and runs green in its CI lane.

### T-045 — `IdentityCryptoBootIT` (fail-fast on missing/short keys)

**Description:** Testcontainers/context IT asserting the Spring context **fails to start** when each crypto key is absent or too short (one case per key), complementing the unit-level validation in T-020 (threat §3.6 startup fail-fast). Confirms the fail-fast contract holds at full application-context level, not just in isolated bean tests.
**Dependencies:** T-020, T-030
**Complexity:** M
**Files impacted (modify):** none
**Files created (new):** `nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/crypto/IdentityCryptoBootIT.java`
**Security mitigations included:** SEC-T2 / SEC-T5 (context-level fail-fast for absent/short/weak keys)
**Testing requirements:**
- Integration (*IT): one method per key asserting context start fails (e.g. via `ApplicationContextRunner` or a `@SpringBootTest` expecting failure) when the key is missing/short; assert the failure references the property name and not the value.
**Definition of Done:**
- [ ] Context fails to start for each absent/short key; failure message names the property, never the value.

---

## └─ Documentation

### T-050 — ADR-0005: UUIDv7 primary keys

**Description:** Author ADR-0005 per design §8 outline. Status Accepted; supersedes the ULID preference in `docs/coding-standards.md` line 29. Records: decision (UUIDv7 as `BINARY(16)` via pinned `uuid-creator` `getTimeOrderedEpoch()` behind the `UuidGenerator` port), rationale (time-ordered sequential inserts; 16 bytes vs 26-char ULID; native UUID interop), alternatives, consequences. Record the **exact pinned `uuid-creator` version and MIT license** and the confirmation that no Bouncy Castle is on the classpath (SEC-T7 supply-chain note). Must be merged before the PR.
**Dependencies:** can draft in parallel any time; the pinned version comes from T-001
**Complexity:** S
**Files impacted (modify):** `docs/coding-standards.md` (line 29 — point the ULID preference to ADR-0005)
**Files created (new):** `docs/adr/0005-uuidv7-primary-keys.md`
**Security mitigations included:** SEC-T7 (record exact pinned version + MIT license)
**Testing requirements:** none (documentation).
**Definition of Done:**
- [ ] ADR-0005 covers context/decision/rationale/alternatives/consequences; records exact pinned version + MIT license + no-BC confirmation.
- [ ] `docs/coding-standards.md` line 29 updated to reference ADR-0005.
- [ ] Status Accepted; merged before PR (condition of done, FR-012).

### T-051 — ADR-0006: Email blind index + at-rest encryption

**Description:** Author ADR-0006 per design §8 outline. Status Accepted. Records: two-column design (`email_cipher` AES-256-GCM auto-applied converter keyed on `EmailCipher`; `email_hmac` deterministic HMAC-SHA256 blind index via `EmailBlindIndexService`); the converter convention ("persistence converters are auto-applied from infrastructure keyed on domain value types; domain entities never reference a converter class"); alternatives; consequences. Fold in all assigned security notes: (SEC-T4) the **`TRUNCATE`/`DROP TRIGGER` append-only bypass** is documented as accepted, plus the **least-privilege runtime DB grant** (app user: SELECT/INSERT/UPDATE/DELETE only, no DDL/TRUNCATE; Flyway runs under a separate DB user); the **HMAC key rotation runbook** (expand/contract re-index: add column, dual-write, backfill, swap, drop) and encryption-key rotation runbook; (SEC-T9) the pinned NFC + `Locale.ROOT` normalisation contract; (SEC-T10) the cross-story constraints — US-002 lookups must return constant 404/timing (no HMAC oracle) and token columns require ≥ 128-bit `SecureRandom` entropy; and the accepted `email_hmac` equality-leak residual. Must be merged before the PR.
**Dependencies:** can draft in parallel any time; finalise converter/normalisation details against T-021/T-022
**Complexity:** M
**Files impacted (modify):** none
**Files created (new):** `docs/adr/0006-email-blind-index-and-encryption.md`
**Security mitigations included:** SEC-T4 (TRUNCATE bypass + least-privilege DB grant), SEC-T9 (NFC + `Locale.ROOT` contract), SEC-T10 (HMAC-oracle + ≥128-bit entropy cross-story constraints), plus the accepted `email_hmac` equality-leak residual
**Testing requirements:** none (documentation).
**Definition of Done:**
- [ ] ADR-0006 covers the full §8 outline plus SEC-T4/T9/T10 notes and the equality-leak residual.
- [ ] HMAC + encryption key-rotation runbooks documented; least-privilege grant + Flyway-separate-user specified.
- [ ] Status Accepted; merged before PR (condition of done, FR-012).

---

## Security mitigation coverage matrix

| SEC-T | Folded into |
|-------|-------------|
| SEC-T1 | T-001 (confirm JDK-native GCM, no BC), T-020 (`Encryptors` GCM), T-021 + T-042 (AEAD tamper IT) |
| SEC-T2 | T-020 (password + salt validation, property-name-only errors), T-030 (placeholders satisfy bounds), T-045 (context fail-fast IT) |
| SEC-T3 | T-010 (`EmailCipher.toString()` redacted), T-021 (typed errors, no PII/ciphertext in messages/logs) |
| SEC-T4 | T-002 (`password_hash` Argon2id column comment), T-051 (TRUNCATE bypass + least-privilege DB grant) |
| SEC-T5 | T-020 (boot guard rejecting dev keys under non-dev profiles), T-030 (dev HMAC placeholder ≥ 32 bytes) |
| SEC-T6 | T-031 (actuator sanitisation for `hmac-key`, `salt`, `password` + masking IT) |
| SEC-T7 | T-001 (exact pin + `-Psecurity` dependency-check), T-050 (record version + MIT license) |
| SEC-T8 | T-042 (`EmailCipherEncryptionIT` — two encryptions differ + tamper fails decrypt) |
| SEC-T9 | T-022 (`EmailBlindIndexServiceTest` NFC + `Locale.ROOT`; fresh `Mac`), T-014 (no `@Setter`/`@Data` mutator on `email_hmac` + reflection assertion), T-051 (normalisation contract) |
| SEC-T10 | T-051 (ADR-0006: HMAC-oracle constant-response + ≥128-bit entropy cross-story constraints) |

All 10 SEC tasks are owned; no mitigation is left open.

---

## Files created / modified — consolidated

**Created (main):**
- `nexus-backend/src/main/resources/db/migration/V2__identity_schema.sql`
- `nexus-backend/src/main/java/com/example/nexus/identity/domain/EmailCipher.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/domain/UserStatus.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/domain/AuthTokenType.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/domain/AuthConstants.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/domain/UuidGenerator.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/domain/User.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/domain/RefreshToken.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/domain/AuthToken.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/domain/AuthEvent.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/application/EmailBlindIndexService.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/persistence/UuidV7Converter.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/persistence/AttributeEncryptor.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/persistence/JpaUserRepository.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/crypto/IdentityCryptoConfig.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/crypto/UuidV7Generator.java`
- `docs/adr/0005-uuidv7-primary-keys.md`
- `docs/adr/0006-email-blind-index-and-encryption.md`

**Created (test):**
- `nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/persistence/IdentitySchemaMigrationIT.java`
- `nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/persistence/UserUniquenessIT.java`
- `nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/persistence/EmailCipherEncryptionIT.java`
- `nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/persistence/AuthEventsAppendOnlyIT.java`
- `nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/persistence/UserQueryPerformanceIT.java`
- `nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/crypto/IdentityCryptoBootIT.java`
- Unit tests: `EmailCipherTest`, `UserStatusTest`, `AuthTokenTypeTest`, `AuthConstantsTest`, `UuidV7ConverterTest`, `UuidV7GeneratorTest`, `EmailBlindIndexServiceTest`, `AttributeEncryptorTest`, `IdentityCryptoConfigTest`, `UserTest`

**Modified:**
- `nexus-backend/pom.xml` (uuid-creator pin + spring-security-crypto explicit; optional perf lane surefire group)
- `nexus-backend/src/main/resources/application.yml` (identity key env-var stubs + actuator sanitisation)
- `nexus-backend/src/main/resources/application-dev.yml` (dev placeholder keys)
- `nexus-backend/src/test/resources/application-test.properties` (test placeholder keys)
- `nexus-backend/src/test/java/com/example/nexus/TestcontainersConfiguration.java` (`@DynamicPropertySource` for IT key injection)
- `docs/coding-standards.md` (line 29: ULID preference → reference ADR-0005)
