# Technical Design — US-001

**Status:** APPROVED — Gate 2 passed (blocker resolutions below)
**Feature:** US-001 — Establish tenant-aware identity data model and migrations
**Date:** 2026-06-14
**Author:** Principal Architect
**Inputs:** `docs/features/US-001/02-impact.md` (approved), `docs/ARCHITECTURE.md`, `SECURITY.md`,
`docs/coding-standards.md`, ADRs 0001–0003, `HexagonalArchitectureTest.java`, `pom.xml`

---

## Gate 2 Blocker Resolutions

**SEC-T1 — GCM provider:** `Encryptors.stronger()` in Spring Security Crypto 7.x delegates to
`AesBytesEncryptor` with `CipherAlgorithm.GCM`, which calls `AES/GCM/NoPadding` via the JDK's
built-in `SunJCE` provider. GCM is JDK-native since Java 8; confirmed on Java 25. **No Bouncy
Castle dependency required.** Implementation task: add an IT asserting that tampered `email_cipher`
fails decryption (proves AEAD integrity is active, not a bare-encrypt mode).

**SEC-T2 — Salt/password strength validation:** `IdentityCryptoConfig` validates all three keys at
startup and throws `IllegalStateException` with the property name (never the value) on failure:
- `nexus.identity.encryption.password`: non-empty, ≥ 16 characters
- `nexus.identity.encryption.salt`: valid lowercase hex string, ≥ 32 hex chars (= 16 bytes)
- `nexus.identity.hmac-key`: ≥ 32 bytes (already specified in §5d — now unified here)

The dev/test placeholder values in `application-dev.yml` and `application-test.properties` must
satisfy these bounds or dev/CI startup breaks. (They do: the example passwords are ≥ 16 chars and
the example salts are 32-char hex strings.)

---

## 1. Overview & Scope

US-001 delivers the first real bounded context, `com.example.nexus.identity`, as a
**data-and-crypto foundation with no API and no frontend**. Concretely:

- One Flyway migration `V2__identity_schema.sql` creating four tables (`users`, `refresh_tokens`,
  `auth_tokens`, `auth_events`) plus two append-only triggers on `auth_events`.
- Four JPA `@Entity` domain classes, two enums, one constants holder.
- Infrastructure: a UUIDv7 BINARY(16) converter, an AES-256-GCM attribute encryptor, a Spring
  crypto configuration, and a `JpaUserRepository`.
- One application-layer `EmailBlindIndexService`.
- Two ADRs as conditions of done: **ADR-0005 (UUIDv7 primary keys)** and **ADR-0006 (email blind
  index + at-rest encryption)**. (Story shorthand "ADR-001/ADR-002" maps to the next sequential
  numbers in `docs/adr/`, which currently ends at 0004.)

**Explicitly out of scope:** any `@RestController`, DTO, route, Angular code, Spring Security
change, or use-case service beyond the blind-index helper. The `identity.interfaces` package is
**not created** (§2.10).

**Driving constraints honoured:**
- Hexagonal dependency rule, ArchUnit-enforced (`domain`/`application` must not import
  `infrastructure`/`interfaces`).
- Flyway owns the schema; `ddl-auto=validate` — every entity mapping must match the migrated column
  exactly (ADR 0003).
- Per-layer JaCoCo gates that go live with this context: domain ≥ 90%, application ≥ 85%,
  infrastructure ≥ 70%, bundle ≥ 80%.
- SECURITY.md crypto matrix: AES-256-GCM via `Encryptors.stronger()`, HMAC-SHA256 for the blind
  index, SHA-256 for token hashes.

---

## 2. Architecture Decisions

This section resolves all ten open items from `02-impact.md §9`. Each decision is binding for
implementation.

### 2.1 Converter placement vs. hexagonal purity *(binding — Risk #1)*

**Problem.** A JPA entity in `identity.domain` that writes
`@Convert(converter = AttributeEncryptor.class)` references a class in
`identity.infrastructure.persistence`. The ArchUnit rule `domain_must_not_depend_on_outer_layers`
fails on any `..domain.. → ..infrastructure..` dependency.

**Decision: use `@Converter(autoApply = true)` for both converters, registered in
`identity.infrastructure.persistence`, with the domain entities declaring NO `@Convert` annotation
and NO import of either converter.**

- `UuidV7Converter` — `@Converter(autoApply = true)`, `AttributeConverter<UUID, byte[]>`. Every
  `UUID` field across the four entities is converted to/from `BINARY(16)` automatically. Entities
  import only `java.util.UUID` (a JDK type).
- `AttributeEncryptor` — `@Converter(autoApply = true)`, `AttributeConverter<EmailCipher, String>`,
  where `EmailCipher` is a tiny immutable value object (`record EmailCipher(String value)`) declared
  in `identity.domain`. Because auto-apply keys on the **attribute Java type** (`EmailCipher`), only
  the `email_cipher` field is encrypted. No other `String` column is touched, and the domain entity
  references only the JDK/domain type `EmailCipher`, never the converter.

**Why this passes ArchUnit:**
- The domain entity's only new compile-time dependencies are `java.util.UUID` and
  `com.example.nexus.identity.domain.EmailCipher` — both inner-layer/JDK.
- Hibernate resolves auto-applied converters at the persistence-unit level (infrastructure concern).
- `EmailCipher` as a value object also gives a typed seam: a raw `String` cannot be accidentally
  assigned to `email_cipher`.

**Recorded in ADR-0006.** Rule: "persistence converters are auto-applied from infrastructure keyed
on domain value types; domain entities never reference a converter class."

### 2.2 `EmailBlindIndexService` layer — **application**

**Decision: `identity.application.EmailBlindIndexService`, 85% coverage gate.**

Justification:
- Stateless and deterministic (domain-like) but **consumes an injected secret** from
  configuration/Vault — a policy concern, not a pure domain invariant (ADR 0002).
- Keeping it out of `domain` keeps the 90% domain gate focused on pure entity/enum/value-object
  behaviour (Risk #5 in impact analysis).
- Does not import `infrastructure` — HMAC key is injected as `byte[]` from
  `IdentityCryptoConfig`. ArchUnit `application_must_not_depend_on_adapters` is satisfied.
- HMAC computation uses a fresh `javax.crypto.Mac` instance per call (never a shared mutable
  instance) — avoids the SpotBugs concurrency flag.
- Public method gets Javadoc documenting the normalisation contract (coding-standards line 64).

### 2.3 Repositories in US-001 — **included now**

**Decision: `JpaUserRepository` lands in US-001.**

Justification:
- NFR-001 requires a `(tenant_id, email_hmac)` lookup under a 1M-row fixture at < 10 ms p95.
  `UserQueryPerformanceIT` needs a real query path that exercises the exact production query plan.
- Thin Spring Data interface with one derived query method — no speculative use case.
- No application port wraps it yet (no use case in US-001); that arrives in US-002. This is a
  deliberate, minimal deviation recorded as a note, not an ADR.

### 2.4 `email_hmac` non-writability *(FR-011)*

**Decision:** `email_hmac` is mapped `@Column(name = "email_hmac", nullable = false,
updatable = false, insertable = true)` with NO public setter and NO Lombok `@Setter` on that field.

Mechanism:
- The blind index is supplied to the `User` constructor as an already-computed `String hmac`
  obtained from `EmailBlindIndexService`.
- `updatable = false` makes the column immutable after insert at the JPA level.
- The field type is plain `String` (hex) so the auto-applied `AttributeEncryptor` does **not** touch
  it (different Java type from `EmailCipher`). This is the critical reason why the encryptor keys
  on `EmailCipher`, not `String`.

### 2.5 H2 smoke-test strategy *(Risk #2)*

**Decision: make identity entities H2-portable AND provide test crypto keys. Do NOT exclude
identity from the H2 component scan.**

Portability is achievable:
- **BINARY(16):** `UuidV7Converter` maps `UUID ↔ byte[]`; `columnDefinition` is omitted so
  Hibernate emits a portable `VARBINARY(16)` under H2 `create-drop`.
- **ENUM columns:** mapped with `@Enumerated(EnumType.STRING)` + `@Column(length = N)`. Hibernate
  emits `VARCHAR(N)` under H2; validates against MySQL native `ENUM` under Testcontainers.
- **Triggers / `SIGNAL`:** created only in the Flyway script; H2 never sees them (Flyway disabled
  on the H2 test profile). The append-only protection is absent under H2 — acceptable because
  `AuthEventsAppendOnlyIT` validates it against real MySQL.
- **Crypto beans:** `application-test.properties` gains non-secret test keys so
  `IdentityCryptoConfig` wires under the H2 profile.

### 2.6 Key bootstrap contract *(Risk #3)*

**Env-var / property contract** (namespace `nexus.identity.*`, all `${ENV_VAR}`, **no prod
default**):

| Property | Env var | Purpose |
|----------|---------|---------|
| `nexus.identity.encryption.password` | `NEXUS_IDENTITY_ENCRYPTION_PASSWORD` | Master password for `Encryptors.stronger(password, salt)` |
| `nexus.identity.encryption.salt` | `NEXUS_IDENTITY_ENCRYPTION_SALT` | Hex-encoded KDF salt for `Encryptors.stronger` |
| `nexus.identity.hmac-key` | `NEXUS_IDENTITY_HMAC_KEY` | Secret key for the email blind index (HMAC-SHA256, ≥ 32 bytes) |

- `Encryptors.stronger(password, salt)` → AES-256-GCM, random IV per call, hex output.
  Non-deterministic → same email encrypts differently each time → need the separate deterministic
  `email_hmac` for lookup (the whole point of ADR-0006).
- **Fail-fast:** missing/too-short key → bean creation fails → application does not start.
- **Dev placeholders** (`application-dev.yml`) allow `spring-boot:run` without a vault.
- **IT injection:** test keys injected via a shared `@DynamicPropertySource` (abstract
  `AbstractIdentityIT` base class or addition to `TestcontainersConfiguration`).
- **HMAC key rotation runbook** documented in ADR-0006: rotating the key invalidates every stored
  `email_hmac` and requires an expand/contract re-index migration.

### 2.7 Trigger SQL form *(Risk #4)*

**Decision: single-statement `CREATE TRIGGER … SIGNAL` blocks with NO `BEGIN…END` and NO
`DELIMITER`.**

`flyway-mysql` ships a MySQL-aware SQL parser that handles `CREATE TRIGGER` statement boundaries
without a client-side `DELIMITER` directive (`DELIMITER` is a CLI construct, must NOT appear in
Flyway scripts). A single-statement trigger body is the most robust form. Exact template:

```sql
CREATE TRIGGER trg_auth_events_no_update
    BEFORE UPDATE ON auth_events
    FOR EACH ROW
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'auth_events is append-only';
```

`AuthEventsAppendOnlyIT` proves the trigger both parsed (migration applied) and fires
(UPDATE/DELETE rejected).

### 2.8 `AuthConstants` coverage *(Risk #5)*

**Decision:** `AuthConstants` is a `final` class with a `private` no-arg constructor throwing
`AssertionError`. An `AuthConstantsTest` (a) asserts each constant's value and (b) invokes the
private constructor reflectively to cover that line. No JaCoCo exclusion added.

### 2.9 UUIDv7 generation seam

**Decision:** introduce a `UuidGenerator` functional interface in `identity.domain` (`UUID newId();`)
with an infrastructure bean `UuidV7Generator` delegating to `UuidCreator.getTimeOrderedEpoch()`.

- Entities receive their `id` as a constructor argument; they never call the generator internally.
- Application/test callers inject the `UuidGenerator` bean → trivially testable with a fixed-UUID
  stub.
- Rationale for UUIDv7 over ULID: time-ordered → sequential B-tree inserts (low fragmentation);
  16 bytes vs 26 chars (smaller FKs, indexes); standard UUID type across JDBC/JPA/tools.

### 2.10 `identity.interfaces` package — **NOT created**

The `*.interfaces.rest` JaCoCo rule stays dormant. No empty package created.

---

## 3. Package Structure

```
com.example.nexus.identity
├── domain
│   ├── User.java               @Entity → users
│   ├── RefreshToken.java       @Entity → refresh_tokens
│   ├── AuthToken.java          @Entity → auth_tokens
│   ├── AuthEvent.java          @Entity → auth_events (no updated_at)
│   ├── UserStatus.java         enum PENDING/ACTIVE/LOCKED/DISABLED
│   ├── AuthTokenType.java      enum VERIFICATION/RESET
│   ├── EmailCipher.java        record EmailCipher(String value) — encrypted-email value type
│   ├── UuidGenerator.java      port: UUID newId()
│   └── AuthConstants.java      final class, private ctor, TTL constants
│
├── application
│   └── EmailBlindIndexService.java   HMAC-SHA256 blind index (injected key)
│
└── infrastructure
    ├── persistence
    │   ├── UuidV7Converter.java      @Converter(autoApply=true) UUID↔byte[16]
    │   ├── AttributeEncryptor.java   @Converter(autoApply=true) EmailCipher↔String
    │   └── JpaUserRepository.java    Spring Data: findByTenantIdAndEmailHmac
    └── crypto
        ├── IdentityCryptoConfig.java @Configuration: TextEncryptor + HMAC key beans
        └── UuidV7Generator.java      @Component implements UuidGenerator (f4b6a3)
```

Resources:
```
src/main/resources/db/migration/V2__identity_schema.sql
```

> `IdentityCryptoConfig` lives in `identity.infrastructure.crypto`, NOT in
> `com.example.nexus.config`. The JaCoCo `**/config/**` exclude matches only the top-level
> `config` package, so `IdentityCryptoConfig` IS subject to the 70% infrastructure gate.

---

## 4. Domain Model

All entities: constructor injection of values, no field injection, no `@Autowired`, no
`System.out`, no `java.util.logging` (ArchUnit). Audit timestamps mapped `insertable=false,
updatable=false` (DB clock — avoids forbidden `new Date()` pattern). Optimistic locking via
`@Version` on `User`, `RefreshToken`, `AuthToken`; `AuthEvent` has no `@Version` (append-only).

### 4a. Entity designs

#### `User` → `users`

```java
@Entity
@Table(name = "users")
public class User {
  @Id @Column(name = "id", length = 16)
  private UUID id;                             // UuidV7Converter auto-applies

  @Column(name = "tenant_id", length = 16, nullable = false)
  private UUID tenantId;

  @Column(name = "email_cipher", nullable = false)
  private EmailCipher emailCipher;             // AttributeEncryptor auto-applies

  @Column(name = "email_hmac", length = 64, nullable = false, updatable = false)
  private String emailHmac;                    // no setter; pre-computed by EmailBlindIndexService

  @Enumerated(EnumType.STRING)
  @Column(name = "status", length = 20, nullable = false)
  private UserStatus status;

  @Column(name = "token_version", nullable = false)
  private int tokenVersion;

  @Column(name = "email_verified_at")
  private Instant emailVerifiedAt;

  @Column(name = "failed_attempt_count", nullable = false)
  private int failedAttemptCount;

  @Column(name = "locked_until")
  private Instant lockedUntil;

  @Column(name = "consent_accepted_at")
  private Instant consentAcceptedAt;

  @Version @Column(name = "version", nullable = false)
  private long version;

  @Column(name = "created_at", insertable = false, updatable = false)
  private Instant createdAt;

  @Column(name = "updated_at", insertable = false, updatable = false)
  private Instant updatedAt;
}
```

Key decisions:
- `email_cipher` type is `EmailCipher` → auto-applied encryptor converts to/from AES-256-GCM
  ciphertext; no `@Convert` annotation on the field.
- `email_hmac` has no setter, `updatable=false` (§2.4); plain `String` so encryptor ignores it.
- `status` maps to MySQL native `ENUM` via `@Enumerated(STRING)`.
- Pre-included columns (`token_version`, `email_verified_at`, `failed_attempt_count`,
  `locked_until`, `consent_accepted_at`) freeze the schema so US-002/003/006 need no ALTER.
- `id`/`tenant_id` are `UUID`; `UuidV7Converter` maps to `BINARY(16)`.

#### `RefreshToken` → `refresh_tokens`

```java
@Id @Column(name = "id", length = 16) UUID id;
@Column(name = "user_id",    length = 16, nullable = false) UUID userId;
@Column(name = "token_hash", length = 64, nullable = false) String tokenHash;  // SHA-256 hex
@Column(name = "family_id",  length = 16, nullable = false) UUID familyId;
@Column(name = "expires_at", nullable = false) Instant expiresAt;
@Column(name = "revoked_at") Instant revokedAt;
@Version @Column(name = "version", nullable = false) long version;
@Column(name = "created_at", insertable = false, updatable = false) Instant createdAt;
@Column(name = "updated_at", insertable = false, updatable = false) Instant updatedAt;
```

`user_id` is a raw `UUID` (not `@ManyToOne`) to avoid lazy-load traps. Joins are explicit JPQL
when needed (coding-standards §Performance).

#### `AuthToken` → `auth_tokens`

```java
@Id UUID id;
@Column(name = "user_id", length = 16, nullable = false) UUID userId;
@Enumerated(EnumType.STRING) @Column(name = "type", length = 20, nullable = false) AuthTokenType type;
@Column(name = "token_hash", length = 64, nullable = false) String tokenHash;  // SHA-256 hex, UNIQUE
@Column(name = "expires_at", nullable = false) Instant expiresAt;
@Column(name = "consumed_at") Instant consumedAt;
@Version @Column(name = "version", nullable = false) long version;
@Column(name = "created_at", insertable = false, updatable = false) Instant createdAt;
@Column(name = "updated_at", insertable = false, updatable = false) Instant updatedAt;
```

One table for both VERIFICATION and RESET tokens, discriminated by `type`. `consumed_at` enforces
single-use at the application layer (US-002/US-007).

#### `AuthEvent` → `auth_events`

```java
@Id UUID id;
@Column(name = "user_id",   length = 16) UUID userId;          // nullable — unknown-email attacks
@Column(name = "tenant_id", length = 16) UUID tenantId;        // nullable — pre-auth events
@Column(name = "event_type", length = 64, nullable = false) String eventType;
@Column(name = "outcome",    length = 20, nullable = false) String outcome;
@Column(name = "ip_address", length = 45) String ipAddress;
@Column(name = "metadata",   columnDefinition = "JSON") String metadata;  // traceId, device, etc.
@Column(name = "created_at", insertable = false, updatable = false) Instant createdAt;
// NO updated_at, NO @Version — append-only
```

- `event_type`/`outcome` are free `String` (not enums) — the audit vocabulary grows independently
  of code and must accept new event types without schema changes.
- `metadata` is MySQL `JSON`; under H2 `create-drop` Hibernate maps it as CLOB-compatible.
- No FK: `user_id`/`tenant_id` are nullable; an audit record must survive even if it references an
  unknown principal.

### 4b. Enum designs

- `UserStatus { PENDING, ACTIVE, LOCKED, DISABLED }` — `@Enumerated(STRING)`, column
  `ENUM('PENDING','ACTIVE','LOCKED','DISABLED') DEFAULT 'PENDING'`.
- `AuthTokenType { VERIFICATION, RESET }` — `@Enumerated(STRING)`, column
  `ENUM('VERIFICATION','RESET')`.

Both enums get behavioural tests contributing to the 90% domain gate.

### 4c. `AuthConstants`

```java
public final class AuthConstants {
  public static final int AUTH_REFRESH_TOKEN_TTL_DAYS = 7;
  public static final Duration AUTH_VERIFICATION_TOKEN_TTL = Duration.ofHours(24);
  public static final Duration AUTH_RESET_TOKEN_TTL = Duration.ofMinutes(60);
  private AuthConstants() { throw new AssertionError("no instances"); }
}
```

Covered by `AuthConstantsTest` including reflective private-ctor invocation (§2.8).

---

## 5. Infrastructure Layer

### 5a. `UuidV7Converter`

- `@Converter(autoApply = true)` implementing `AttributeConverter<UUID, byte[]>`.
- `convertToDatabaseColumn(UUID)` → 16-byte big-endian. `convertToEntityAttribute(byte[])` →
  reconstructed `UUID`. Null-safe both directions.
- Auto-applied to every `UUID` field across all four entities → `BINARY(16)` storage.
- No state, thread-safe. Lives in `infrastructure.persistence`; domain entities never import it.

### 5b. `AttributeEncryptor`

- `@Converter(autoApply = true)` implementing `AttributeConverter<EmailCipher, String>`.
- Constructor-injects the `TextEncryptor` bean. JPA converters are managed by Spring via Boot's
  Hibernate `BeanContainer` integration — constructor injection of `TextEncryptor` works.
- `convertToDatabaseColumn(EmailCipher)` → `textEncryptor.encrypt(value.value())` (AES-256-GCM,
  random IV, hex output). `convertToEntityAttribute(String)` → `new EmailCipher(decrypt(cipher))`.
  Null-safe.

### 5c. `EmailBlindIndexService` *(application — §2.2)*

- `@Service` in `identity.application`. Constructor-injects the validated HMAC key `byte[]` from
  `IdentityCryptoConfig`.
- `String blindIndex(String email)`: normalise (`trim` → NFC → `toLowerCase(Locale.ROOT)`) →
  `HMAC-SHA256(normalised, key)` via a **fresh `Mac` instance per call** → lowercase hex (64
  chars).
- Javadoc on the public method documenting the normalisation contract (this is a cross-story
  contract: US-002 must index identically to look up).
- Imports only JDK crypto + Spring `@Service` — zero `infrastructure` imports.

### 5d. `IdentityCryptoConfig` *(key bootstrap)*

- `@Configuration` in `identity.infrastructure.crypto`. Reads the three `nexus.identity.*`
  properties.
- `@Bean TextEncryptor identityTextEncryptor()` → `Encryptors.text(password, salt)`. Throws at
  startup if password/salt absent.
- `@Bean byte[] identityHmacKey()` — decodes and validates: non-null, ≥ 32 bytes; throws
  `IllegalStateException("nexus.identity.hmac-key missing or too short")` if not met.
- Validates `encryption.password`: non-empty, ≥ 16 characters; throws on failure.
- Validates `encryption.salt`: non-empty, ≥ 32 hex characters (16 bytes), valid hex; throws on
  failure. All error messages include the property name, never the value (SEC-T2 resolution).
- Properties documented inline per coding-standards §Configuration.

### 5e. `JpaUserRepository` *(included — §2.3)*

- `interface JpaUserRepository extends JpaRepository<User, UUID>` in `infrastructure.persistence`.
- One derived query: `Optional<User> findByTenantIdAndEmailHmac(UUID tenantId, String emailHmac)`
  → served by `idx_users_tenant_id_email_hmac` UNIQUE index.
- No application port wraps it yet (no use case in US-001); port arrives in US-002.

---

## 6. Database Design

### 6a. Full migration SQL — `V2__identity_schema.sql`

Complete, runnable MySQL 8.4 DDL. All names verified ≤ 64 chars. Naming follows coding-standards.

```sql
-- V2__identity_schema.sql
-- Identity bounded context: tenant-aware user identity + token + audit tables.
-- UUIDv7 primary keys stored as BINARY(16) (ADR-0005).
-- email_cipher: AES-256-GCM at rest (ADR-0006).
-- email_hmac:   HMAC-SHA256 blind index for per-tenant email uniqueness and lookup.
-- auth_events:  append-only, enforced by BEFORE UPDATE/DELETE triggers (NFR-009).
-- Append-only migration (ADR 0003) — never edit after first apply.

-- ---------------------------------------------------------------------------
-- users
-- ---------------------------------------------------------------------------
CREATE TABLE users (
    id                   BINARY(16)                                           NOT NULL,
    tenant_id            BINARY(16)                                           NOT NULL,
    email_cipher         TEXT                                                 NOT NULL,
    email_hmac           VARCHAR(64)                                          NOT NULL,
    status               ENUM('PENDING','ACTIVE','LOCKED','DISABLED')         NOT NULL DEFAULT 'PENDING',
    token_version        INT                                                  NOT NULL DEFAULT 0,
    email_verified_at    DATETIME(6)                                          NULL,
    failed_attempt_count INT                                                  NOT NULL DEFAULT 0,
    locked_until         DATETIME(6)                                          NULL,
    consent_accepted_at  DATETIME(6)                                          NULL,
    version              BIGINT                                               NOT NULL DEFAULT 0,
    created_at           DATETIME(6)                                          NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at           DATETIME(6)                                          NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    CONSTRAINT pk_users PRIMARY KEY (id),
    CONSTRAINT uq_users_tenant_id_email_hmac UNIQUE (tenant_id, email_hmac)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE INDEX idx_users_tenant_id_status ON users (tenant_id, status);

-- ---------------------------------------------------------------------------
-- refresh_tokens
-- ---------------------------------------------------------------------------
CREATE TABLE refresh_tokens (
    id          BINARY(16)  NOT NULL,
    user_id     BINARY(16)  NOT NULL,
    token_hash  VARCHAR(64) NOT NULL,
    family_id   BINARY(16)  NOT NULL,
    expires_at  DATETIME(6) NOT NULL,
    revoked_at  DATETIME(6) NULL,
    version     BIGINT      NOT NULL DEFAULT 0,
    created_at  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    CONSTRAINT pk_refresh_tokens  PRIMARY KEY (id),
    CONSTRAINT uq_refresh_tokens_token_hash UNIQUE (token_hash),
    CONSTRAINT fk_refresh_tokens_users FOREIGN KEY (user_id) REFERENCES users (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE INDEX idx_refresh_tokens_user_id_revoked_at ON refresh_tokens (user_id, revoked_at);
CREATE INDEX idx_refresh_tokens_family_id           ON refresh_tokens (family_id);

-- ---------------------------------------------------------------------------
-- auth_tokens (email verification + password reset)
-- ---------------------------------------------------------------------------
CREATE TABLE auth_tokens (
    id          BINARY(16)                  NOT NULL,
    user_id     BINARY(16)                  NOT NULL,
    type        ENUM('VERIFICATION','RESET') NOT NULL,
    token_hash  VARCHAR(64)                 NOT NULL,
    expires_at  DATETIME(6)                 NOT NULL,
    consumed_at DATETIME(6)                 NULL,
    version     BIGINT                      NOT NULL DEFAULT 0,
    created_at  DATETIME(6)                 NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at  DATETIME(6)                 NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    CONSTRAINT pk_auth_tokens              PRIMARY KEY (id),
    CONSTRAINT uq_auth_tokens_token_hash   UNIQUE (token_hash),
    CONSTRAINT fk_auth_tokens_users        FOREIGN KEY (user_id) REFERENCES users (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE INDEX idx_auth_tokens_user_id_type_consumed_at ON auth_tokens (user_id, type, consumed_at);

-- ---------------------------------------------------------------------------
-- auth_events (append-only audit trail — no updated_at, no FK)
-- ---------------------------------------------------------------------------
CREATE TABLE auth_events (
    id         BINARY(16)  NOT NULL,
    user_id    BINARY(16)  NULL,
    tenant_id  BINARY(16)  NULL,
    event_type VARCHAR(64) NOT NULL,
    outcome    VARCHAR(20) NOT NULL,
    ip_address VARCHAR(45) NULL,
    metadata   JSON        NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT pk_auth_events PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE INDEX idx_auth_events_user_id_created_at    ON auth_events (user_id,    created_at);
CREATE INDEX idx_auth_events_tenant_id_created_at  ON auth_events (tenant_id,  created_at);
CREATE INDEX idx_auth_events_event_type_created_at ON auth_events (event_type, created_at);

-- ---------------------------------------------------------------------------
-- Append-only enforcement on auth_events (NFR-009, AC-5).
-- Single-statement SIGNAL triggers — no BEGIN/END, no DELIMITER.
-- flyway-mysql parses CREATE TRIGGER boundaries natively; DELIMITER is a CLI construct only.
-- ---------------------------------------------------------------------------
CREATE TRIGGER trg_auth_events_no_update
    BEFORE UPDATE ON auth_events
    FOR EACH ROW
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'auth_events is append-only';

CREATE TRIGGER trg_auth_events_no_delete
    BEFORE DELETE ON auth_events
    FOR EACH ROW
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'auth_events is append-only';
```

**`ddl-auto=validate` alignment checklist for implementer:**
- `DATETIME(6)` ↔ `Instant` fields (microsecond precision matches Hibernate's MySQL mapping).
- `version BIGINT` ↔ `@Version long`. `auth_events` intentionally has none.
- `BINARY(16)` ↔ `UUID` via `UuidV7Converter`.
- `status`/`type` ENUM ↔ `@Enumerated(STRING)` with `@Column(length ≥ longest literal)`.
- `email_cipher TEXT` ↔ `EmailCipher` (encryptor → String); map without explicit length.

### 6b. Trigger SQL rationale

Two `BEFORE` triggers raise `SQLSTATE '45000'` (MySQL generic user-defined exception state) on any
attempt to mutate or delete an `auth_events` row, aborting the statement and rolling it back.
This enforces NFR-009 at the database, below the application, so even a buggy service or direct SQL
session cannot tamper with the audit trail (SECURITY.md §10: "never deleted by application code").
`AuthEventsAppendOnlyIT` proves both that the trigger parsed (migration applied) and fires
(UPDATE/DELETE rejected), asserting the exact SQLSTATE.

### 6c. Index strategy rationale

| Index | Serves | Why |
|-------|--------|-----|
| `uq_users_tenant_id_email_hmac` UNIQUE | NFR-001 login lookup; AC-2 uniqueness | Tenant-scoped email uniqueness AND < 10 ms p95 lookup; leading `tenant_id` keeps tenants' rows clustered |
| `idx_users_tenant_id_status` | Admin/lockout queries | Future status-sweep queries; pre-built so no later migration needed |
| `uq_refresh_tokens_token_hash` UNIQUE | Token presentation lookup | Single-row hash lookup; UNIQUE prevents collisions |
| `idx_refresh_tokens_user_id_revoked_at` | Revoke-all-for-user | Logout/lockout revokes live tokens; `revoked_at` lets planner skip revoked rows |
| `idx_refresh_tokens_family_id` | Family revocation | Rotation reuse-detection |
| `uq_auth_tokens_token_hash` UNIQUE | Verify/reset token lookup | Same pattern as refresh tokens |
| `idx_auth_tokens_user_id_type_consumed_at` | Active-token fetch | Verification/reset flows fetch the active unconsumed token |
| `idx_auth_events_user_id_created_at` | Per-user audit timeline (EPIC-007) | Audit UI lists a user's events newest-first |
| `idx_auth_events_tenant_id_created_at` | Per-tenant audit timeline | Tenant-scoped audit views |
| `idx_auth_events_event_type_created_at` | Security monitoring | "All failed logins in time window" queries |

---

## 7. Configuration

### 7a. `application.yml` additions (base — no prod defaults)

```yaml
# Identity context crypto material — REQUIRED in every Flyway-enabled environment.
# Missing key → fast-fail startup (SECURITY.md §1). Source from Vault/env vars.
nexus:
  identity:
    encryption:
      password: ${NEXUS_IDENTITY_ENCRYPTION_PASSWORD}  # AES-256-GCM master password
      salt: ${NEXUS_IDENTITY_ENCRYPTION_SALT}          # hex-encoded KDF salt (Encryptors.stronger)
    hmac-key: ${NEXUS_IDENTITY_HMAC_KEY}               # HMAC-SHA256 key for email blind index (>=32 bytes)
```

### 7b. `application-dev.yml` placeholder keys (non-secret, dev-only)

```yaml
# DEV ONLY — non-secret placeholder keys for local development without a vault.
# MUST NOT be used in shared/staging/prod environments.
nexus:
  identity:
    encryption:
      password: dev-not-a-secret-encryption-password
      salt: deadbeefdeadbeefdeadbeefdeadbeef
    hmac-key: dev-not-a-secret-hmac-key-min-32-bytes-long
```

### 7c. `application-test.properties` (H2 smoke) and IT key injection

Add to `application-test.properties`:
```properties
nexus.identity.encryption.password=test-not-a-secret-encryption-password
nexus.identity.encryption.salt=cafebabecafebabecafebabecafebabe
nexus.identity.hmac-key=test-not-a-secret-hmac-key-min-32-bytes!!
```

For `*IT` (Testcontainers context): inject via `@DynamicPropertySource` in a shared
`AbstractIdentityIT` base class (or extend `TestcontainersConfiguration`). `EmailBlindIndexServiceTest`
(pure unit) constructs the service with a literal test key — no Spring context needed.

---

## 8. ADR Outlines

### ADR-0005 — UUIDv7 primary keys (`docs/adr/0005-uuidv7-primary-keys.md`)

- **Status:** Accepted. **Supersedes:** ULID preference in `docs/coding-standards.md` line 29.
- **Context:** Identity tables need globally-unique, non-enumerable, index-friendly PKs; coding-standard currently suggests CHAR(26) ULID.
- **Decision:** UUIDv7 stored as `BINARY(16)`, generated via `com.github.f4b6a3:uuid-creator` (`getTimeOrderedEpoch()`), minted behind a `UuidGenerator` port.
- **Rationale:** time-ordered → sequential B-tree inserts; 16 bytes vs 26 chars → smaller FKs/indexes; native UUID type interop across JDBC/JPA.
- **Alternatives:** ULID CHAR(26) (larger, non-native); UUIDv4 (random → fragmentation); DB auto-increment (enumerable, leaks volume).
- **Consequences:** new pinned MIT dependency; BINARY(16) less human-readable (mitigated by `BIN_TO_UUID()` in ad-hoc queries); generator is injectable/testable; coding-standard must be updated to reference this ADR.

### ADR-0006 — Email blind index + at-rest encryption (`docs/adr/0006-email-blind-index-and-encryption.md`)

- **Status:** Accepted.
- **Context:** Email is PII (SECURITY.md §7), must be encrypted at rest, yet login requires exact-match lookup. AES-256-GCM is non-deterministic (random IV) → cannot index/look up on ciphertext.
- **Decision:** Two columns: `email_cipher` (AES-256-GCM via `Encryptors.stronger`, auto-applied `@Converter` keyed on `EmailCipher` domain value type) and `email_hmac` (deterministic HMAC-SHA256 blind index, lowercase-normalised, computed by `EmailBlindIndexService`). Uniqueness and lookup use `(tenant_id, email_hmac)`. Converter convention: "persistence converters are auto-applied from infrastructure keyed on domain value types; domain entities never reference a converter class."
- **Alternatives:** deterministic encryption (weaker, leaks equality); plaintext + DB-level encryption only (no app-layer PII control); decrypt-all-rows search (O(n), violates NFR-001).
- **Consequences / HMAC key rotation runbook:** rotating `NEXUS_IDENTITY_HMAC_KEY` invalidates every `email_hmac` — requires expand/contract re-index migration (add column, dual-write, backfill, swap, drop). Encryption key rotation requires decrypt-with-old/encrypt-with-new backfill. Both runbooks documented here.

---

## 9. Test Design

### 9a. Unit tests (no Spring context)

| Test class | Asserts |
|------------|---------|
| `EmailBlindIndexServiceTest` | Determinism (same email → same 64-char hex); case/whitespace normalisation (`A@B.COM ` ≡ `a@b.com`); distinctness (different emails → different hash); 64-char lowercase-hex format. Instantiated with a literal test key. (Scenarios 8, 9) |
| `AuthConstantsTest` | Each constant's value; reflective private-ctor invocation for line coverage (§2.8). |
| `UuidV7ConverterTest` | Round-trip `UUID → byte[16] → UUID`; null-safety; 16-byte length; big-endian ordering. |
| `UserStatusTest` / `AuthTokenTypeTest` | Enum value set and any helpers — contributes to 90% domain gate. |

### 9b. Integration tests (`*IT`, Testcontainers MySQL 8.4)

| Test class | Test methods | Asserts |
|------------|-------------|---------|
| `IdentitySchemaMigrationIT` | `should_createAllTables_when_migrationsApplied`; `should_createExpectedIndexes_when_migrationsApplied`; `should_keepFlywayChecksumStable_when_rerun` | All 4 tables, all columns, all indexes in `information_schema`; Flyway V2 checksum stable (AC-1, AC-4, AC-6 / Scenario 1) |
| `UserUniquenessIT` | `should_rejectDuplicate_when_sameTenantSameEmailHmac`; `should_persistBoth_when_sameEmailHmacDifferentTenant` | Duplicate `(tenant_id, email_hmac)` → constraint violation; same `email_hmac` different `tenant_id` → both persist (AC-2 / Scenarios 2, 3) |
| `EmailCipherEncryptionIT` | `should_storeCiphertext_when_userPersisted`; `should_decryptTransparently_when_userLoaded` | Native query on `email_cipher` returns ciphertext ≠ plaintext; JPA reload decrypts to original (AC-3 / Scenario 4) |
| `AuthEventsAppendOnlyIT` | `should_rejectUpdate_when_authEventModified`; `should_rejectDelete_when_authEventDeleted`; `should_leaveRowUnchanged_when_updateRejected` | UPDATE/DELETE each raise SQLSTATE '45000'; row unchanged (AC-5 / Scenarios 5, 6) |
| `UserQueryPerformanceIT` *`@Tag("perf")`* | `should_lookupUnder10msP95_when_1MRowFixture` | 1M-row fixture; `findByTenantIdAndEmailHmac` p95 < 10 ms; `EXPLAIN` confirms `uq_users_tenant_id_email_hmac` used (NFR-001 / Scenario 7). Runs in dedicated CI lane. |
| `NexusApplicationIT` (existing) | unchanged | Now implicitly boots V2 + JPA `validate`; needs `@DynamicPropertySource` test keys. Catches entity/column drift. |

### 9c. Coverage strategy

- **domain ≥ 90%:** entities exercised by `*IT` persistence tests + enum/constants unit tests + reflective ctor for `AuthConstants`. Configure `lombok.config` with `lombok.addLombokGeneratedAnnotation=true` so JaCoCo ignores generated accessors.
- **application ≥ 85%:** `EmailBlindIndexServiceTest` covers `EmailBlindIndexService` end to end.
- **infrastructure ≥ 70%:** `*IT` suite drives converters, config, repository. `UuidV7ConverterTest` adds pure coverage.
- **bundle ≥ 80%:** IT + unit suite combined. `IdentityCryptoConfig` is NOT JaCoCo-excluded (it is not under `**/config/**`) and is exercised by every encryption IT.

---

## 10. Observability

- **Startup INFO log:** `IdentityCryptoConfig` logs successful initialisation of the encryptor and
  HMAC key (fact + key-length category only — never the value).
- **Fail-fast ERROR log:** missing/weak key causes bean-creation failure; Spring logs the property
  name (not value) at ERROR level.
- **Flyway:** existing INFO logging records V2 application; no change needed.
- **MDC / correlation:** unchanged — existing `CorrelationIdFilter` provides `traceId`. The
  `auth_events.metadata` JSON column is designed to carry `traceId`, IP, and device fields when
  US-002+ start writing audit rows (SECURITY.md §10 schema).
- **PII masking (downstream note):** when audit writing lands, emails in logs must be masked
  `u***@example.com` (SECURITY.md §7). US-001 only sizes the columns.
- **Metrics:** no new Micrometer metrics in US-001. First `identity.user.lookup` timer lands
  with the US-003 login endpoint.

---

## 11. Rollout / Feature Flag

- **Feature flag: none.** US-001 adds inert schema, entities, and crypto beans with no runtime
  entry point. First flag candidate is the auth endpoint in US-003.
- **Rollout type: instant / single-step.** Purely additive; ships as one Flyway forward migration
  plus new beans.
- **Pre-deploy checklist:**
  1. `NEXUS_IDENTITY_ENCRYPTION_PASSWORD`, `NEXUS_IDENTITY_ENCRYPTION_SALT`,
     `NEXUS_IDENTITY_HMAC_KEY` set in the target environment's secret store.
  2. ADR-0005 and ADR-0006 accepted and merged.
  3. `mvn verify` fully green including ArchUnit and per-layer JaCoCo; `perf`-tagged IT green in
     its CI lane.
  4. `-Psecurity` dependency-check clean for `uuid-creator`.
- **Rollback:** deploy prior application version; new tables remain unused and harmless. No
  down-migration written (Flyway forward-only). Emergency rollback of the migration itself requires
  a new `V3` drop migration — never an edit to V2 (ADR 0003).

---

## 12. Out of Scope (confirmed)

- No `@RestController`, DTOs, OpenAPI paths, or API versioning work.
- No Angular code of any kind.
- No Spring Security changes; no JWT, login, refresh, logout, lockout, or password-reset logic.
- No `identity.interfaces` package.
- No application-layer use-case service beyond `EmailBlindIndexService`.
- No `UserRepository` port in `application` (no consumer yet; arrives in US-002).
- No Redis / cache.
- No audit-write code; `auth_events` schema + triggers only.

---

## Files to create / modify

| Action | Path |
|--------|------|
| CREATE | `nexus-backend/src/main/resources/db/migration/V2__identity_schema.sql` |
| CREATE | `nexus-backend/src/main/java/com/example/nexus/identity/domain/*.java` (9 files) |
| CREATE | `nexus-backend/src/main/java/com/example/nexus/identity/application/EmailBlindIndexService.java` |
| CREATE | `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/persistence/*.java` (3 files) |
| CREATE | `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/crypto/*.java` (2 files) |
| CREATE | `docs/adr/0005-uuidv7-primary-keys.md` |
| CREATE | `docs/adr/0006-email-blind-index-and-encryption.md` |
| MODIFY | `nexus-backend/pom.xml` — add 2 dependencies |
| MODIFY | `nexus-backend/src/main/resources/application.yml` — add `nexus.identity.*` config keys |
| MODIFY | `nexus-backend/src/main/resources/application-dev.yml` — add dev placeholder keys |
| MODIFY | `nexus-backend/src/test/resources/application-test.properties` — add test keys |
| MODIFY | `nexus-backend/src/test/java/…/TestcontainersConfiguration.java` — add `@DynamicPropertySource` for IT key injection |
| MODIFY | `docs/coding-standards.md` line 29 — update ULID preference to reference ADR-0005 |
