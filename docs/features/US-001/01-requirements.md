# Requirements Analysis — US-001

**Status:** APPROVED — Gate 1 passed <br>
**Feature:** US-001 — Establish tenant-aware identity data model and migrations <br>
**Epic:** EPIC-001 — Identity & Access — Enterprise Authentication Foundation <br>
**Date:** 2026-06-14

---

## Gate 1 Decision Log

| Ref | Decision | Rationale |
|-----|----------|-----------|
| OQ-001 | **UUIDv7 as platform ID type** | Overrides ULID coding standard; ADR-001 required before merge to update platform standard |
| OQ-002 | **Blind-index pattern for email uniqueness** | MySQL 8.4 has no citext; generated column on plaintext incompatible with encryption (OQ-006) |
| OQ-003 | **`name` column dropped** | No collection form in US-002 scope; will be added in a future profile story |
| OQ-004 | **`token_version` included in this migration** | US-003 JWT contract references it; deferring forces ALTER on the highest-traffic table |
| OQ-005 | **BEFORE UPDATE / BEFORE DELETE triggers enforce append-only on `auth_events`** | MySQL 8.4 Community has no row-level security; triggers are the viable enforcement layer |
| OQ-006 | **Blind-index pattern approved (Security sign-off recorded)** | AES-256-GCM (non-deterministic) cannot be indexed; `email_cipher` + `email_hmac` replaces single email column |
| OQ-007 | **Refresh token TTL = 7 days** | Aligns with SECURITY.md; overrides 14-day value in EPIC-001 discovery doc |
| OQ-008 | **"Rollback test" redefined** | Flyway Community has no undo; AC-5 now means Testcontainers clean-forward migration in CI |
| RISK-001 | **`email_verified_at` added to `users`** | Required by US-002 (Sprint 1); omitting forces mid-sprint ALTER |

---

## 1. Story Summary

US-001 establishes the tenant-aware identity data model that underpins every other feature in the
Nexus platform. It delivers four new database tables (`users`, `refresh_tokens`, `auth_tokens`,
`auth_events`) via a single Flyway migration (`V2__identity_schema.sql`), along with JPA domain
entities in a new `identity` bounded context (`com.example.nexus.identity`). No API endpoints are
exposed and no frontend changes are made.

Target database is MySQL 8.4 Community. Key design constraints resolved at Gate 1: email PII is
stored encrypted (AES-256-GCM) and looked up via an HMAC blind index; UUIDv7 is the canonical ID
type for the platform (ADR-001 required); `auth_events` append-only semantics are enforced via
database triggers (row-level security is unavailable in MySQL Community); schema is frozen via ADR
review before merge — no ALTER TABLE is acceptable once downstream stories begin.

Every story in EPIC-001 (US-002 → US-008) and all future epics are blocked on this.

---

## 2. Functional Requirements

**FR-001** — A Flyway migration file `V2__identity_schema.sql` must be created in
`nexus-backend/src/main/resources/db/migration/`. It must create all four tables defined below in a
single script. Append-only; never edit after first application (ADR 0003).

**FR-002** — The migration must create the `users` table with the exact column list in § 6 below.

**FR-003** — Email uniqueness must be enforced per-tenant via a UNIQUE index on
`(tenant_id, email_hmac)` (the blind-index pattern — see Technical Notes and ADR-002). Plaintext
email must never be stored.

**FR-004** — The migration must create the `refresh_tokens` table with the exact column list in § 6
below.

**FR-005** — The migration must create the `auth_tokens` table with the exact column list in § 6
below.

**FR-006** — The migration must create the `auth_events` table with the exact column list in § 6
below. No `updated_at` column. No `email` column. Append-only enforced via BEFORE UPDATE and BEFORE
DELETE triggers that SIGNAL SQLSTATE '45000'.

**FR-007** — All indexes must follow the `idx_<table>_<columns>` naming convention
(`docs/coding-standards.md`). All foreign keys follow `fk_<from_table>_<to_table>`.

**FR-008** — JPA entity classes must be created for each of the four tables within
`com.example.nexus.identity.domain`. No entity may be returned from a REST controller.

**FR-009** — The bounded context package root must be `com.example.nexus.identity` with
sub-packages `domain`, `application`, `infrastructure`, `interfaces` per ADR 0002. The existing
`HexagonalArchitectureTest` (ArchUnit) must pass.

**FR-010** — `email_cipher` must store AES-256-GCM ciphertext via `Spring Encryptors.stronger()`.
Encryption and HMAC keys are sourced from environment variables / secrets vault only — never from
`application.yml` or source code.

**FR-011** — An `AttributeEncryptor` JPA `@Converter` must handle transparent encryption /
decryption of `email_cipher`. A `@Column(insertable=false, updatable=false)` or equivalent
strategy must prevent JPA from writing or reading `email_hmac` as a plain string — the HMAC is
always computed by `EmailBlindIndexService`, not by the entity setter.

**FR-012** — ADR-001 (UUIDv7 as platform ID type) and ADR-002 (email blind-index + encryption
pattern) must be authored, approved, and merged before this migration is merged. They are
conditions of done, not follow-ups.

**FR-013** — An `AuthConstants.java` class must define `AUTH_REFRESH_TOKEN_TTL_DAYS = 7` (used by
US-004 and US-005) to prevent magic numbers across downstream stories.

---

## 3. Non-Functional Requirements

**NFR-001 (Performance)** — A `users` query on `(tenant_id, email_hmac)` against a 1-million-row
dataset must execute in under 10 ms p95. Requires a data-loading test fixture.

**NFR-002 (Security — PII encryption)** — `email_cipher` stores AES-256-GCM ciphertext produced by
`Encryptors.stronger()`. Reading the raw DB column must return ciphertext, not plaintext.

**NFR-003 (Security — Blind index)** — `email_hmac` is `HMAC-SHA256(LOWER(email), hmac_secret_key)`
with the key sourced from vault. The plaintext email is never stored. The HMAC key must be rotatable
(runbook documented in ADR-002).

**NFR-004 (Security — Token hashing)** — `token_hash` columns in `refresh_tokens` and `auth_tokens`
store SHA-256 digests of the raw token. Raw values are never persisted.

**NFR-005 (Security — Append-only audit)** — BEFORE UPDATE and BEFORE DELETE triggers on
`auth_events` must SIGNAL SQLSTATE '45000'. Tests must confirm both operations are rejected.

**NFR-006 (Security — Key management)** — All secret keys (encryption password, HMAC key) are
environment-variable or vault-sourced. They must never appear in code, YAML, or migration SQL.

**NFR-007 (Scalability)** — `tenant_id` is the leading column in all composite indexes to support
future table partitioning by tenant.

**NFR-008 (Testability)** — Integration tests (`*IT`) use Testcontainers MySQL 8.4 and cover all
acceptance criteria. No H2 for integration tests (`ARCHITECTURE.md` non-negotiable 8).

**NFR-009 (Observability)** — `users`, `refresh_tokens`, `auth_tokens` use JPA auditing
(`@CreatedDate`, `@LastModifiedDate`) for `created_at` / `updated_at`. `auth_events` has no
`updated_at` by design.

**NFR-010 (Privacy)** — No `email` column in `auth_events`. `email_hmac` and `email_cipher` exist
only on `users`.

**NFR-011 (Coverage gate)** — JaCoCo: `*.identity.domain` ≥ 90% line; `*.identity.application`
≥ 85% line (enforced in `pom.xml`).

---

## 4. Acceptance Criteria

| # | Criterion | Definition of Done | Priority | Notes |
|---|-----------|-------------------|----------|-------|
| 1 | `users` table created with all columns | Flyway migration `V2__identity_schema.sql` creates `users` with every column in the explicit list; schema verified via Testcontainers assertion | P0 | UUIDv7 stored as BINARY(16) |
| 2 | Email uniqueness is per-tenant via blind index | UNIQUE `(tenant_id, email_hmac)` enforced; inserting a duplicate `email_hmac` within the same `tenant_id` raises a constraint violation; same email in a different tenant succeeds | P0 | Plaintext email never stored |
| 3 | Email PII encrypted at rest | `email_cipher` stores AES-256-GCM ciphertext via `Spring Encryptors.stronger()`; reading the raw column value returns ciphertext, not plaintext; approach documented in ADR-002 | P0 | `name` column out of scope (OQ-003) |
| 4 | Supporting tables created with explicit columns | `refresh_tokens`, `auth_tokens`, `auth_events` created with all columns and indexes per the explicit lists | P0 | |
| 5 | `auth_events` append-only enforced | BEFORE UPDATE and BEFORE DELETE triggers on `auth_events` raise SIGNAL SQLSTATE '45000'; test confirms both UPDATE and DELETE fail with that state | P0 | MySQL 8.4 has no RLS; triggers are the enforcement layer (OQ-005) |
| 6 | Migration verified clean-forward in CI | Testcontainers spins a fresh MySQL 8.4 instance, applies all Flyway migrations from baseline, and asserts all 4 tables and their indexes exist; pipeline green on every build | P1 | "Rollback test" redefined per OQ-008 |

---

## 5. Test Scenarios

| # | Scenario | Type | Expected Result |
|---|----------|------|-----------------|
| 1 | Testcontainers: clean MySQL 8.4 → apply migrations → assert schema | Integration | All 4 tables, all columns, all indexes present; Flyway checksum stable |
| 2 | Duplicate `email_hmac` same `tenant_id` | Integration | Unique constraint violation |
| 3 | Same `email_hmac` in different `tenant_id` | Integration | Both rows persist |
| 4 | Read `email_cipher` directly from DB | Security | Ciphertext returned; plaintext not recoverable without vault key |
| 5 | UPDATE any row in `auth_events` | Security | SQLSTATE '45000' raised; row unchanged |
| 6 | DELETE any row in `auth_events` | Security | SQLSTATE '45000' raised; row unchanged |
| 7 | Insert 1M rows into `users`; query by `(tenant_id, email_hmac)` | Performance | < 10 ms p95 index lookup |
| 8 | Two different plaintext emails produce different `email_hmac` values | Unit | Distinct hashes confirmed |
| 9 | Same plaintext email always produces the same `email_hmac` | Unit | Deterministic HMAC confirmed |

---

## 6. Explicit Column Lists (approved at Gate 1)

### Table: `users`

| Column | Type | Constraints | Notes |
|--------|------|-------------|-------|
| `id` | BINARY(16) | PK | UUIDv7, stored as bytes |
| `tenant_id` | BINARY(16) | NOT NULL | FK placeholder; no tenant table yet |
| `email_cipher` | TEXT | NOT NULL | AES-256-GCM via `Spring Encryptors.stronger()` |
| `email_hmac` | VARCHAR(64) | NOT NULL | HMAC-SHA256 of LOWER(email); unique lookup key |
| `password_hash` | VARCHAR(255) | NOT NULL | Argon2id output |
| `status` | ENUM('PENDING','ACTIVE','LOCKED','DISABLED') | NOT NULL DEFAULT 'PENDING' | |
| `identity_provider` | VARCHAR(32) | NOT NULL DEFAULT 'LOCAL' | Extension point for SSO/federation |
| `email_verified_at` | TIMESTAMP | NULL | Set by US-002 on verification |
| `consent_accepted_at` | TIMESTAMP | NULL | GDPR lawful-basis capture |
| `token_version` | INT | NOT NULL DEFAULT 0 | Mass-invalidation counter for US-003 JWT |
| `failed_attempt_count` | INT | NOT NULL DEFAULT 0 | Brute-force counter for US-006 |
| `locked_until` | TIMESTAMP | NULL | Auto-expiring lockout for US-006 |
| `created_at` | TIMESTAMP | NOT NULL DEFAULT CURRENT_TIMESTAMP | |
| `updated_at` | TIMESTAMP | NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP | |

Indexes: `UNIQUE (tenant_id, email_hmac)`, `INDEX (tenant_id, status)`

### Table: `refresh_tokens`

| Column | Type | Constraints | Notes |
|--------|------|-------------|-------|
| `id` | BINARY(16) | PK | UUIDv7 |
| `user_id` | BINARY(16) | NOT NULL FK → users.id | |
| `family_id` | BINARY(16) | NOT NULL | Reuse-detection scope |
| `token_hash` | VARCHAR(64) | NOT NULL | SHA-256 of opaque token |
| `expires_at` | TIMESTAMP | NOT NULL | 7 days (OQ-007) |
| `revoked_at` | TIMESTAMP | NULL | Set on rotation or logout |
| `created_at` | TIMESTAMP | NOT NULL DEFAULT CURRENT_TIMESTAMP | |

Indexes: `UNIQUE (token_hash)`, `INDEX (user_id, revoked_at)`, `INDEX (family_id)`

### Table: `auth_tokens`

| Column | Type | Constraints | Notes |
|--------|------|-------------|-------|
| `id` | BINARY(16) | PK | UUIDv7 |
| `user_id` | BINARY(16) | NOT NULL FK → users.id | |
| `type` | ENUM('VERIFICATION','RESET') | NOT NULL | |
| `token_hash` | VARCHAR(64) | NOT NULL | SHA-256; entropy ≥ 128 bits |
| `expires_at` | TIMESTAMP | NOT NULL | 24h (VERIFICATION), 1h (RESET) |
| `consumed_at` | TIMESTAMP | NULL | Set on single-use consumption |
| `created_at` | TIMESTAMP | NOT NULL DEFAULT CURRENT_TIMESTAMP | |

Indexes: `UNIQUE (token_hash)`, `INDEX (user_id, type, consumed_at)`

### Table: `auth_events`

| Column | Type | Constraints | Notes |
|--------|------|-------------|-------|
| `id` | BINARY(16) | PK | UUIDv7 |
| `event_type` | VARCHAR(64) | NOT NULL | LOGIN_SUCCESS, LOGIN_FAILURE, LOCKOUT, LOGOUT, REGISTER, VERIFY, PASSWORD_RESET_REQUESTED, PASSWORD_CHANGED, TOKEN_REFRESH_REUSE |
| `user_id` | BINARY(16) | NULL | NULL for unknown-email attempts |
| `tenant_id` | BINARY(16) | NULL | NULL for pre-auth events |
| `source_ip` | VARCHAR(45) | NULL | IPv4 and IPv6 |
| `user_agent` | VARCHAR(512) | NULL | |
| `outcome` | VARCHAR(16) | NOT NULL | SUCCESS / FAILURE |
| `correlation_id` | VARCHAR(36) | NULL | Trace ID from request header |
| `created_at` | TIMESTAMP | NOT NULL DEFAULT CURRENT_TIMESTAMP | UTC |

Append-only enforced via BEFORE UPDATE and BEFORE DELETE triggers (SIGNAL SQLSTATE '45000').
Indexes: `INDEX (user_id, created_at)`, `INDEX (tenant_id, created_at)`, `INDEX (event_type, created_at)`

---

## 7. Technical Notes (ARC)

- **Migration file:** `V2__identity_schema.sql` in `src/main/resources/db/migration`; baseline is `V1__baseline.sql`
- **ID strategy:** UUIDv7 generated in the application layer (`com.github.f4b6a3:uuid-creator`); stored as BINARY(16); ADR-001 to update platform coding standard before merge
- **Email blind index:** `EmailBlindIndexService` — `HMAC-SHA256(LOWER(email), hmac_secret_key)`; `hmac_secret_key` sourced from secrets vault; documented in ADR-002
- **Encryption:** `Spring Encryptors.stronger(encryption_password, salt)` for `email_cipher`; keys from secrets vault; never logged or serialised into tokens
- **JPA entities:** in bounded context `com.example.nexus.identity`; `@Converter` for BINARY(16) ↔ UUID; `AttributeEncryptor` for `email_cipher`
- **`auth_events` triggers:** created in the Flyway migration; BEFORE UPDATE and BEFORE DELETE both SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'auth_events is append-only'
- **Refresh token TTL constant:** `AUTH_REFRESH_TOKEN_TTL_DAYS = 7` defined in `AuthConstants.java`; used by US-004
- **Feature flag required:** No
- **ADRs required before merge:** ADR-001 (UUIDv7 as platform ID type), ADR-002 (email blind-index + encryption pattern)

---

## 8. Dependencies

| Dependency | Direction | Status | Note |
|---|---|---|---|
| `V1__baseline.sql` | Required predecessor | Present (comment-only) | No conflicts |
| `com.github.f4b6a3:uuid-creator` | New runtime dependency | Not in `pom.xml` | Must be added; confirm license (MIT) |
| `spring-security-crypto` | Required at runtime | Transitive via `spring-boot-starter-security` | Validate with `./mvnw dependency:tree`; should be added explicitly |
| ADR-001 (UUIDv7) | Required before merge | Does not exist | Condition of done |
| ADR-002 (blind-index + encryption) | Required before merge | Does not exist | Condition of done |
| Secrets vault / env vars | Required at runtime | Not configured for dev | Must exist in every environment before startup |
| Testcontainers MySQL 8.4 | Integration tests | Already wired | CI matches prod DB version |
| US-002 through US-008 | Downstream | Blocked on US-001 | |
| EPIC-007 (Audit Log UI) | Future consumer | Blocked on US-001 | `auth_events` schema contract must be stable |

---

## 9. Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| ADR-001 / ADR-002 sign-off delays Sprint 1 start | Med | High | Parallel-path: start ADR drafts in pre-sprint; migration cannot merge without both |
| HMAC key rotation requires re-hashing all `email_hmac` values | Low | High | Document key-rotation runbook in ADR-002 before merge |
| Trigger-based append-only bypassable by DBA/root | Low | Med | Acceptable for MVP; SIEM/external append-only store is the long-term control |
| UUIDv7 library not yet on approved dependency list | Med | Med | Add `com.github.f4b6a3:uuid-creator` to bill-of-materials in ADR-001 |

---

## 10. Out of Scope

- `name` column and any profile data (future profile story — OQ-003)
- Role/permission tables (RBAC epic)
- Org/tenant management tables (Epic 3 — `tenant_id` is a raw column, not yet a FK)
- Flyway undo migrations (Teams feature; not available in Community)
- Any REST API endpoints, controllers, or DTOs
- Any Angular frontend changes
- JWT library and signing key infrastructure (US-003)
- Redis integration (US-006)
