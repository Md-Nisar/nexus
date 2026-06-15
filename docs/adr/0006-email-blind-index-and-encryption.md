# ADR 0006 — Email Blind Index + At-Rest Encryption

**Status:** Accepted
**Date:** 2026-06-14
**Author:** Engineering Team

## Context

Email addresses are PII under GDPR/PDPA and must be encrypted at rest per SECURITY.md §7. The platform needs to:
1. Store email encrypted in the database (column level, application-managed)
2. Look up users by exact email match per tenant (login, deduplication)
3. Enforce per-tenant uniqueness on email

Standard AES-256-GCM (as provided by `Encryptors.text()` / `Encryptors.stronger()`) uses a random initialisation vector (IV) per encryption — the same plaintext email produces different ciphertext each time. This non-determinism is a security property (prevents frequency analysis) but makes exact-match lookup impossible on the ciphertext column.

Options considered:
- **Deterministic encryption** (fixed IV, AES-ECB, or SIV mode): allows lookup but leaks email equality across rows — two users with the same email at different tenants have identical ciphertext, enabling correlation attacks.
- **Decrypt-all-rows search**: O(n) scan with decryption per row — violates the < 10 ms p95 lookup NFR.
- **Blind index**: a separate deterministic column containing a keyed hash (HMAC-SHA256) of the normalised plaintext email. The ciphertext column stores the encrypted email (non-deterministic, unindexable); the hash column is indexed and searched. Breaking the hash requires knowing the HMAC key — a secret not present in the database.

## Decision

**Two-column design for email storage:**

1. `email_cipher TEXT NOT NULL` — AES-256-GCM ciphertext produced by `Encryptors.text(password, salt)` from Spring Security Crypto. Random IV per call → non-deterministic → NOT indexed. Decrypted on read via a JPA `@Converter(autoApply=true)` keyed on the `EmailCipher` domain value type (`record EmailCipher(String value)` in `identity.domain`). Domain entities declare `EmailCipher emailCipher` — never a raw `String` — so the wrong type cannot be assigned accidentally.

2. `email_hmac VARCHAR(64) NOT NULL` — deterministic HMAC-SHA256 of the normalised email, hex-encoded (64 chars). Computed by `EmailBlindIndexService` in `identity.application` using a separate secret key (`nexus.identity.hmac-key`). Per-tenant unique index `uq_users_tenant_id_email_hmac (tenant_id, email_hmac)` enables exact-match lookup and enforces uniqueness.

**Normalisation contract (must be identical on every write and lookup):** `email.trim() → NFC Unicode normalisation → toLowerCase(Locale.ROOT)`. This contract is pinned on `EmailBlindIndexService` and must never change without an expand/contract re-index migration. Future stories (US-002+) must call `EmailBlindIndexService.blindIndex()` — never re-implement the normalisation.

**Converter convention:** Persistence converters are auto-applied from `infrastructure.persistence` keyed on domain value types; domain entities never reference a converter class. This is what keeps ArchUnit's `domain_must_not_depend_on_outer_layers` rule green — the entity field type is `EmailCipher` (a domain type), not `AttributeEncryptor` (an infrastructure class).

**Crypto provider:** AES-256-GCM via JDK-native `SunJCE` provider (Java 8+, confirmed on Java 25). No Bouncy Castle dependency. Confirmed via `mvn dependency:tree` in T-001.

## Security properties

- `email_cipher` leaks nothing about the plaintext (non-deterministic GCM with AEAD integrity; tampered ciphertext fails decryption and throws, never silently returns null or wrong plaintext).
- `email_hmac` leaks email equality within a tenant (two users with the same email have the same hmac) — this is the **accepted equality-leak residual**. Cross-tenant leakage is mitigated by the per-tenant unique index design (`tenant_id` is always in the WHERE clause).
- The HMAC key is a separate secret from the encryption password/salt — compromise of one does not compromise the other.

## Security mitigations included

**SEC-T4 — Least-privilege DB grant and append-only bypass:**
- The runtime application database user must have: `SELECT, INSERT, UPDATE, DELETE` only on the identity tables. No `DDL`, no `TRUNCATE`, no `DROP`.
- The Flyway migration user is a separate database user with DDL privileges, used only during schema migrations.
- TRUNCATE bypass risk on `auth_events`: a DBA-level `TRUNCATE` bypasses the `BEFORE DELETE` trigger. This is documented as an accepted residual risk controlled by DBA access controls and least-privilege grants, not by application code.
- `password_hash` (future column, added in a later migration) must store only Argon2id output — enforced by the application layer, not the DB schema.

**SEC-T9 — NFC normalisation + Locale.ROOT:**
- Turkish locale's dotted/dotless `I` (`İ` / `ı`) diverges between `toLowerCase()` and `toLowerCase(Locale.ROOT)`. `Locale.ROOT` is mandatory for cross-locale stability.
- NFC normalisation ensures composed vs decomposed Unicode forms (`é` = U+00E9 vs `e` + U+0301) hash identically.

**SEC-T10 — HMAC oracle and token entropy:**
- Future US-002 lookup endpoints must return constant-time responses for found vs not-found email (no timing oracle exposing whether an email exists).
- Token columns in `refresh_tokens` and `auth_tokens` must be populated with ≥ 128-bit `SecureRandom` entropy (to be enforced in US-002/US-007 implementation).

## Key rotation runbooks

**HMAC key rotation (nexus.identity.hmac-key):**
Rotating the HMAC key invalidates every stored `email_hmac` — all rows have the old hash, making all lookups fail.
Procedure (expand/contract):
1. Add `email_hmac_new VARCHAR(64) NULL` column (new migration).
2. Deploy new app version that dual-writes both columns using the new key.
3. Backfill `email_hmac_new` for existing rows (background job or migration).
4. Swap the unique index to `(tenant_id, email_hmac_new)`.
5. Drop `email_hmac` column (new migration); rename `email_hmac_new` → `email_hmac`.
6. Deploy app version that writes only `email_hmac` with new key.

**Encryption key rotation (nexus.identity.encryption.password + salt):**
1. Deploy app version with both old and new keys available.
2. Background job: decrypt each `email_cipher` with old key, re-encrypt with new key, save.
3. Remove old key from configuration once all rows are re-encrypted.

## Alternatives considered

**Deterministic encryption (AES-SIV or fixed IV):**
- Allows lookup without a separate hash column.
- Leaks email equality (two rows with same plaintext have same ciphertext) — ruled out on privacy grounds.

**Decrypt-all-rows on lookup:**
- Simple to implement.
- O(n) with per-row decryption — violates < 10 ms p95 NFR at scale. Ruled out.

**Database-level encryption (MySQL TDE):**
- Protects against storage theft but not against a compromised DB user — the DB engine decrypts on the fly.
- No application-layer PII control.
- Does not solve the unique-index problem.
- Ruled out as insufficient on its own; may be used in addition as a defence-in-depth layer.

**Full email as plain HMAC (no encryption):**
- Allows lookup without `email_cipher`.
- HMAC is not reversible but is queryable; if the HMAC key leaks, brute-force lookup is feasible for known email patterns.
- Ruled out: SECURITY.md §7 requires encryption, not just hashing.

## Consequences

Positive:
- Email is encrypted at rest with AEAD integrity (tamper detection).
- Exact-match lookup at < 10 ms p95 via the blind index.
- Domain entities are clean (`EmailCipher` typed field, no `@Convert` annotation).
- Two independent secrets (encryption vs HMAC) limit blast radius.

Negative:
- Two columns per email instead of one; two secret keys to manage.
- HMAC key rotation requires a multi-step expand/contract migration.
- `email_hmac` equality-leak residual is accepted.

Follow-on:
- All future stories that write email must call `EmailBlindIndexService.blindIndex()` with the identical normalisation contract.
- Least-privilege DB grant must be applied in all environments at first deploy.
- Token entropy enforcement: US-002 and US-007 must use `SecureRandom` with ≥ 128-bit output for `token_hash` columns.
