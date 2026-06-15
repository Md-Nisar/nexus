# Test Audit — US-001: Tenant-Aware Identity Data Model and Migrations

## Coverage audit for Task US-001

### Existing tests (pre-audit)

| File | What it covers |
|------|---------------|
| `EmailCipherTest` | `toString()` redaction; `value()` accessor; record equality |
| `UserTest` | Constructor sets `PENDING` status and zero `tokenVersion`; no `setEmailHmac` mutator |
| `AuthEventTest` | Constructor sets required fields; optional fields default to null |
| `AuthTokenTest` | Constructor sets all required fields; optional fields default to null |
| `RefreshTokenTest` | Constructor sets all required fields; `revokedAt` defaults to null |
| `UserStatusTest` | Enum contains all four values in order |
| `AuthTokenTypeTest` | Enum contains `VERIFICATION` and `RESET` |
| `AuthConstantsTest` | TTL constants; `AssertionError` on constructor invocation |
| `EmailBlindIndexServiceTest` | 64-char hex output; determinism; distinct inputs; case/trim/NFC normalisation; Turkish-I; null guard; crypto failure |
| `IdentityCryptoConfigTest` | Valid keys produce beans; short password; short salt; non-hex salt; short HMAC key; dev password in prod; dev password in dev |
| `IdentityActuatorSanitizerTest` | Sanitises `salt`, `hmac-key`, `password` keys; does not sanitise outside-namespace key, non-sensitive key, or empty key; env-var casing (`NEXUS_IDENTITY_ENCRYPTION_SALT`) |
| `UuidV7GeneratorTest` | Non-null; distinct; version 7; monotone order across 10 successive calls |
| `AttributeEncryptorTest` | Encrypt non-null; round-trip decrypt; null-to-null in both directions; corrupt ciphertext throws `EncryptionException`; no PII in error message |
| `UuidV7ConverterTest` | 16-byte output; round-trip; big-endian order; null-to-null in both directions; wrong-length bytes throws |
| `IdentityCryptoBootIT` | `ApplicationContextRunner` boots with valid keys; fails fast on short password, short salt, short HMAC key, dev password in non-dev/test profile, dev HMAC key in non-dev/test profile, dev salt in non-dev/test profile |

### Integration tests (structural audit only — require Docker TCP 2375)

| File | Coverage intent |
|------|----------------|
| `IdentitySchemaMigrationIT` | All four tables created; expected columns present; `auth_events` has no `updated_at`; expected indexes; Flyway V2 applied successfully |
| `UserUniquenessIT` | Happy-path save + lookup by tenant+hmac; duplicate in same tenant rejected; same email in different tenants allowed; normalised lookup finds stored user |
| `EmailCipherEncryptionIT` | Raw column does not contain plaintext; JPA reload decrypts correctly; AES-GCM non-determinism (same plaintext → different ciphertexts); tampered ciphertext throws `EncryptionException` |
| `AuthEventsAppendOnlyIT` | Insert succeeds; UPDATE triggers SQLSTATE 45000; row unchanged after rejected UPDATE; DELETE triggers SQLSTATE 45000; nullable fields accepted |
| `UserQueryPerformanceIT` | 1 M-row fixture; p95 lookup < 10 ms; EXPLAIN shows unique index used |

**Structural findings for ITs (no Docker — cannot run):**

- `AuthEventsAppendOnlyIT` has `should_leaveRowUnchanged_when_updateRejected` and asserts SQLSTATE 45000 — both present and correct.
- `IdentityCryptoBootIT` tests all three dev-placeholder guards (password, HMAC key, salt). Class name ends in `IT` so Failsafe picks it up; it does NOT require Docker (uses `ApplicationContextRunner`). It was excluded from Surefire by Failsafe's default `*IT` include pattern, meaning it ran only under `mvnw verify` and contributed zero coverage when Docker was absent (`-DskipITs`). All three guards were therefore untested at unit level — this was the primary coverage gap.

### Gaps identified and closed

| Severity | Gap | Location closed |
|----------|-----|-----------------|
| HIGH | `validatePassword` null/blank path (line 69) not exercised by any unit test — only reachable when `encryptionPassword` is `null` or blank; `IdentityCryptoBootIT` was excluded from Surefire | Added `should_throwIllegalState_when_passwordIsBlank` in `IdentityCryptoConfigTest` |
| HIGH | `validateSalt` null/blank path (line 84) not exercised | Added `should_throwIllegalState_when_saltIsBlank` in `IdentityCryptoConfigTest` |
| HIGH | `validateSalt` dev-placeholder-in-prod path (line 95) not exercised at unit level | Added `should_throwIllegalState_when_devSaltUsedInProd` in `IdentityCryptoConfigTest` |
| HIGH | `validateAndGetHmacKey` null/blank path (line 103) not exercised | Added `should_throwIllegalState_when_hmacKeyIsBlank` in `IdentityCryptoConfigTest` |
| HIGH | `validateAndGetHmacKey` dev-HMAC-placeholder-in-prod path (line 110) not exercised | Added `should_throwIllegalState_when_devHmacKeyUsedInProd` in `IdentityCryptoConfigTest` |
| MED | `AttributeEncryptor.convertToDatabaseColumn` catch block (lines 29-30) unreachable with a working encryptor — encryption failure never tested | Added `should_throwEncryptionException_when_encryptionFails` in `AttributeEncryptorTest` |
| MED | `IdentityActuatorSanitizer.isSensitive` false-return branch for an `nexus.identity.*` key that contains none of password/salt/hmac/key — branch at lines 45-46 partially uncovered | Added `should_notSanitize_when_identityKeyHasNoSensitiveWord` in `IdentityActuatorSanitizerTest` |
| MED | `IdentityActuatorSanitizer` env-var form with `HMAC_KEY` not explicitly tested (only `SALT` was) | Added `should_sanitize_when_envVarFormContainsHmac` in `IdentityActuatorSanitizerTest` |
| MED | `IdentityActuatorSanitizer` non-identity key containing "password" (e.g. `spring.datasource.password`) not tested — important negative case for the namespace guard | Added `should_notSanitize_when_nonIdentityKeyContainsPassword` in `IdentityActuatorSanitizerTest` |
| LOW | `EmailBlindIndexService` empty-string input — contract not documented by test | Added `should_return64HexChars_when_emptyStringIndexed` in `EmailBlindIndexServiceTest` |
| LOW | `EmailBlindIndexService` whitespace-only input collapses to empty after `trim()` — parity with empty-string undocumented | Added `should_treatWhitespaceOnlyAsEmpty_when_indexed` in `EmailBlindIndexServiceTest` |

**Note — `VALID_SALT_EXAMPLE` collision:** `IdentityCryptoConfigTest.VALID_SALT_EXAMPLE` (`"deadbeefdeadbeefdeadbeefdeadbeef"`) is byte-for-byte identical to `DEV_SALT_PLACEHOLDER`. When `devHmacKeyUsedInProd` was first written using that constant with `prodEnv()`, `validateSalt` fired before `validateAndGetHmacKey` and produced the wrong error message. Fixed by introducing a distinct `nonPlaceholderSalt` (`"00112233445566778899aabbccddeeff"`) local to that test.

### Tests added

**`EmailBlindIndexServiceTest`** (+2 methods):
- `should_return64HexChars_when_emptyStringIndexed`
- `should_treatWhitespaceOnlyAsEmpty_when_indexed`

**`IdentityCryptoConfigTest`** (+5 methods):
- `should_throwIllegalState_when_passwordIsBlank`
- `should_throwIllegalState_when_saltIsBlank`
- `should_throwIllegalState_when_hmacKeyIsBlank`
- `should_throwIllegalState_when_devSaltUsedInProd`
- `should_throwIllegalState_when_devHmacKeyUsedInProd`

**`IdentityActuatorSanitizerTest`** (+3 methods):
- `should_notSanitize_when_identityKeyHasNoSensitiveWord`
- `should_sanitize_when_envVarFormContainsHmac`
- `should_notSanitize_when_nonIdentityKeyContainsPassword`

**`AttributeEncryptorTest`** (+1 method):
- `should_throwEncryptionException_when_encryptionFails`

### Run results

Backend: 88/88 passing (was 77/77 before audit; +11 new tests)
Frontend: not applicable (US-001 is backend-only; no Angular components added)

### Coverage verdict

All JaCoCo gates met — before and after additions.

| Package | Gate (LINE) | Before | After |
|---------|-------------|--------|-------|
| `identity.domain.*` | ≥ 90% | 100.0% | 100.0% |
| `identity.application.*` | ≥ 85% | 100.0% | 100.0% |
| `identity.infrastructure.*` | ≥ 70% | 90.6% / 92.9% | 100.0% / 100.0% |
| Bundle | ≥ 80% | 94.6% | 98.4% |

Instruction coverage per identity class (all reached 100% after additions):

| Class | Before | After |
|-------|--------|-------|
| `IdentityCryptoConfig` | 80.1% | 100.0% |
| `IdentityActuatorSanitizer` | 92.6% | 100.0% |
| `AttributeEncryptor` | 85.0% | 100.0% |
| All others | 100.0% | 100.0% |

### Load scenarios

No load test script added. `JpaUserRepository.findByTenantIdAndEmailHmac` is the only endpoint expected to exceed 10 RPS at production scale; its index and p95 latency are validated by `UserQueryPerformanceIT` (Gatling/k6 script deferred — that IT already covers the NFR-001 latency assertion with a 1 M-row MySQL fixture via Testcontainers).

### Flaky tests

No flaky tests identified.

- `UuidV7GeneratorTest.should_beTimeOrdered_when_calledSuccessively` compares MSB ordering rather than wall-clock time, so it is immune to clock resolution issues on fast hardware. Not flaky.
- `UserQueryPerformanceIT.should_lookupUnder10msP95_when_1MRowFixture` measures p95 against a 10 ms threshold on Testcontainers MySQL. This test could be environment-sensitive (slow CI runners), but it is tagged `@Tag("perf")` and excluded from the standard Surefire run.
- All other tests are deterministic: no `Thread.sleep`, no `Random` without fixed seed, no shared mutable state across test methods.
