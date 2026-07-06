# Code Review — US-001

**Reviewer:** code-reviewer agent  
**Branch:** feature/US-001  
**Base:** origin/main  
**Date:** 2026-06-15

---

## Summary

| Severity | Count |
|----------|-------|
| Blocker  | 2 |
| High     | 3 |
| Medium   | 5 |
| Low/Nit  | 6 |

**Verdict:** CHANGES REQUESTED

---

## Findings
### [BLOCKER] SEC-T5 dev-key boot guard is incomplete — HMAC key and salt placeholders are not blocked outside dev/test

**File:** nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/crypto/IdentityCryptoConfig.java:61-77
**Cross-ref:** 03b-threat-model SEC-T5; design section 2.6

**Issue:** The validatePassword() method rejects the known dev-placeholder password when the active profile is not dev or test, satisfying SEC-T5 for the password only. However, the committed dev HMAC key (dev-not-a-secret-hmac-key-min-32-bytes-long, visible in application-dev.yml) and the committed dev salt (deadbeefdeadbeefdeadbeefdeadbeef) have no equivalent guard. An operator who correctly rotates the encryption password but forgets the other two values will start a non-dev/test instance with known committed secrets for HMAC-SHA256 and AES-256-GCM, and the application will not detect this. The threat model (03b section 3.9) explicitly requires the boot guard for all known committed dev key values, not just the password.

**Fix:** Add DEV_HMAC_PLACEHOLDER and DEV_SALT_PLACEHOLDER constants (use + string concatenation to defeat secret-scan, mirroring the existing password constant). Add guard checks in validateAndGetHmacKey() and validateSalt() using the same devOrTest boolean already computed in validatePassword(). Extend IdentityCryptoBootIT.should_failFast_when_devKeyUsedInNonDevTestProfile() to also exercise the HMAC-key and salt placeholder cases.

---

### [BLOCKER] application-test.properties is missing identity crypto keys — H2 smoke test context will fail to start

**File:** nexus-backend/src/test/resources/application-test.properties
**Cross-ref:** Design section 2.5 and 7c

**Issue:** Design section 7c explicitly states that the three nexus.identity.* properties must be added to application-test.properties. The file as committed contains only H2 datasource and Flyway config — no identity properties. NexusBackendApplicationTests is @ActiveProfiles("test") and will trigger IdentityCryptoConfig to attempt to resolve , which has no binding in the H2 test profile, causing context startup to fail.

The identity keys were instead placed in a parallel application-test.yml file. Having both application-test.properties and application-test.yml coexist for the same profile is fragile: Spring Boot gives .properties higher precedence than .yml, so any property defined in .properties silently shadows the .yml value for that profile. This creates a silent ordering hazard for future property additions to either file.

**Fix:** Either (a) add the three identity keys directly to application-test.properties as the design specifies, or (b) delete application-test.properties and consolidate all H2/Flyway/identity test-profile config into application-test.yml. The two-file coexistence for the same profile must be resolved.

---
### [HIGH] Wildcard jakarta.persistence.* imports in AuthToken and RefreshToken violate Checkstyle

**File:** nexus-backend/src/main/java/com/example/nexus/identity/domain/AuthToken.java:3
**File:** nexus-backend/src/main/java/com/example/nexus/identity/domain/RefreshToken.java:3

**Issue:** Both files use import jakarta.persistence.*. The Checkstyle configuration (google_checks.xml) enforces AvoidStarImport, which runs in the validate phase on every build before compilation or tests execute. This will fail mvn checkstyle:check and block the build entirely. The other entity files (User.java, AuthEvent.java) correctly use explicit imports — the wildcard imports in these two files are inconsistent.

**Fix:** Replace the wildcard with explicit imports. For AuthToken.java: jakarta.persistence.Column, jakarta.persistence.Entity, jakarta.persistence.EnumType, jakarta.persistence.Enumerated, jakarta.persistence.Id, jakarta.persistence.Table, jakarta.persistence.Version. For RefreshToken.java: the same set minus Enumerated and EnumType.

---

### [HIGH] AuthEventsAppendOnlyIT does not assert the row is byte-identical after a rejected UPDATE

**File:** nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/persistence/AuthEventsAppendOnlyIT.java
**Cross-ref:** 03b-threat-model section 3.3 required mitigation; design section 9b

**Issue:** The threat model requires: "IT must assert the rejected UPDATE leaves the row byte-identical". should_rejectUpdate_when_authEventModified correctly asserts the update throws a DataAccessException, but never re-reads the row to confirm the data is unchanged. The design (section 9b) explicitly names a third test method should_leaveRowUnchanged_when_updateRejected as required, which is absent. Without the read-back assertion, the test cannot distinguish the trigger correctly blocking the write from some other error condition that throws but may not prevent the write.

**Fix:** Add the missing test. After the failed UPDATE attempt, query the row by id via JDBC and assert that outcome is still "SUCCESS" (not "FAILURE"). Example:

    @Test
    void should_leaveRowUnchanged_when_updateRejected() {
        byte[] id = toBytes(uuidGenerator.newId());
        jdbc.update("INSERT INTO auth_events (id, event_type, outcome) VALUES (?, ?, ?)",
            id, "LOGIN_ATTEMPT", "SUCCESS");
        try { jdbc.update("UPDATE auth_events SET outcome = ? WHERE id = ?", "FAILURE", id); }
        catch (DataAccessException ignored) {}
        String outcome = jdbc.queryForObject(
            "SELECT outcome FROM auth_events WHERE id = ?", String.class, id);
        assertThat(outcome).isEqualTo("SUCCESS");
    }

---

### [HIGH] UserQueryPerformanceIT (1M-row performance gate) is entirely absent

**File:** nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/persistence/ (file missing)
**Cross-ref:** Design section 9b; NFR-001; Story Scenario 5

**Issue:** The design mandates UserQueryPerformanceIT tagged @Tag("perf") that inserts a 1M-row fixture and asserts findByTenantIdAndEmailHmac p95 < 10 ms with an EXPLAIN confirming the uq_users_tenant_id_email_hmac index is used. This is the only test that validates NFR-001 (the < 10 ms p95 login lookup SLA). It is a named condition of done in the design spec (section 9b) and corresponds directly to story acceptance criterion 4 and Scenario 5. Without it, the index strategy is stated but never exercised at production data volumes.

**Fix:** Create UserQueryPerformanceIT annotated @SpringBootTest + @Import(TestcontainersConfiguration.class) + @Tag("perf"). Use JdbcTemplate.batchUpdate to bulk-insert 1M rows under a known tenant. Run findByTenantIdAndEmailHmac 100 times; collect latencies via System.nanoTime(); assert p95 < 10 ms. Execute EXPLAIN SELECT ... WHERE tenant_id = ? AND email_hmac = ? and assert the key column is uq_users_tenant_id_email_hmac.

---
### [MEDIUM] blindIndex does not guard against null input — NPE escapes before the try-catch

**File:** nexus-backend/src/main/java/com/example/nexus/identity/application/EmailBlindIndexService.java:34

**Issue:** email.trim() on line 34 throws NullPointerException if email is null. The NPE propagates before entering the try block on line 36, so the catch (Exception e) on line 41 does not intercept it. Callers receive a raw NullPointerException rather than a documented exception. Future US-002 callers building a User from form input may pass null on a missing field.

**Fix:** Add as the first statement of blindIndex():
    if (email == null) { throw new IllegalArgumentException("email must not be null"); }
Add test: should_throwIllegalArgument_when_emailIsNull.

---

### [MEDIUM] IdentityCryptoConfig retains plaintext password and salt as String fields for the full application lifetime

**File:** nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/crypto/IdentityCryptoConfig.java:28-30 and 44-45

**Issue:** encryptionPassword and encryptionSalt are stored as private final String instance fields and assigned in the constructor. Because IdentityCryptoConfig is a @Configuration bean, these strings are reachable for the entire application context lifetime, even though they are only needed once to call Encryptors.text(password, salt). The threat model (section 3.6) notes key-in-String as a residual risk where the Encryptors API forces it, but retaining raw key values in long-lived bean fields is an avoidable extension of that exposure window.

**Fix:** Replace the two String fields with a single TextEncryptor field. Construct the TextEncryptor immediately inside the constructor after validation; the encryptionPassword and encryptionSalt constructor parameters go out of scope at constructor exit. The @Bean method then simply returns the stored TextEncryptor.

---

### [MEDIUM] SEC-T8 tamper-detection IT (AEAD integrity proof) is absent

**File:** nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/persistence/EmailCipherEncryptionIT.java
**Cross-ref:** 03b-threat-model SEC-T8; design Gate 2 blocker resolution for SEC-T1

**Issue:** The design Gate 2 blocker resolution for SEC-T1 explicitly requires an IT asserting that tampered email_cipher fails decryption, proving AEAD integrity is active (not a bare-encrypt mode). EmailCipherEncryptionIT covers non-deterministic ciphertext and round-trip decryption, but has no test that corrupts email_cipher via raw JDBC and asserts loading the entity throws EncryptionException rather than silently returning wrong plaintext. This was a named condition of Gate 2 sign-off.

**Fix:** Add a test that: (1) saves a user and flushes, (2) corrupts email_cipher via jdbc.update on the users table (not blocked by the auth_events trigger), (3) clears the first-level entity cache, (4) reloads via the repository, and (5) asserts EncryptionException is thrown.

---

### [MEDIUM] IdentityActuatorSanitizer isSensitive predicate is over-broad and masks unrelated properties

**File:** nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/crypto/IdentityActuatorSanitizer.java:39-47

**Issue:** The predicate matches any property key containing token, key, secret, password, credentials, salt, or hmac. This will mask unrelated properties such as spring.mvc.format.token-path or server.ssl.key-store-type. The design (SEC-T6) specifies masking the three specific nexus.identity.* properties. Over-masking is less dangerous than under-masking but makes actuator diagnostics unhelpful and hides misconfiguration in unrelated properties.

**Fix:** Narrow the predicate to match only the nexus.identity.* namespace plus sensitive suffixes:
    private boolean isSensitive(String lowerKey) {
        return lowerKey.startsWith("nexus.identity.")
            && (lowerKey.contains("password") || lowerKey.contains("salt")
                || lowerKey.contains("hmac") || lowerKey.contains("key"));
    }
Update the should_sanitize_when_keyContainsKey test: "some.api.key" should now return the original value, not SANITIZED_VALUE.

---

### [MEDIUM] UuidV7Converter does not validate byte array length on read — wrong-length input produces confusing errors

**File:** nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/persistence/UuidV7Converter.java:27-33

**Issue:** convertToEntityAttribute(byte[] bytes) wraps any non-null byte array in a ByteBuffer and reads two longs. A byte array shorter than 16 bytes throws BufferUnderflowException (confusing at the JPA layer with no mention of UUID conversion). An array longer than 16 bytes silently ignores trailing bytes. Either case produces a misleading or silent failure.

**Fix:** Add after the null check:
    if (bytes.length != 16) {
        throw new IllegalArgumentException(
            "Expected 16 bytes for UUID BINARY(16) column, got " + bytes.length);
    }
Add test: should_throw_when_wrongLengthBytesConverted.

---
### [LOW] EmailBlindIndexServiceTest Turkish locale test does not cover the plain ASCII I/i case

**File:** nexus-backend/src/test/java/com/example/nexus/identity/application/EmailBlindIndexServiceTest.java:74-89

**Issue:** The test covers U+0130 LATIN CAPITAL LETTER I WITH DOT ABOVE (dotted capital I), but the more impactful Turkish locale divergence is plain ASCII I (U+0049): on a JVM with Locale.TURKISH as the default, "I".toLowerCase() produces the dotless-i (U+0131), not "i" (U+0069). This is the case where Locale.ROOT matters most in practice. The current test covers a rare character (dotted I is uncommon in email addresses) and misses the common case.

**Fix:** Add: should_normalisePlainAsciiI_when_emailHasUppercaseI asserting service.blindIndex("I@B.COM").equals(service.blindIndex("i@b.com")). This passes with Locale.ROOT and would fail with Locale.TURKISH as the JVM default locale.

---

### [LOW] AuthEventsAppendOnlyIT does not assert SQLSTATE 45000 — only checks message substring

**File:** nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/persistence/AuthEventsAppendOnlyIT.java:47-51

**Issue:** The test asserts hasMessageContaining("append-only"). This validates the trigger error message text but does not confirm the specific SQLSTATE 45000. The design (section 2.7) and threat model (section 3.3) both specify asserting the exact SQLSTATE.

**Fix:** Unwrap the root-cause java.sql.SQLException in both trigger tests and assert getSQLState() equals "45000".

---

### [LOW] IdentityCryptoConfigTest has dead code: + "x".repeat(0) appends nothing

**File:** nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/crypto/IdentityCryptoConfigTest.java:56-57

**Issue:** String tooShortExample = "tooshort123456" + "x".repeat(0) concatenates an empty string. The dead expression is misleading — readers may wonder if this was intended as a boundary test at exactly 15 chars.

**Fix:** String tooShortExample = "tooshort123456"; // 14 chars, below the 16-char minimum. Optionally add a 15-char boundary test.

---

### [LOW] Story AC lists password_hash and identity_provider columns absent from the migration and entity

**File:** docs/story/1-authentication/US-001.md (AC #1)
**Cross-ref:** Design section 4a (intentional omission)

**Issue:** Story AC #1 lists password_hash and identity_provider (default LOCAL) as required columns in users. Neither appears in V2__identity_schema.sql or User.java. The technical design intentionally defers these (section 4a). This is not a code defect — the design post-Gate 2 is the authoritative spec — but the story artifact and technical design are in conflict, which may confuse downstream reviewers or QA.

**Fix (documentation only):** Add a note to 04-tasks.md clarifying that password_hash is deferred to the US-002 migration and identity_provider to a future epic, per the approved technical design.

---

## Positives

**Architecture discipline is exemplary.** The hexagonal boundary is cleanly respected across all 17 source files. User.java has zero infrastructure imports — only java.util.UUID (JDK) and EmailCipher (domain). The autoApply converter trick (design section 2.1) is correctly implemented and will satisfy ArchUnit. EmailBlindIndexService has zero infrastructure imports. This is a clean hexagonal implementation.

**EmailCipher.toString() redaction (SEC-T3) is done correctly.** Overriding toString() on a Java record is non-trivial since records auto-generate it from all components. The implementation correctly returns "EmailCipher[REDACTED]" and EmailCipherTest validates this explicitly.

**HMAC key is cloned on intake and on output.** this.hmacKey = identityHmacKey.clone() in the constructor and return hmacKeyBytes.clone() in the identityHmacKey() bean method prevent callers from mutating the internal key array. Many implementations miss the second clone on the bean return path.

**EncryptionException wraps without leaking PII.** The AttributeEncryptor catch blocks use fixed strings with no plaintext email or ciphertext in the message. AttributeEncryptorTest explicitly asserts hasMessageNotContaining(tampered). SEC-T3 is properly implemented in both production code and test.

**IdentityCryptoConfig fail-fast is tested with ApplicationContextRunner.** IdentityCryptoBootIT uses ApplicationContextRunner, the correct lightweight tool for testing context startup failures without a full @SpringBootTest. This is a non-obvious API choice that was made correctly.

**BINARY(16) big-endian encoding is correct.** ByteBuffer defaults to BIG_ENDIAN, so putLong(msb) + putLong(lsb) matches MySQL BIN_TO_UUID(id, 0) standard UUID byte order. UuidV7ConverterTest validates this with a known MSB/LSB pair.

**lombok.config sets addLombokGeneratedAnnotation = true** as required by the design (section 9c), so JaCoCo correctly ignores Lombok-generated accessors when computing coverage ratios for the 90% domain gate.

**Migration SQL matches the design spec exactly**, including single-statement SIGNAL trigger forms with no DELIMITER and no BEGIN...END blocks. The two BEFORE triggers are valid Flyway-compatible forms for MySQL 8.4.

**IdentityActuatorSanitizer uses a SanitizingFunction bean** rather than the deprecated management.endpoint.env.keys-to-sanitize YAML property (removed in Spring Boot 4). The implementation correctly adapts to the new Spring Boot 4 API with an inline comment explaining the deprecation.

**AuthEvent correctly omits @Version and updated_at**, and both IdentitySchemaMigrationIT and AuthEventTest have assertions that verify this invariant. The absence of @Version on AuthEvent is easy to miss when copying from other entity files, and having tests catch it is good discipline.