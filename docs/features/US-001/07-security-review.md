# Security Review — US-001

**Reviewer:** security-reviewer agent (hostile-mindset)
**Date:** 2026-06-15
**Branch:** feature/US-001
**Cross-referenced:** `docs/features/US-001/03b-threat-model.md`, `SECURITY.md`
**Attestation:** Auth, crypto, and PII-handling concerns were all explicitly reviewed.
**Dependency scan:** `./mvnw -Psecurity dependency-check:check` — completed, results below.

---

## Verdict: BLOCKED — pending platform dep-check remediation (A06)

The cryptographic BLOCKER (`Encryptors.text()` → AES-CBC, no AEAD) was **fixed in this
session** by switching to `Encryptors.delux()` (AES-256-GCM, AEAD integrity confirmed).
The remaining BLOCKER is in platform dependencies (Spring Framework, Spring Security
core/web, Tomcat) with CVSS ≥ 7.0 CVEs — pre-existing, not introduced by US-001, must be
resolved at the platform level before merge.

---

## Findings

### ~~[BLOCKER] `Encryptors.text()` is AES-CBC, not AES-256-GCM~~ — **FIXED**

**File:** `IdentityCryptoConfig.java` — **resolved in this session**

`Encryptors.text()` resolved to `standard()` → AES-CBC (no AEAD). Bytecode-verified against
`spring-security-crypto:7.0.5`. The fix was to replace with `Encryptors.delux()`, which
resolves to `HexEncodingTextEncryptor(stronger())` → AES-256-GCM with random IV per call.
`Encryptors.text()` wraps `standard()` (CBC); `Encryptors.delux()` wraps `stronger()` (GCM).

**Fix applied:** `IdentityCryptoConfig.java:49` — `Encryptors.delux(password, salt)` with
an inline comment explaining why `text()` must not be used. 77 unit tests pass post-fix.

SEC-T1 and SEC-T8 are now correctly satisfied: GCM AEAD will reject tampered ciphertext;
the `EmailCipherEncryptionIT.should_throwEncryptionException_when_emailCipherTampered` test
now exercises genuine AEAD tag verification rather than CBC length-check fallback.

---

### [BLOCKER] OWASP dependency-check: CVSS ≥ 7.0 in platform dependencies (A06 / SEC-T7)

**Source:** `./mvnw -Psecurity dependency-check:check` exit code 1.

These CVEs are in the Spring Boot platform, **not in US-001-specific dependencies**
(`uuid-creator:6.1.1` — CLEAN; `spring-security-crypto:7.0.5` — CLEAN from crypto lib
perspective; not flagged for its own CVEs).

| Artifact | CVE(s) | CVSS |
|----------|--------|------|
| `tomcat-embed-core:11.0.21` | CVE-2026-41293, CVE-2026-43512 | **9.8** |
| `tomcat-embed-core:11.0.21` | CVE-2026-41284, CVE-2026-43513, CVE-2026-43515 | 7.5, 9.1 |
| `spring-core:7.0.7` | CVE-2026-41838/41848/41851/41850/41842 | 7.5 each |
| `spring-security-core/web:7.0.5` | CVE-2026-40988 | 7.5 |
| `micrometer-registry-prometheus:1.16.5` | CVE-2026-42154 | 7.5 |
| `angus-activation:2.0.3` | CVE-2025-7962 | 6.0 (below gate) |

**Note:** Tomcat CVE-2026-41293 / CVE-2026-43512 at CVSS 9.8 and CVE-2026-43515 at 9.1
are critical and must be remediated before any deployment.

**Scope:** All affected JARs are transitive Spring Boot platform dependencies predating US-001.
US-001 introduced only `uuid-creator` (clean) and the explicit `spring-security-crypto`
declaration (crypto jar not flagged). Platform upgrades are a separate track.

**Required action before merge:**
- Either upgrade to a Spring Boot 4.x patch that pulls in fixed Tomcat/Spring versions, OR
- Raise suppressions in `dependency-check-suppression.xml` with documented rationale and
  CVE publication dates — accepted only if no patched versions are available yet.

---

### [MEDIUM] `JpaUserRepository` inherits un-tenanted `findById`/`findAll` (A01 / IDOR)

**File:** `JpaUserRepository.java:9`

Extending `JpaRepository<User, UUID>` exposes `findById`, `findAll`, `deleteById`,
`getReferenceById` — none tenant-scoped. No Hibernate filter on `User`. Not exploitable in
US-001 (no endpoint) but creates a footgun for US-002+ callers.

**Fix:** Narrow the interface to extend `Repository<>` and expose only
`findByTenantIdAndEmailHmac`; add an ArchUnit rule blocking `findAll`/`deleteById` on
tenant-owned entities; carry into the US-002 threat model.

---

### [LOW] Append-only audit log: TRUNCATE/DROP TRIGGER bypass (SEC-T4 deferred)

**File:** `V2__identity_schema.sql:97-105`

BEFORE triggers on `auth_events` are syntactically correct for MySQL 8.4. Triggers do not
block `TRUNCATE` or `DROP TRIGGER` — this is a MySQL platform constraint accepted in the
design (SEC-T4 deferred to least-privilege runtime grant in ADR-0006). Not a US-001 code
defect; verify the compensating control (DML-only app user, separate Flyway user) is tracked.

---

### [LOW] Email-existence equality leak via deterministic `email_hmac` (accepted residual)

**File:** `V2__identity_schema.sql`, `EmailBlindIndexService.java`

HMAC determinism means an attacker with DB read-access and the HMAC key can confirm email
existence. This is inherent to blind-index design and is documented as an accepted residual
in ADR-0006. Normalisation (`trim → NFC → Locale.ROOT`) is centralised and correct.
SEC-T10 constant-response constraint must be enforced in US-002.

---

### [LOW] Key material lingers as `String` in heap (inherent `Encryptors` API constraint)

**File:** `IdentityCryptoConfig.java`

`encryptionPassword` and `encryptionSalt` arrive as `@Value String`s (non-zeroable). The
HMAC key is defensively copied to `byte[]` and cloned on return. Accepted residual for MVP.

---

## Verified Clean (explicitly reviewed, no finding)

| Area | Status |
|------|--------|
| **SEC-T5** dev-key prod guard — all three committed placeholders blocked outside dev/test | ✅ |
| **SEC-T6** actuator masking — dot and env-var form both masked, no over-masking | ✅ |
| **SEC-T9** `User.emailHmac` immutability — no setter, `updatable=false`, no `@Data` | ✅ |
| **SEC-T3** PII redaction — `EmailCipher.toString()` → `[REDACTED]`; `AttributeEncryptor` errors carry no PII | ✅ |
| **Input validation** — `blindIndex(null)` throws before crypto; null-safe converter both directions | ✅ |
| **UuidV7Converter** — `!= 16` check covers short and long inputs | ✅ |
| **Randomness** — `UuidCreator.getTimeOrderedEpoch()` uses SecureRandom | ✅ |
| **Migration SQL** — no literal PII or key material | ✅ |
| **Injection (A03)** — Spring Data derived query only, no dynamic SQL | ✅ |
| **Test credentials** — dev/test placeholders non-secret, clearly distinguishable | ✅ |
| **uuid-creator dep** — exact-pinned `6.1.1`, MIT license, not flagged in dep-check | ✅ |

## OWASP Top 10 Summary

| # | Category | Result |
|---|----------|--------|
| A01 | Broken Access Control | NOTE — untenanted `findById`/`findAll` (MEDIUM) |
| A02 | Cryptographic Failures | PASS — **FIXED**: `Encryptors.delux()` → AES-256-GCM |
| A03 | Injection | PASS |
| A04 | Insecure Design | PASS w/ notes |
| A05 | Security Misconfiguration | PASS |
| **A06** | **Vulnerable Components** | **BLOCKED — Tomcat 9.8 CVE in platform deps** |
| A07 | Auth Failures | N/A (no runtime auth in US-001) |
| A08 | Software/Data Integrity | PASS |
| A09 | Logging & Monitoring | PASS — startup log `encryptor=AES-256-GCM` now accurate post-fix |
| A10 | SSRF | N/A |

## SEC-T Coverage (threat model cross-reference)

| SEC-T | Status |
|-------|--------|
| SEC-T1 — JDK-native GCM, no BC | ✅ FIXED: `Encryptors.delux()` → AES-256-GCM confirmed |
| SEC-T2 — property-name-only error messages | ✅ |
| SEC-T3 — no PII in logs/exceptions | ✅ |
| SEC-T4 — Argon2id column comment; TRUNCATE bypass residual tracked | ✅ (residual documented) |
| SEC-T5 — dev-key boot guard (all 3 values) | ✅ |
| SEC-T6 — actuator masking | ✅ |
| SEC-T7 — exact dep pin; dep-check | ❌ BLOCKER: platform CVEs ≥ 7.0 |
| SEC-T8 — AEAD tamper detection | ✅ FIXED: GCM AEAD active; tamper IT now tests genuine tag verification |
| SEC-T9 — normalisation + immutable emailHmac | ✅ |
| SEC-T10 — HMAC-oracle residual documented in ADR-0006 | ✅ |
