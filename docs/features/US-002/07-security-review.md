# Security Review — US-002

## Self-Service Registration with Email Verification

**Phase:** 7 — Code Audit (hostile-mindset)
**Date:** 2026-06-20
**Reviewer:** Application Security Engineer (security-reviewer agent)
**Re-audit date:** 2026-06-20 (post-fix pass)
**Scope:** Uncommitted working-tree changes on branch US-002
**Methodology:** OWASP Top 10 2021, SECURITY.md baseline, STRIDE threat-model cross-reference

**Explicit attestation:** Authentication (token lifecycle), cryptography (Argon2id, AES-256-GCM, HMAC-SHA256, SHA-256 token hashing, SecureRandom), and PII handling (email masking, encryption at rest, log discipline) were each reviewed in depth.

---

## Findings (original + resolution status)

### [HIGH → FIXED] Frontend Angular dependencies carry a known XSS sanitization-bypass CVE
File: `nexus-frontend/package.json`
Risk: `@angular/common`/`@angular/compiler`/`@angular/core` 21.0.0–21.2.16 carry GHSA-58w9-8g37-x9v5 (XSS), GHSA-48r7-hpm6-gfxm (OOM DoS), GHSA-39pv-4j6c-2g6v (SSR cache leak). SECURITY.md §11 gates on `npm audit --omit=dev --audit-level=high` clean.
**Resolution:** All runtime packages pinned to `21.2.17` (patched). Build toolchain (`@angular/build`, `@angular/cli`) stay at `21.2.16` (no `.17` published); `--legacy-peer-deps` used for install. `npm audit --omit=dev --audit-level=high` → **found 0 vulnerabilities**.

### [MEDIUM → FIXED] BouncyCastle 1.78 has published CVEs
File: `nexus-backend/pom.xml`
Risk: CVE-2024-30172 (Ed25519 DoS), CVE-2024-34447. SECURITY.md §11 blocks CVSS ≥ 7.
**Resolution:** Upgraded to `bcprov-jdk18on:1.81` (latest). (A06)

### [MEDIUM → FIXED] `RequestContext.toMetadataJson` builds JSON by string concatenation
File: `nexus-backend/src/main/java/com/example/nexus/common/domain/RequestContext.java`
Risk: User-supplied `ipAddress` / `traceId` interpolated into JSON string without escaping. If `CorrelationIdFilter` allowlist is ever relaxed, a quote/backslash could corrupt the `auth_events.metadata` native JSON column. Defense-in-depth gap.
**Resolution:** Added `jsonEscape()` helper that escapes `\`, `"`, `\n`, `\r`, `\t` before interpolation. (A09, A03)

### [LOW → FIXED] `AccountExistsEmailEvent` has no PII-masking `toString()` override
File: `nexus-backend/src/main/java/com/example/nexus/identity/application/event/AccountExistsEmailEvent.java`
Risk: Default record `toString()` prints raw email; any logger printing the event on listener failure leaks PII. Latent — no current code path logs it.
**Resolution:** Added `toString()` override using `LogMaskingUtil.maskEmail()`, mirroring `VerificationEmailEvent`. (A09, T-I3)

### [LOW → FIXED] New mail adapters import the deprecated `common.web.LogMaskingUtil` shim
Files: `SmtpMailSenderAdapter.java`, `LoggingMailSenderAdapter.java`, `MailEventListener.java`
Risk: Hygiene — new code depending on a `@Deprecated(forRemoval=true)` wrapper.
**Resolution:** All three files updated to import `com.example.nexus.common.domain.LogMaskingUtil` directly. (Hygiene)

### [LOW — Accepted] Resend throttle has a small TOCTOU race under concurrency
File: `nexus-backend/src/main/java/com/example/nexus/identity/application/ResendVerificationUseCase.java`
Risk: COUNT-then-insert with no lock allows two concurrent resends for the same user to both pass the 60s window check. Bounded impact: 24h cap (5 tokens) holds; token TTL/single-use unaffected; at worst the user gets 2 emails.
**Resolution:** Accepted residual for this story. Stronger control (row lock before count) deferred to US-007. (A04, T-D3)

### [INFO] Verification email body is fully static
File: `SmtpMailSenderAdapter.java`
No injection surface: `SimpleMailMessage` plaintext; token is server-generated hex; `setTo` uses validated `@Email`. Link is mailed, never fetched. Clean (A03/A08/A10).

### [INFO] Open-redirect surface on verification link is constrained
File: `SmtpMailSenderAdapter.java`
`frontendBaseUrl` is server config; token is server-generated; no user-controlled redirect target. Clean (A08/T-T1).

---

## OWASP Top 10 — area-by-area result

| Area | Result | Notes |
|------|--------|-------|
| A01 Broken Access Control | PASS | All 3 endpoints permitAll in SecurityConfig matching controller paths; default-deny intact. No IDOR: verify resolves user from token-bound userId server-side; tenant id is server config. |
| A02 Cryptographic Failures | PASS | Token: `SecureRandom.nextBytes(32)` → hex (256-bit). Token hash: SHA-256, stored hashed only. Password: Argon2id (mem=19456KiB/it=2/p=1, OWASP 2023). Email at rest: AES-256-GCM (`Encryptors.delux`). Blind index: HMAC-SHA256, key separate from encryption key, fail-fast validation. |
| A03 Injection | PASS | All DB access via Spring Data derived queries (parameterised). `sanitizeCrlf` in log paths. `RequestContext.toMetadataJson` now JSON-escapes both fields. |
| A04 Insecure Design | PASS | Anti-enumeration: duplicate returns identical 201. Argon2 hash computed BEFORE duplicate check. Resend identical 200 for unknown/non-PENDING. Verify uniform 410. Token TTL enforced. |
| A05 Security Misconfiguration | PASS | CORS single configured origin (no wildcard). HSTS (1y, includeSubDomains). RFC 7807 errors only; no stack traces. Actuator restricted; springdoc disabled in prod. |
| A06 Vulnerable Components | **PASS** | Frontend: Angular runtime upgraded to 21.2.17; `npm audit --omit=dev` → 0 vulnerabilities. Backend: BouncyCastle upgraded to 1.81; Spring Boot 4 / Tomcat 11 / MySQL 9.7 current. |
| A07 Identification and Auth Failures | PASS | Token: 256-bit hex, URL-safe. Only SHA-256 hash stored. Single-use enforced via `consumed_at` + `@Version` optimistic lock + explicit `flush()`. Rate-limited (1/60s, 5/24h) with `429 + Retry-After`. |
| A08 Software and Data Integrity | PASS | Link from server config + server token. DTO `@Pattern([0-9a-f]{64})` rejects percent-encoding; `parseHex` hashes deterministically. No untrusted deserialization. |
| A09 Logging and Monitoring | PASS | All 6 audit events wired. `rawToken` in NO log (grep-confirmed). Emails masked everywhere. `RequestContext` carries IP+traceId into every event. `AccountExistsEmailEvent.toString` now masks email. |
| A10 SSRF | PASS | No outbound HTTP from user input; link is emailed not fetched; SMTP host is fixed config. |

---

## Threat Model Compliance

| Threat ID | Status | Notes |
|-----------|--------|-------|
| T-S1 | Mitigated | 256-bit token; sent only to supplied inbox. |
| T-S2 | Mitigated | 2^256 keyspace; SHA-256 stored. |
| T-S3 | Mitigated | HSTS in SecurityConfig (1y, includeSubDomains). |
| T-T1 | Mitigated | Hash lookup; tampered token → no row → 410. |
| T-T2 | Mitigated | Derived queries only — no SQL injection surface. |
| T-T3 | Mitigated | `sanitizeCrlf` + masking; `RequestContext.toMetadataJson` now JSON-escapes. |
| T-T4 | Mitigated | Angular interpolation; no `innerHTML`; `@Email`/`@Size` caps. |
| T-T5 | Mitigated | `@AssertTrue` + server-side consent timestamp. |
| T-R1 | Mitigated | `REGISTRATION_SUCCESS` event with IP+traceId. |
| T-R2 | Mitigated | `consent_accepted_at` persisted server-side. |
| T-R3 | Mitigated | `VERIFICATION_FAILED` recorded with IP. |
| T-R4 | Mitigated | `RESEND_THROTTLED` recorded before `RateLimitException` thrown. |
| T-I1 | Mitigated | Hash before duplicate check; identical 201 returned. |
| T-I2 | Mitigated | Identical 200 for unknown/non-PENDING on resend. |
| T-I3 | Mitigated | Email logs masked; `AccountExistsEmailEvent.toString` now masks email. |
| T-I4 | Mitigated | No `rawToken` in any log; `VerificationEmailEvent.toString` redacts. |
| T-I5 | Mitigated | Entity never returned from controllers; DTOs exclude password hash. |
| T-I6 | Mitigated | `GlobalExceptionHandler` maps all new domain types; generic fallback. |
| T-I7 | Mitigated | SHA-256 stored, irreversible. |
| T-I8 | Mitigated | STARTTLS enabled+required in `application.yml`; dev override for MailHog only. |
| T-D1 | Partial (accepted) | Argon2 self-limiting + flag; gateway rate limiting deferred to US-009+. |
| T-D2 | Mitigated | At most 1 email per registration request. |
| T-D3 | Mitigated | 1/60s + 5/24h enforced. Minor TOCTOU race is accepted residual (deferred to US-007). |
| T-D4 | Mitigated | `@Size(max=1024)` on password field. |
| T-D5 | Mitigated | `common-passwords.txt` present (379 lines), loaded once, fail-fast if missing. |
| T-E1 | Mitigated | 256-bit + UNIQUE constraint + single-use. |
| T-E2 | Mitigated | `verify()` enforces PENDING; login gating is US-003. |
| T-E3 | Mitigated | `@Version` lock + `flush()` + catch → 410. |
| T-E4 | Mitigated | `@AssertTrue` → 400 on terms rejection. |
| T-E5 | Mitigated | `@ConditionalOnProperty` removes resend bean → 404. |
| T-E6 | Mitigated | DB triggers (US-001) block UPDATE/DELETE on sensitive rows. |
| T-E7 | Mitigated | `length()` check, no pre-trim; Unicode caveat documented. |

No threat is Missing. Non-fully-mitigated items (T-D1, T-D3) match risks the threat model explicitly accepts.

---

## Summary Counts

| Severity | Initial | After fixes |
|----------|---------|-------------|
| CRITICAL | 0 | 0 |
| HIGH     | 1 | 0 |
| MEDIUM   | 2 | 0 |
| LOW      | 3 | 1 (TOCTOU, accepted) |
| INFO     | 2 | 2 |

---

## Verdict: APPROVED

All blocking findings (HIGH: Angular CVEs; MEDIUM: BouncyCastle CVEs, JSON concatenation) have been remediated. The one remaining LOW (resend throttle TOCTOU race) is a bounded-impact residual explicitly accepted by the threat model and deferred to US-007. Application code meets the SECURITY.md baseline and the full US-002 STRIDE threat model across access control, token crypto, password hashing, email PII handling, optimistic-lock token consumption, audit logging, CORS/HSTS, and error handling.
