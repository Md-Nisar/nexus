# Security Review: US-018 M6 (T-005, A11 token claim validation)

**Verdict: APPROVED.** Nothing in this diff is a Blocker, High or Medium. 2 Low issues found, both defence-in-depth gaps. Neither blocks merge, and both can be fixed now or ticketed.

The OWASP dependency-check scan could not run in this environment (details in the A06 section). That needs to be closed by CI before Gate 3.

**Scope:** `git diff origin/main...HEAD -- nexus-backend` on `feature/US-018/M6` at HEAD `8ba3696`. Excluded the `STATUS.md` change in commit `78655be`.

**Auth, crypto and PII were reviewed explicitly.** This change is authentication code and touches the JWT verification path, so algorithm handling, the signature-bypass surface, the authentication/authorization boundary, tenant claim validation, information leakage and PII were reviewed. Findings and evidence below.

---

## Verification run

| Check | Result |
|---|---|
| Unit tests: `JwtRs256ServiceTest`, `JwtRs256ServiceSecurityTest`, `JwtClaimsTest`, `JwtClaimsContractTest`, `JwtSizeBenchmarkTest`, `JwtAuthenticationFilterTest`, `RbacControllerSupportTest`, `UserRoleControllerTest` | **83 run, 0 failures, BUILD SUCCESS** |
| `RoleAssignmentSecurityIT` (Testcontainers, Docker up) | **28 run, 0 failures, BUILD SUCCESS**. The rewritten non-UUID `sub` case returns 401 `AUTH_003`. The request-completed log line for it has no token material. |
| `./mvnw -Psecurity dependency-check:check` | **Could not complete.** Error: `NVD returned a 403 or 404` and `cisa.gov known_exploited_vulnerabilities.json - 403 Forbidden`, then `NoDataException: No documents exist`. There is no local NVD cache and no NVD API key. (`mvnw` is not executable in this checkout, so it was run as `sh ./mvnw`.) |
| `./mvnw dependency:tree` | Ran. The diff changes no `pom.xml` and adds no dependency. Auth-relevant resolved versions: jjwt-api/impl/jackson 0.12.6, micrometer-core 1.17.1, logback-classic 1.5.38, slf4j-api 2.0.18, jackson-databind 2.21.5 (via jjwt-jackson). |
| `npm audit` | Skipped as instructed. No frontend change. |

---

## Findings

```
[LOW] Element types of roles/permissions are not validated; a malformed element escapes as a 500, not a 401
File: nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/security/JwtRs256Service.java:193-196, 217-231
      (with nexus-backend/src/main/java/com/example/nexus/identity/domain/JwtClaims.java:42-43)
Issue: `roles`/`permissions` are unchecked-cast to List<String>. Only the List shape is checked (by the
       ClassCastException catch); the element types are not. A null element (`"roles":[null]`) makes
       `List.copyOf` in the JwtClaims constructor throw NullPointerException. That is not caught by
       `catch (ClassCastException | RequiredTypeException)`, and JwtAuthenticationFilter catches only
       AuthenticationException, so the result is a 500. A non-string element (`"roles":[1]`) passes the
       erased cast and later throws ClassCastException in the filter's `claims.roles().stream().map(...)`.
       That is also a 500. Both behaviours pre-date this diff, but they contradict M6's stated goal
       (design §8 and the TS-10 intent: a malformed claim gets "401, never 500").
Risk: Fail-closed. setAuthentication is never reached, so the token is never treated as authenticated.
      The token must also be signed with the platform's private key, so an external attacker cannot
      trigger this. What remains is a minting bug or key compromise producing 500s instead of a
      counted 401, plus a small A09 gap: those tokens bypass the token_rejected counter.
      OWASP A04 (Insecure Design, incomplete input validation at a trust boundary).
Fix: In validatedClaims(), after the null checks, require every element of `roles` and `permissions`
     to be a non-null String (e.g. `list.stream().allMatch(String.class::isInstance)`), otherwise
     `throw reject(RejectionReason.CLAIMS_MISSING)`. Add two tests: `roles: [null]` and
     `permissions: [1]`, each giving 401 with `claims_missing` counted.
```

```
[LOW] Post-signature rejection reasons are high-signal (they imply a minting bug or key compromise) but no alert is wired
File: nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/security/JwtRs256Service.java:183-215, 260-264
      (docs/features/US-018/monitoring.md, runbook.md, deployment.md: no `token_rejected` entry)
Issue: The reasons `claims_missing`, `schema_version`, `sub`, `tenant_id` and `perm_epoch` can only
       increment for a token whose RS256 signature under the platform key already verified. Outside a
       mixed-version rollout, any non-zero rate means either our own issuer minted a bad token or
       someone else holds the private key. These events are logged at DEBUG only, which is correct for
       log-flood control, and no alert rule references the counter. Design §16 only says to "watch"
       `schema_version` during M7.
Risk: A forged-but-validly-signed token (key compromise) that gets a claim shape wrong would be
      rejected silently. The best early-warning signal for key compromise exists but pages no one.
      OWASP A09 (Security Logging & Monitoring Failures).
Fix: Add an alert to monitoring.md and runbook.md on
     `increase(nexus_auth_token_rejected_total{reason=~"claims_missing|sub|tenant_id|perm_epoch"}[15m]) > 0`
     (page Platform Security), and on `schema_version` outside the M7 rollout window. Keep
     `signature` and `expired` dashboard-only, because unauthenticated callers can drive them.
     No code change needed.
```

---

## Focus areas

**T-3.1 / T-3.2 (alg=none, HS256 confusion): not weakened.** Phase 1 (`JwtRs256Service.java:153-174`) is unchanged in substance:
- `verifyWith(publicKey)` with `parseSignedClaims` rejects unsigned tokens and JWE.
- The explicit `"RS256".equals(alg)` assertion stays at `:160-164`.

The restructuring changes only which reason is counted. The `AuthenticationException` catch at `:165-168` re-throws the same exception after counting it. `validatedClaims()` runs only after Phase 1 returns normally (`:175`), so no claim is ever read from an unverified token. The RS384 test (`should_rejectWithSignatureReason_when_algorithmIsRs384`) shows the explicit assertion is still live, because JJWT alone would accept RS384 under the same key. The alg=none, HS256-confusion, foreign-key and payload-tamper tests all pass.

**Authn/authz boundary: fail-closed.** `JwtAuthenticationFilter.java:73-85` sets `SecurityContextHolder` authentication only after `verify()` returns. Every rejection path is a 401. Any other exception propagates before authentication is set. No path was found where a malformed or invalid token is treated as authenticated. The `RoleAssignmentSecurityIT` change from 403 to 401 is correct and stronger: a malformed `sub` now fails authentication and never reaches RBAC. The controller-level `MALFORMED_AUTHENTICATION` defence in depth is still covered by `RbacControllerSupportTest` and `UserRoleControllerTest`, which pass.

**Tenant isolation (A01):** `tenant_id` must now be a String and a canonical UUID (`:207-210`). This closes the null-`tenant_id` NPE that caused a 500 in the filter's `Map.of` (threat-model M6 S row). The exact round-trip check (`UUID.fromString(x).toString().equals(x)`, `:239-248`) also blocks non-canonical aliases such as `1-1-1-1-1` or uppercase spellings. Those parse to a real UUID downstream but would not string-match. The same rule applies to `sub`. `issue()` mints only `UUID.toString()` (`:117-118`), so legitimate tokens are unaffected. No code in `src/main` uses the nil UUID as a sentinel.

**Injection / log injection (A03):** No query, command or template is built from claims. As a side benefit, `sub` and `tenant_id` are now restricted to `[0-9a-f-]{36}` before `JwtAuthenticationFilter` puts them into MDC (`:86-87`). That removes a CRLF and log-injection vector, which before this change was reachable only with our key.

**Information leakage (A05):**
- All seven reasons throw the same `AuthenticationException("AUTH_003", "Token invalid or expired")` (`:255-258`).
- The 401 body from `SecurityConfig.java:99-107` is a fixed template with no reason field. Its `traceId` comes from the `CorrelationIdFilter`-sanitised MDC.
- JJWT exception messages, which include expiry timestamps, are discarded.
- Response timing differs between reasons only after the signature is verified, so it gives an outside attacker no oracle.

**Logging and PII (A09):** `recordRejection` (`:261-264`) logs at DEBUG with a constant enum tag only. It never logs the token or any claim value, and `should_logRejectionAtDebugOnly_when_tokenRejected` asserts this. Counter cardinality is fixed at 7 series by a closed enum and registered up front, so an unauthenticated caller can inflate the counts but cannot create new series. **`JwtClaims.java` "Contains no PII" (`:15`) still holds.** The diff only adds `ACCEPTED_VERSIONS`. The record's fields remain a UUID `sub`, tenant UUID, boolean, role/permission strings, timestamps, `jti` and version ints. There is no email or name. The counters carry no user or tenant tag.

**Crypto (A02):** No change to key material, algorithm, key size or randomness. RS256 with the existing RSA key pair. No custom crypto.

**Integrity / deserialization (A08):** Claims are deserialized by jjwt-jackson only after signature verification. `ACCEPTED_VERSIONS` is an immutable `Set.of`. `schema_version` is pattern-matched as `Integer`, so `"2"`, `2.0` or a missing value is rejected. `perm_epoch` accepts only a non-negative `Integer` or `Long`, so a fractional, string or `BigInteger` value is rejected.

**A07 / A10:** Accepting v3 tokens is not an authentication weakening, because only the platform key can mint them, and M6 ignores `perm_epoch` (pre-A9 behaviour, Decision 18, accepted in T-E40). No outbound calls, so SSRF does not apply.

---

## Threat-model cross-reference (`docs/features/US-018/03b-threat-model.md`, M6 table, plus T-S10 / RC-40.1 / T-E40)

| Threat | Status in model | Mitigation visible in diff |
|---|---|---|
| S: missing `tenant_id` gives a 500 (NPE) | ✅ mitigated | Yes. `JwtRs256Service.java:207-210`. Tested through the real filter: `JwtAuthenticationFilterTest.should_return401AndNeverThrow_when_bearerTokenMissingTenantId` |
| S: non-UUID `sub` gives a 500 (**T-S10**, RC-40.1) | ⚠️ open | **Now closed.** `:203-206`, canonical check. Tested by 3 unit attack cases and the IT. The model row can be updated to ✅ |
| T: v3 accepted before its shape is frozen (**T-S10**) | ⚠️ open | **Now closed.** `perm_epoch` validation at `:211-215`, plus the v3 = v2 ∪ {`perm_epoch`} freeze in `JwtClaims.java:32-38`. 4 negative and 3 positive tests |
| R/I: rejection logging floods | ✅ | Yes. DEBUG only, closed `reason` enum (`:261-281`) |
| D: mixed-version rollout ping-pongs sessions | ✅ | Yes. `ACCEPTED_VERSIONS = {2,3}`, `CURRENT_VERSION` stays 2 |
| E: M6 accepts v3 (**T-E40**) | ✅ attacked and survived | Consistent. `perm_epoch` is shape-checked and ignored. RC-40.6 (runbook pages Security on rollback to M6) is an M7 deliverable, outside this diff |

Every threat in the model marked "mitigated" that is relevant to token or claim validation shows a visible code mitigation and a test.

---

## OWASP Top 10 checklist (SECURITY.md §12)

- **A01 Broken Access Control:** Pass. Tenant and subject are canonicalised, the boundary is fail-closed, and the 401/403 boundary matches SECURITY.md §3.1.
- **A02 Cryptographic Failures:** Pass. No change, and T-3.1/T-3.2 are intact.
- **A03 Injection:** Pass. No sinks, and the MDC log-injection surface is narrowed.
- **A04 Insecure Design:** Pass, with one Low (list element types).
- **A05 Security Misconfiguration:** Pass. The 401 is generic and stack-free.
- **A06 Vulnerable Components:** **Not verified.** The dependency-check scan failed on NVD/CISA 403 and there is no local DB. No dependency changed in this diff, but CI's weekly CVSS ≥ 7 gate must be green before Gate 3.
- **A07 Identification & Authentication Failures:** Pass. Authentication now fails closed on malformed claims.
- **A08 Software & Data Integrity Failures:** Pass.
- **A09 Security Logging & Monitoring Failures:** Pass on logging (no PII, no token material). One Low on alerting.
- **A10 SSRF:** Not applicable.

## Residual risk

- **Pre-existing, not in this diff:** `iat` is not checked against a future-dated value. A validly signed token with a far-future `iat` is accepted, but `exp` still bounds its lifetime. Recording this only. It needs our private key.
- **Accepted by design:** during the M7 rollout, M6 instances accept v3 tokens without enforcing `perm_epoch` (T-E40, Decision 18).
- **Pending:** A06, until CI dependency-check runs green.

## Relevant files

- `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/security/JwtRs256Service.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/domain/JwtClaims.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/web/JwtAuthenticationFilter.java`
- `nexus-backend/src/main/java/com/example/nexus/config/SecurityConfig.java` (lines 99-107, the 401 body)
- `nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/security/JwtRs256ServiceSecurityTest.java`
- `nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/security/JwtRs256ServiceTest.java`
- `nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/web/JwtAuthenticationFilterTest.java`
- `nexus-backend/src/test/java/com/example/nexus/rbac/security/RoleAssignmentSecurityIT.java`
- `docs/features/US-018/03b-threat-model.md` (M6 table, lines 210-219; T-S10 at line 452)
- `docs/features/US-018/03-design.md` (§8, lines 670-686)
