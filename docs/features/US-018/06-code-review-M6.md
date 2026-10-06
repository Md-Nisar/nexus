# Code review: US-018 M6 / T-005 (A11 token claim validation)

**Verdict: APPROVE WITH NITS.** Nothing blocks the merge. One Medium is worth closing in this PR because it's about 5 lines. It's a remaining 500 path that is old code, not a regression.

**Scope:** `git diff origin/main...HEAD -- nexus-backend`, HEAD `8ba3696`, 9 files, +660/-42. `STATUS.md` was ignored as instructed.

**Heads-up: the working tree was not clean at review time, and the reviewer did not make these changes.** `git status` showed two uncommitted changes not in `8ba3696` (from the in-flight `qa-engineer` test-audit agent running concurrently):
- `nexus-backend/mvnw`: file mode changed from 644 to 755.
- `JwtRs256ServiceTest.java`: +24 lines, adding `should_rejectWithTenantIdReason_when_tenantIdIsUppercaseUuid` and `should_reportZeroCount_when_serviceConstructedBeforeAnyVerifyCall`.

The reviewer's test runs therefore include them. The committed diff alone does not contain those two tests.

## Gates run (results as reported)
- **`./mvnw -o verify -DskipITs`:** BUILD SUCCESS. Tests run: 1455, Failures 0, Errors 0, Skipped 1. JaCoCo check passed. SpotBugs `BugInstance size is 0`.
- **ITs with Docker up, `RoleAssignmentSecurityIT` and `JwtAlgorithmDowngradeIT`:** 29 tests, 0 failures. These are the only two `*IT`s that forge tokens, and `-DskipITs` does not cover them. The rewritten 401 `AUTH_003` case passes, and the RS384 forged token still gets 401.
- **Behaviour probe:** a throwaway program (not in the repo) fed hand-signed RS256 tokens with malformed claims to the compiled `JwtRs256Service`. Its results are the basis for the Medium and the first Low below.

## Matches the design (ADR-0022 D7, design §8, T-005)
- **ADR-0022 D7 freeze is respected.**
  - `CURRENT_VERSION` stays 2.
  - `issue()` is unchanged, and no `permEpoch` field was added to `JwtClaims`.
  - `JwtClaimsContractTest` only gains the extra constructor argument.
  - v3 is validated as "all v2 required claims plus `perm_epoch`, a non-negative `Integer` or `Long`". `BigInteger`, fractional, string and negative values are all rejected.
- **`ACCEPTED_VERSIONS = Set.of(2, 3)`** is checked first, with an `instanceof Integer` guard, so `"2"`, `2.0` and an absent version are rejected as `schema_version`.
- **All seven reason tags match design §8 exactly.** Counters are registered up front, so the M6 baseline in §14 shows zeros rather than missing series.
- **Every rejection maps to 401 `AUTH_003`.** Logs are DEBUG only and contain no token or claim values; a test covers this.
- **The RS256 algorithm assertion (`JwtRs256Service.java:160-164`) is textually unchanged**, as the T-005 Risks require.
- **The `Map.of` NPE in `JwtAuthenticationFilter` is removed where it starts.** There is no filter change, and TS-10 has a real-verifier filter test.

**Good decisions:**
- **Canonical UUID round-trip (`UUID.fromString(v).toString().equals(v)`).** It closes the `"1-1-1-1-1"` lenient-parse aliasing hole and has its own tests.
- **Pre-registered counters in an `EnumMap`.** No registry lookup on the hot path, a bounded set of tag values, and it follows the existing `AuthEventRetryBuffer` pattern.
- **Cheap on the hot path.** The added work is two UUID round-trips, an `EnumMap.get`, and a fluent `atDebug()` that does nothing when DEBUG is off. That is negligible next to the RSA verify, so the EPIC-002 <5 ms p95 budget is not at risk.
- **The `RoleAssignmentSecurityIT` rewrite is honest.** Its Javadoc says defence in depth still lives in `RbacControllerSupportTest` and `UserRoleControllerTest`, and both still cover `MALFORMED_AUTHENTICATION`.

## Findings

**[MEDIUM]** `verify()` can still end in a 500 when `roles`/`permissions` contain null or non-string items
File: `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/security/JwtRs256Service.java:193-201` (NPE thrown at `nexus-backend/src/main/java/com/example/nexus/identity/domain/JwtClaims.java:42-43`)
Problem: `(List<String>) payload.get("roles")` is an unchecked cast, so the elements are never checked. The probe confirmed two outcomes:
- `roles: [null]` → `List.copyOf` throws `NullPointerException`. It escapes `verify()` uncounted, and the filter only catches `AuthenticationException`, so the response is a 500.
- `roles: [1, 2]` → accepted by `verify()`. It then fails with a `ClassCastException` in the filter's `"ROLE_" + r` mapping, which is also a 500. `permissions` behaves the same way further downstream.

Why it matters: ADR-0022 D7 says `verify()` "never returns 500", and the T-005 title says "401, never 500". Reaching this needs the platform signing key, the same exposure the threat model rates T-S10 Low, so this is a contract gap rather than an exploit. Old code, not a regression.
Suggested fix (inside the existing try, before the null check):
```java
List<String> roles = stringList(payload.get("roles"));
List<String> permissions = stringList(payload.get("permissions"));
...
private static List<String> stringList(Object v) {
  if (!(v instanceof List<?> l)) return null;
  for (Object e : l) if (!(e instanceof String)) throw new ClassCastException(); // -> claims_missing
  @SuppressWarnings("unchecked") List<String> s = (List<String>) l;
  return s;
}
```
Add tests: `roles: [null]` and `permissions: [1]` → `claims_missing`.

**[LOW]** `reason=signature` also counts tokens with a valid signature that are malformed or not yet valid
File: `JwtRs256Service.java:169-174`
Problem: `JwtException | IllegalArgumentException` is tagged `SIGNATURE`. The probe showed that tokens signed with our key but carrying a numeric `sub`, a numeric `jti`, a string `iat`, or a future `nbf` (`PrematureJwtException`) are all counted as `signature`.
Why it matters: on dashboards, `signature` reads as "possible forgery", and mixing these cases in weakens that signal. It does not affect the M7 rollout watch, which uses `schema_version`.
Suggested fix: either catch `MalformedJwtException` / `PrematureJwtException` separately, or, more simply because the tag set is closed by design, document on `RejectionReason.SIGNATURE` (and in `monitoring.md`) that `signature` means "JJWT parse or crypto failure, including malformed registered claims and nbf".

**[LOW]** The test helper does not prove a rejection is counted under only one reason
File: `nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/security/JwtRs256ServiceTest.java:546` and `.../JwtRs256ServiceSecurityTest.java:391`
Problem: `assertRejectedWithReason` checks that the expected counter equals 1.0, but never checks the other six. A regression that counts twice would not be caught, for example `recordRejection(SIGNATURE)` followed by a `reject(...)` with a second reason, or a nested catch re-tagging.
Suggested fix: also assert the total across all reasons:
```java
assertThat(meterRegistry.find("nexus.auth.token_rejected").counters())
    .mapToDouble(Counter::count).sum()).isEqualTo(1.0);
```
(or compare per-reason snapshots taken before and after).

**[LOW]** Missing edge-case tests for paths whose behaviour changed
File: `JwtRs256ServiceTest.java` (T-005 section)
Problem:
- An absent `sub` used to be counted as `claims_missing` and is now counted as `sub` (`isCanonicalUuid(null)`). No test pins this.
- No test shows that a v2 token carrying a malformed `perm_epoch` is accepted, which is the intended behaviour since only v3 validates it.
- No test covers a wrong-type optional claim (`email_verified: "true"` → `claims_missing`).
Suggested fix: add three short tests using the existing `validClaims` / `signedToken` helpers.

**[NIT]** The `catch (AuthenticationException)` block depends on a comment
File: `JwtRs256Service.java:165-168`
Problem: correctness depends on the comment "Only the algorithm assertion above throws this". `AuthenticationException extends DomainException`, so the later `JwtException | IllegalArgumentException` catch would never swallow it anyway.
Suggested fix: optional. If touching the assertion line is acceptable, change `:163` to `throw reject(RejectionReason.SIGNATURE);` and delete `:165-168`. Otherwise keep the block as it is (it is correct).

**[NIT]** Unclear test in `JwtClaimsTest`, and its name will go stale
File: `nexus-backend/src/test/java/com/example/nexus/identity/domain/JwtClaimsTest.java:79-83`
Problem: `.satisfies(versions -> assertThat(CURRENT_VERSION).isEqualTo(2))` ignores its lambda argument and makes two separate assertions. The name `_when_m6Ships` will be wrong after M7.
Suggested fix: split it into `assertThat(ACCEPTED_VERSIONS).contains(CURRENT_VERSION)`, which holds for every release. The `CURRENT_VERSION == 2` pin already belongs to `JwtClaimsContractTest`, the designated freeze gate.

**[NIT]** Duplicate test
File: `JwtRs256ServiceTest.java:341`
Problem: `should_acceptToken_when_schemaVersionIs2WithoutPermEpoch` repeats `:334`, because `validClaims(2)` never contains `perm_epoch` and the `doesNotContainKey` precondition always passes.
Suggested fix: delete it, or turn it into the "v2 with malformed `perm_epoch` is accepted" case from the Low above.

**[NIT]** The check is stricter than the approved design wording, and that isn't written down
File: `JwtRs256Service.java:239-248`
Problem: the design and ADR say "parseable as a UUID", but the code requires the canonical lowercase form, so an uppercase UUID is rejected. This is the right call (`issue()` only mints `UUID.toString()`), but it differs from the Gate-2 text.
Suggested fix: add one line to `09-technical.md`, or to design §8 as an implementation note.

**[NIT]** Milestone names in production Javadoc will go stale
File: `nexus-backend/src/main/java/com/example/nexus/identity/domain/JwtClaims.java:32-38`, `JwtRs256Service.java:141-143, 211`
Problem: phrases like "M6 accepts {2, 3}" and "an M7 rolling deploy" will be wrong at M7b.
Suggested fix: describe the rule ("accepted set widened one release ahead of minting; see ADR-0022 D7") and leave milestone details to the ADR.

**[NIT]** The DEBUG reason doesn't show in the non-prod console log
File: `JwtRs256Service.java:263`
Problem: `addKeyValue("reason", ...)` appears only with prod's ECS structured logging. The local and test console pattern prints only "access token rejected", as seen in the surefire output. This matches the existing `RbacAuthEventAdapter` usage, so it is consistent with the codebase, but debugging locally is harder.
Suggested fix: optionally use `log.debug("access token rejected reason={}", reason.tag)`, which renders under both layouts.

**[NIT]** Six constructor dependencies
File: `JwtRs256Service.java:60-66`
Problem: the standards say more than 4 dependencies is a smell. `MeterRegistry` is a cross-cutting concern, and pulling out a `TokenRejectionMetrics` bean for 7 counters would be speculative abstraction. No action recommended; noted for completeness.

## Summary

| Severity | Count |
|---|---|
| Blocker | 0 |
| High | 0 |
| Medium | 1 |
| Low | 3 |
| Nit | 7 |

**Verdict: APPROVE WITH NITS.** The diff does what T-005, design §8 and ADR-0022 D7 ask: v3 frozen as v2 ∪ {`perm_epoch`}, the accepted-set shape, all seven reasons, DEBUG-only logging, and the alg assertion untouched. It is well tested, and both the `-DskipITs` gate and the affected ITs pass. Recommend closing the Medium (element type checks on `roles`/`permissions`) in this PR, since it is cheap and makes "never 500" actually true. It is old code, needs the signing key to reach, and can go to a follow-up if the team prefers. Before opening the PR, either commit or discard the uncommitted `mvnw` mode change and the 2 extra tests in `JwtRs256ServiceTest.java` (these turned out to be the in-flight `qa-engineer` test-audit agent's work, running concurrently with this review).

**Files reviewed:**
- `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/security/JwtRs256Service.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/domain/JwtClaims.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/web/JwtAuthenticationFilter.java` (context only)
- `nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/security/JwtRs256ServiceTest.java`
- `nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/security/JwtRs256ServiceSecurityTest.java`
- `nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/web/JwtAuthenticationFilterTest.java`
- `nexus-backend/src/test/java/com/example/nexus/identity/domain/JwtClaimsTest.java`
- `nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/security/JwtClaimsContractTest.java`
- `nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/security/JwtSizeBenchmarkTest.java`
- `nexus-backend/src/test/java/com/example/nexus/rbac/security/RoleAssignmentSecurityIT.java`
- `docs/features/US-018/03-design.md` (§8, §9.5, §9.6)
- `docs/features/US-018/03b-threat-model.md` (T-S10)
- `docs/features/US-018/04-tasks.md` (M6 / T-005)
- `docs/adr/0022-permission-token-freshness.md` (D7)
