# Coverage audit for Task T-005 (US-018, M6 — A11 token claim validation)

Branch `feature/US-018/M6`, audited diff `origin/main...HEAD -- nexus-backend` at commit `8ba3696` (docs-only `78655be` ignored as instructed). Backend verify was re-run after two new doc commits landed on the branch from other subagents (`ceeee39`, `e10290d`) — unrelated to this audit, not reviewed.

## Existing tests
- `nexus-backend/src/test/java/com/example/nexus/identity/domain/JwtClaimsTest.java`: `ACCEPTED_VERSIONS` contains exactly {2,3}; includes `CURRENT_VERSION` (2).
- `nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/security/JwtRs256ServiceTest.java` (21 new cases pre-audit): schema_version boundaries 1/4 rejected, non-integer (string) and absent schema_version rejected; happy path v2 (with/without perm_epoch) and v3 (with perm_epoch); perm_epoch boundary 0 accepted, Long-sized value accepted; perm_epoch missing/negative/string/fractional rejected (v3); tenant_id absent/non-UUID/non-canonical("1-1-1-1-1")/non-string(42) rejected; EXPIRED and CLAIMS_MISSING (roles absent) reasons; counter-stays-zero-on-valid-token test; counter-tags-all-registered test.
- `nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/security/JwtRs256ServiceSecurityTest.java` (7 new cases): sub non-UUID, sub non-canonical ("1-1-1-1-1"), sub uppercase; signature rejections for foreign RSA key, RS384, alg=none; DEBUG-only logging assertion (never logs token/claim values).
- `nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/web/JwtAuthenticationFilterTest.java` (1 new case): missing `tenant_id` through the real filter chain returns 401 and never throws (regression for a prior NPE/500).
- `nexus-backend/src/test/java/com/example/nexus/rbac/security/RoleAssignmentSecurityIT.java`: rewritten case now asserts 401/AUTH_003 and `token_rejected{reason=sub}` incrementing by 1, end-to-end through the real filter chain and Spring context.

All of the above were already adequate and not duplicated — confirmed by reading `JwtRs256Service.java` line-by-line against each rejection branch (`SIGNATURE`, `EXPIRED`, `CLAIMS_MISSING`, `SCHEMA_VERSION`, `TENANT_ID`, `SUB`, `PERM_EPOCH`) and cross-checking every test asserts both the AUTH_003/401 outcome and the matching counter increment via the shared `assertRejectedWithReason` helpers.

## Gaps identified
- **[MED]** Counter pre-registration only tested for tag *existence*, not that each reports **0** — `should_registerEveryRejectionReasonAtZero_when_serviceConstructed` extracts only `counter.getId().getTag("reason")`, never asserts `.count()`. The closest existing proof (`should_notIncrementTokenRejected_when_tokenValid`) runs a `verify()` call first, so it doesn't isolate "zero at construction, before any verify call" — added `should_reportZeroCount_when_serviceConstructedBeforeAnyVerifyCall`.
- **[LOW]** `tenant_id`'s canonical-UUID anti-aliasing check had a non-canonical-form test (`"1-1-1-1-1"`) but, unlike `sub` (which has both the stripped-form and the uppercase-form test), no uppercase/non-lowercase variant for `tenant_id` — added `should_rejectWithTenantIdReason_when_tenantIdIsUppercaseUuid`.

No other real gaps found. Specifically confirmed adequate (no action needed):
- Happy path v2 and v3 — covered.
- Boundary schema_version 1 and 4 rejected — covered.
- perm_epoch 0 (valid boundary), negative (-1), string, fractional (1.5) — all covered.
- All 7 `RejectionReason` values have ≥1 test asserting both 401/AUTH_003 and the specific counter increment — confirmed by reading every rejection branch against the test suite.
- Non-canonical UUID anti-aliasing for `sub` (both stripped-segment and uppercase forms) — already adequate; "leading zeros stripped vs added" collapse to the same code path/bug class (`UUID.fromString` leniency on segment length), one deliberate non-canonical test per field is sufficient since `isCanonicalUuid()` is a single shared private method.
- Concurrent access — not applicable; `verify()` is stateless, no shared mutable state introduced by this diff (the `Map<RejectionReason, Counter>` is built once at construction and only read/incremented via thread-safe Micrometer `Counter` instances afterward).
- Load scenario: `nexus.auth.token_rejected` / `verify()` doesn't change RPS expectations for an already-existing authenticated endpoint path; no new load scenario added, no `docs/TESTING.md` requirement triggered by this diff (login/token endpoints' existing load scripts, if any, are untouched by M6 and out of this diff's scope).

## Tests added
In `nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/security/JwtRs256ServiceTest.java`:
- `should_rejectWithTenantIdReason_when_tenantIdIsUppercaseUuid()`
- `should_reportZeroCount_when_serviceConstructedBeforeAnyVerifyCall()`

Both follow existing AAA/naming conventions in the file and reuse existing helpers (`validClaims`, `signedToken`, `assertRejectedWithReason`, `service(...)`) — no restructuring of existing tests.

Committed as `3bf9643` on `feature/US-018/M6`:
```
test(security): close M6 claim-validation coverage gaps (US-018 T-005)
```

## Run results
Full `./mvnw verify` (Docker/Testcontainers MySQL available) — run twice (before and after the commit):

- Backend unit + slice (Surefire): **1455 passing**, 0 failures, 0 errors, 1 skipped (pre-existing, unrelated `JpaAuthEventAdapterFailurePathBenchmarkTest` conditional skip — not part of this diff).
- Backend integration (Failsafe, Testcontainers MySQL): **353 passing**, 0 failures, 0 errors, 0 skipped.
- JaCoCo per-layer + bundle coverage gates: all met.
- SpotBugs: 0 bugs/errors.
- Checkstyle: passed (cached).
- `BUILD SUCCESS` both times (pre-commit and post-commit confirmation run).
- `JwtRs256ServiceTest`: 35/35 (was 33, +2 new). `JwtRs256ServiceSecurityTest`: 13/13. `JwtAuthenticationFilterTest`: 5/5. `JwtClaimsTest`: 4/4. `RoleAssignmentSecurityIT`: 28/28.

Frontend `npm run test:ci` was **not** run — this diff touches only `nexus-backend` (per the scoped `git diff origin/main...HEAD -- nexus-backend`), no Angular/TypeScript files are in scope.

## Load scenarios
None added. This diff only changes claim-validation logic inside an already-existing authenticated-request path (`JwtRs256Service.verify()`), called on every authenticated request. If `/docs/TESTING.md`'s >10 RPS threshold applies to the overall authenticated-request path, that load scenario (if missing) is a pre-existing gap from whichever milestone first introduced JWT verification to the hot path, not something introduced or widened by M6's claim-validation narrowing — out of scope for this audit per the task's "keep additions minimal and directly tied to a gap" instruction.

## Flaky tests
None identified. All new and existing tests in this diff are deterministic: fixed `Clock` instances (`Clock.systemUTC()`/`Clock.fixed(...)`) where time matters, no `Thread.sleep`, no unseeded randomness affecting assertions (`UUID.randomUUID()` is used only to generate distinct-but-irrelevant identifiers, never as an assertion target), and counter assertions use a fresh `SimpleMeterRegistry` per test instance so there's no cross-test shared state. The two full-suite runs (pre- and post-commit) produced identical pass counts (1455/353, 1 skip both times), with no order-dependent or timing-dependent test observed.

## Files touched
- `nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/security/JwtRs256ServiceTest.java` (only file changed, 24 lines added, 2 new test methods + 1 import)
- Reviewed (no changes needed): `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/security/JwtRs256Service.java`, `nexus-backend/src/main/java/com/example/nexus/identity/domain/JwtClaims.java`, `nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/security/JwtRs256ServiceSecurityTest.java`, `nexus-backend/src/test/java/com/example/nexus/identity/domain/JwtClaimsTest.java`, `nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/web/JwtAuthenticationFilterTest.java`, `nexus-backend/src/test/java/com/example/nexus/rbac/security/RoleAssignmentSecurityIT.java`
