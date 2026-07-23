# US-011 — Code Review

**Feature:** US-011 — Enforce permission checks on API endpoints via Spring Security
**Epic:** EPIC-002 (RBAC Foundation)
**Branch:** feature/US-011 (no commits yet — reviewed as the full uncommitted working-tree diff vs. `origin/main`, `git diff` / `git status`)
**Reviewer:** code-reviewer sub-agent (fresh context)
**Cross-referenced against:** `docs/features/US-011/03-design.md`, `03b-threat-model.md` (verdict: APPROVE WITH CONDITIONS, 5 required + 1 recommended), `04-tasks.md` (16 tasks), `docs/adr/0013-rbac-data-model-and-enforcement-contract.md` (D5/D6 amendment), `SECURITY.md` §3.1, `CLAUDE.md`, `docs/coding-standards.md`.

**Verification performed:** read every new/modified production and test file; ran `./mvnw verify -DskipITs` (668 unit tests, 0 failures/errors, 0 checkstyle violations, 0 SpotBugs findings, JaCoCo gate met); traced `CrossTenantPermissionIT`'s seed data against `V5__rbac_schema.sql`'s actual UUIDs (confirmed correct — `tenant:write` = `019f6839-1801-…002`, `MEMBER` role = `019f6839-1811-…00b`); confirmed via `git diff` that all three `AuthenticationDetailKeys` consumers were updated together and all three `GlobalExceptionHandler` test call sites picked up the new `MeterRegistry` constructor param; did not execute `CrossTenantPermissionIT` itself (Docker unavailable in this environment) — read it closely instead.

## Summary

| Severity | Count |
|---|---|
| Blocker | 0 |
| High | 0 |
| Medium | 0 |
| Low | 3 |
| Nit | 2 |

**Verdict: APPROVE WITH NITS**

---

## Findings

### [Low] Denial-logging logic in `GlobalExceptionHandler` duplicates, rather than extends, the existing `logHandledException` helper

**File:** `nexus-backend/src/main/java/com/example/nexus/common/web/GlobalExceptionHandler.java:144-157` vs. `196-218`

`handleInsufficientPermission` hand-rolls its own `log.atWarn()...` chain (correlationId lookup, key-value building, message template) instead of reusing `logHandledException(Exception, String, String)`, which every other handler in the class uses. The duplication exists because `logHandledException` doesn't support arbitrary extra structured fields (`reason`, `requiredPermission`, `userId`, `tenantId`) — a real constraint, not an oversight — but the result is two independent places that both compute `correlationId` and both build a WARN-level structured log entry, with no shared helper between them.

**Why it matters:** Not a bug today, but a maintenance/consistency smell. A future change to the WARN-log shape (e.g., adding a new default field to every handled-error log) has to be applied in two places, and a reviewer skimming the class for "how do we log a handled error" now sees two different patterns.

**Suggested fix:** Extend `logHandledException` (or add an overload) to accept a `Map<String, Object>` / varargs of extra key-values, e.g. `logHandledException(e, "WARN", "RBAC_001", Map.of("reason", ..., "requiredPermission", ..., "userId", ..., "tenantId", ...))`, and route `handleInsufficientPermission` through it. Small, mechanical, not blocking.

---

### [Low] MDC key literals (`"userId"`, `"tenantId"`) are duplicated string constants with no compile-time binding, in the same spirit as the problem `AuthenticationDetailKeys` was introduced to solve

**File:** `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/web/JwtAuthenticationFilter.java:86-87`, `nexus-backend/src/main/java/com/example/nexus/common/web/GlobalExceptionHandler.java:153-154`

This PR introduces `AuthenticationDetailKeys` specifically to close the "stringly-typed contract between producer and consumer" gap (T-06/T-009) for the `Authentication.getDetails()` map. The *new* code this PR adds to `GlobalExceptionHandler` (`MDC.get("userId")`, `MDC.get("tenantId")`) reads from a different but structurally identical stringly-typed contract — MDC keys set by `JwtAuthenticationFilter` — using bare literals, with no shared constant. This isn't a regression (the MDC-key pattern itself predates this story, per `docs/coding-standards.md`'s "MDC fields: `traceId`, `userId`, `tenantId`"), but the new consumer added by this PR (`handleInsufficientPermission`) is a fresh place where a rename on the producer side (`JwtAuthenticationFilter`) would silently degrade the new RBAC denial log to `userId=null, tenantId=null` with no compiler warning — exactly the class of fragility T-009 was written to eliminate for the *other* map.

**Why it matters:** Low severity — a mismatch fails safe (a null log field, not a security hole), and it's consistent with pre-existing codebase convention. But since this PR is the one adding a new consumer of these particular MDC keys, and it just finished solving the identical problem for `Authentication.getDetails()`, it's an easy, cheap consistency win to close now rather than leave as an inconsistency between two "same shape, different treatment" contracts in one diff.

**Suggested fix:** Add `MDC_USER_ID` / `MDC_TENANT_ID` constants (e.g. to `AuthenticationDetailKeys` or a small `MdcKeys` holder) referenced by both `JwtAuthenticationFilter.doFilterInternal` and `GlobalExceptionHandler.handleInsufficientPermission`. Optional, not blocking.

---

### [Low] `AuthenticatedRequestDetails.fromAuthentication` takes a `requiredPermission` parameter that exists solely to phrase an exception message — a deviation from the design's two-argument sketch, undocumented outside the class Javadoc

**File:** `nexus-backend/src/main/java/com/example/nexus/common/security/AuthenticatedRequestDetails.java:40-41`

`03-design.md` §B2 sketches `fromAuthentication(Authentication)` — one argument. The shipped signature is `fromAuthentication(Authentication, String requiredPermission)`, where the second argument is used *only* to construct `InsufficientPermissionException` on the various fail-closed branches (it plays no role in reading/validating the details map itself). This is a reasonable, well-justified implementation refinement — the class Javadoc explains it plainly ("exists solely to construct that exception; it is not otherwise used by this factory") — but it's a real signature deviation from the design doc that wasn't called out anywhere in `03-design.md`, `03b-threat-model.md`, or `04-tasks.md` as a "verified basis" change.

**Why it matters:** Nothing functionally wrong; flagging only because the design doc is supposed to be the binding contract other stories build against, and a future consumer of `AuthenticatedRequestDetails` skimming the design doc would be surprised by the extra parameter. Purely a documentation-freshness nit.

**Suggested fix:** None required for merge. Worth a one-line note added to `03-design.md` §B2 (or a footnote in the ADR-0013 amendment) the next time that doc is touched, so the "verification basis" stays accurate for future readers.

---

### [Nit] `InsufficientPermissionException` has no `serialVersionUID`

**File:** `nexus-backend/src/main/java/com/example/nexus/common/security/InsufficientPermissionException.java:25`

`AccessDeniedException` (and its superclasses) are `Serializable`; this subclass doesn't declare `serialVersionUID`. SpotBugs doesn't flag it (confirmed — 0 findings), and no current code serializes this exception, so this is cosmetic only.

---

### [Nit] `TenantAwarePermissionEvaluatorTest` and `AuthenticatedRequestDetailsTest` both hand-roll an identical `authenticationWithDetails`/`authenticatedWith` fixture pair

**File:** `nexus-backend/src/test/java/com/example/nexus/common/security/TenantAwarePermissionEvaluatorTest.java:19-32`, `nexus-backend/src/test/java/com/example/nexus/common/security/AuthenticatedRequestDetailsTest.java:20-33`

Byte-for-byte identical private helper methods in two test classes in the same package. Harmless (test code, not production), but a small `AuthenticationTestFixtures` helper in `common.security` (test sources) would remove the duplication cheaply. Not blocking — test quality is otherwise excellent (exhaustive fail-closed branch coverage, reason assertions on every throw site).

---

## Things done well

This is a notably rigorous piece of security-critical work. Specific highlights:

- **Threat-model conditions were genuinely implemented, not just marked done.** Independently verified all five required conditions against the actual code rather than trusting `04-tasks.md`'s own "done" claims:
  - **T-02/Cond 1** (tenant-provenance invariant): the Javadoc on `TenantAwarePermissionEvaluator` states the invariant explicitly; `JwtRs256ServiceTest.should_sourcePermissionsResolutionAndTenantClaim_fromSameTenantId_when_tokenIssued` genuinely locks `issue()` to source both values from the same `user.getTenantId()` via an `ArgumentCaptor`; and the ArchUnit rule `only_jwtAuthenticationFilter_sets_authentication_details` correctly targets `setDetails` calls on any `Authentication`-assignable owner type, confirmed to pass cleanly (9/9 `HexagonalArchitectureTest` cases green) with no false-positives against the (excluded) test-only `setDetails` calls in `TenantAwarePermissionEvaluatorTest`/`AuthenticatedRequestDetailsTest`.
  - **T-02/Cond 2** (`CrossTenantPermissionIT` as a genuine end-to-end proof): this is the real deal — Testcontainers MySQL, a real persisted `User`, a real second tenant seeded on the fly, real `Role`/`RolePermission`/`UserRole` rows, and a **real minted JWT** via the actual `jwtPort.issue(user)` (not a hand-built claims object). It calls the fixture endpoint through a real embedded server (`RANDOM_PORT` + `RestTemplate`, not MockMvc), asserting 403/`RBAC_001` for the cross-tenant case and 200 for the positive control. This is exactly the proof the threat model demanded, not a token approximation of it.
  - **T-08/Cond 5** (denial-reason discriminator): `DenialReason` (`PERMISSION_ABSENT`/`MALFORMED_AUTHENTICATION`/`MISSING_TENANT`) is set correctly at every throw site, asserted by both unit tests and the `GlobalExceptionHandlerTest` Logback `ListAppender` tests that capture the *actual* rendered structured log fields — not just that MDC happened to contain the values, but that the handler's log statement genuinely emits them.
  - **T-05/Cond 4** (self-invocation): `SECURITY.md` §3.1 gives this the most prominent treatment in the new doc section, with a concrete before/after code example — appropriately weighted for a silent-bypass-class limitation.
  - **T-06/Cond 6** (shared detail-key constants + producer contract test): `AuthenticationDetailKeys` is referenced consistently by all three real consumers (`JwtAuthenticationFilter`, `AuthenticatedRequestDetails`, `UserProfileController` — verified via `git diff`, no literal left behind), and `AuthenticationDetailsContractTest` exercises the **real** `JwtAuthenticationFilter.doFilter` end-to-end rather than a hand-built `Authentication`, which is exactly what makes the contract test meaningful.

- **Fail-closed is actually fail-closed, exhaustively.** Every deny branch in `AuthenticatedRequestDetails.fromAuthentication` and `TenantAwarePermissionEvaluator.hasPermission` throws `InsufficientPermissionException` with the correct `DenialReason` — none silently return `true`/allow, none produce a 500. This was verified in code, not just asserted by the tests that ship with it.

- **Constructor-injection ripple was fully handled.** `GlobalExceptionHandler`'s new required `MeterRegistry` param was updated at all three call sites across the suite (`GlobalExceptionHandlerTest`, `LoginControllerTest`, `PasswordResetControllerTest`) — confirmed by grep across the whole test tree, nothing missed.

- **The exception-dispatch claim (§A.2 of the design) is tested, not assumed.** `GlobalExceptionHandlerTest.should_resolveInsufficientPermissionHandler_notGenericAccessDeniedHandler_when_dispatched` uses Spring's real `ExceptionHandlerMethodResolver` to prove `InsufficientPermissionException` resolves to the specific handler over the generic `AccessDeniedException` one — a genuinely useful regression guard against a future handler-ordering surprise.

- **PII discipline is clean.** The new WARN log and Micrometer counter carry only UUIDs (`userId`, `tenantId`), enum names (`reason`), and a closed, code-defined permission vocabulary — no names, emails, or free text. Counter cardinality is bounded (`permission` × `reason` ≈ 7 × 3), matching the design's stated bound.

- **The `GuardedTestController` fixture is correctly isolated.** Confirmed it lives strictly under `src/test/java`, is registered only via `@TestConfiguration`/`@Import` (never `@ComponentScan`), and is therefore structurally incapable of shipping — Maven's separate main/test output directories make this a non-issue regardless of scanning configuration, and the design's own reasoning for the fixture-over-real-endpoint choice (§B6) is sound.

- **Documentation quality is high and genuinely useful**, not boilerplate: `SECURITY.md` §3.1's self-invocation warning includes a concrete "wrong code / right code" pair; the ADR-0013 D5/D6 amendment correctly follows the append-only convention and cross-references the threat model; `EPIC-002.md`'s Open Decisions items 4–5 correctly distinguish the still-open Epic-3 entry criterion from the now-closed CI-gate one.

- **All quality gates are green**: 668 unit tests / 0 failures, 0 checkstyle violations, 0 SpotBugs findings, JaCoCo coverage met (independently re-run, not taken on faith from the task doc).

---

## Verdict: **APPROVE WITH NITS**

No Blocker, High, or Medium findings. The three Low findings are minor consistency/duplication observations that don't affect correctness or security, and the two Nits are cosmetic. This is a strong implementation that took its own threat model seriously — every required condition was independently verified in the actual code rather than trusted from the task breakdown's self-reported status.
