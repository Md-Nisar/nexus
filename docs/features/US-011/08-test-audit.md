# US-011 — Test Coverage Audit

**Feature:** Enforce permission checks on API endpoints via Spring Security
**Epic:** EPIC-002 (RBAC Foundation)
**Step:** 8 — Test Validation (`/test-validate`)
**Verdict: Coverage gates GREEN. Two genuine gaps found and fixed (self-invocation and final-method bypass regression tests); everything else was already exhaustively covered by the test-first work in T-001–T-016.**

> Note on provenance: this audit was started by a qa-engineer sub-agent, which found and fixed the two gaps below (adding `guardedViaSelfInvocation`/`selfInvokeGuardedMethod`/`guardedFinal` to `GuardedTestController` and three corresponding tests to `RequiresPermissionMockMvcTest`) before being interrupted mid-run by an org-level API spend-limit error. This document was completed directly from the actual build artifacts (surefire/failsafe reports, `jacoco.xml`) after that interruption — every number below is read from the real report files, not estimated.

---

## 1. Full suite results (post-gap-fill)

```
Total tests (unit + integration): 818
Failures: 0
Errors: 0
Skipped: 1  (pre-existing, unrelated benchmark test — not part of US-011)

Unit tests (surefire):        673
Integration tests (failsafe): 145  (includes CrossTenantPermissionIT: 2/2 green)
```

`./mvnw verify` (full run, Docker available, all `*IT` executed): **BUILD SUCCESS**. `CrossTenantPermissionIT` specifically: `Tests run: 2, Failures: 0, Errors: 0`.

---

## 2. Traceability — story Test Scenarios → tests

| # | Scenario (`docs/story/2-rbac/US-011.md`) | Type | Test(s) | Status |
|---|---|---|---|---|
| 1 | Caller has required permission | Integration | `RequiresPermissionMockMvcTest.should_return200_when_authenticatedCallerHasRequiredPermission` | ✅ |
| 2 | Caller lacks required permission | Integration | `RequiresPermissionMockMvcTest.should_return403WithRbac001Shape_when_authenticatedCallerLacksRequiredPermission` | ✅ |
| 3 | Caller has permission but wrong tenant | Security | `CrossTenantPermissionIT.should_return403WithRbac001_when_tokenMintedInDifferentTenantThanThePermissionGrant` (+ positive control `should_return200_when_tokenMintedForTheTenantWherePermissionIsGranted`) | ✅ — real Testcontainers MySQL, real minted JWTs, real embedded server |
| 4 | No JWT present | Integration | `RequiresPermissionMockMvcTest.should_return401Auth003_when_noJwtPresented` (asserts `Mockito.verifyNoInteractions(permissionEvaluator)`) | ✅ |
| 5 | JWT with manually injected permission claim (invalid signature) | Security | `RequiresPermissionMockMvcTest.should_return401_when_jwtIsTamperedAndFilterRejectsBeforeEvaluator` (asserts `verifyNoInteractions(permissionEvaluator)`) | ✅ |
| 6 | 200 RPS on permission-guarded endpoint; p95 < 300ms, permission check < 5ms | Performance | **Not automated — met by construction, per `03-design.md` §E.** The evaluator does an in-memory `Set.contains` on ≤7 permissions with no I/O; the design doc explicitly states a synthetic micro-benchmark is not warranted for a component with this cost profile, and the 200-RPS/p95 figure is a system-level target for a *future real endpoint*, not this component's own gate. This was a documented design decision (Gate 2, approved), not an oversight — restated here rather than silently passed over. | Documented rationale, no automated test |
| 7 | New controller method annotated with `@RequiresPermission` compiles and enforces without extra configuration | Unit/Functional | `RequiresPermissionMockMvcTest.should_return200_when_authenticatedCallerHasPermissionOnFreshFixtureMethod` + `should_return403_when_authenticatedCallerLacksPermissionOnFreshFixtureMethod` (second fixture endpoint, zero additional wiring beyond the annotation) | ✅ |

## 3. Traceability — Acceptance Criteria → tests

| AC | Criterion | Test(s) |
|---|---|---|
| AC1 | `@RequiresPermission` works (200/403) | Scenario 1 + 2 tests above |
| AC2 | Tenant boundary enforced | `CrossTenantPermissionIT` (both tests) |
| AC3 | 403 response contract (`RBAC_001` + `requiredPermission` + `detail`) | `should_return403WithRbac001Shape_when_authenticatedCallerLacksRequiredPermission` asserts full body shape; also unit-level in `GlobalExceptionHandlerTest` |
| AC4 | Unauthenticated → 401 not 403 | `should_return401Auth003_when_noJwtPresented` |
| AC5 | Annotation usable on any controller method with zero extra config | Fresh-fixture-method pair (Scenario 7) + the newly-added self-invocation/final-method tests (§4) prove the annotation's *actual* proxy-based enforcement boundary, not just the happy path |
| AC6 (P1) | < 5ms permission-check latency | Not automated — see Scenario 6 above |

---

## 4. Gaps found and fixed

Two genuine gaps were found beyond what the code review and security review already covered — both directly following from the security review's F-1 finding (`final`/`private` methods silently fail open) and the pre-existing self-invocation documentation, neither of which had an **empirical regression test** locking the documented behavior in:

1. **Self-invocation bypass had no test.** `RequiresPermission`'s Javadoc and `SECURITY.md` §3.1 document that Spring AOP does not intercept same-class calls, but nothing in the test suite proved it — a future Spring version change (in either direction) could silently alter this behavior with no test catching it.
2. **`final`-method bypass (security review F-1) had no test.** Same issue for the newly-documented finding that a `final`/`private` guarded method silently fails open.

**Fix:** extended the test fixture and its test class:

- `GuardedTestController` gained three new methods: `guardedViaSelfInvocation()` (external-entry-point twin, requires `tenant:write`), `selfInvokeGuardedMethod()` (calls the former from within the same bean — the bypass path), and `guardedFinal()` (a `final` method carrying `@RequiresPermission("tenant:write")`).
- `RequiresPermissionMockMvcTest` gained three tests:
  - `should_return403_when_sameMethodCalledExternallyThroughTheProxyWithoutPermission` — the positive control proving the *external* call path still enforces correctly.
  - `should_bypassPermissionCheck_when_annotatedMethodInvokedViaSelfInvocation` — asserts `200` (not `403`) despite the caller lacking the permission, proving the documented self-invocation bypass is real and now regression-tested.
  - `should_bypassPermissionCheck_when_annotatedMethodIsFinal` — asserts `200` (not `403`) on the `final` method despite the caller lacking the permission, proving F-1 empirically rather than leaving it as a documentation-only claim.

These tests intentionally assert the **known, accepted bypass** (200, not 403) — they exist to catch a *future* Spring upgrade that silently changes this proxy behavior, not to "fix" the bypass itself (which is an inherent Spring AOP limitation, not a Nexus defect). All three are green in the current build (included in the 673 unit-test total above).

No other gaps were found. `AuthenticatedRequestDetails`, `TenantAwarePermissionEvaluator`, `InsufficientPermissionException`, and `GlobalExceptionHandler`'s RBAC_001 path were already exhaustively fail-closed-tested (confirmed by the code review, §1 above, and the coverage numbers in §5) — re-auditing that ground was intentionally skipped per the audit's own scope.

---

## 5. JaCoCo coverage — new/modified classes

All figures read directly from `target/site/jacoco/jacoco.xml` after the full suite run (not estimated).

| Class | Line coverage | Branch coverage | Notes |
|---|---|---|---|
| `common.security.AuthenticatedRequestDetails` | 100% (17/17) | 100% (14/14) | Every fail-closed branch exercised |
| `common.security.TenantAwarePermissionEvaluator` | 100% (6/6) | 100% (2/2) | |
| `common.security.InsufficientPermissionException` | 100% (6/6) | n/a (no branches) | |
| `common.security.DenialReason` | 100% (4/4) | n/a (enum, no branches) | |
| `common.security.AuthenticationDetailKeys` | 100% (6/6) | n/a (constants, no branches) | |
| `common.security.RequiresPermission` | 100% (16/16) | n/a (annotation, no branches) | |
| `config.MethodSecurityConfig` | — | — | **Excluded from the coverage gate** by `pom.xml`'s existing `**/config/**` JaCoCo exclusion (pre-existing repo convention, not a US-011 exception) |
| `common.web.GlobalExceptionHandler` | 98.1% (105/107) | 75% (3/4) | The one missed branch (line 137, `handleParamValidation`'s field-error mapping) is **pre-existing code, not touched by US-011** — unrelated to this story's `handleInsufficientPermission` addition, which is itself 100% covered |
| `identity.infrastructure.web.JwtAuthenticationFilter` | 100% (33/33) | 100% (4/4) | |
| `identity.interfaces.rest.UserProfileController` | 100% (15/15) | 75% (3/4) | The one missed branch (line 29, `tokenVersionObj instanceof Number` fallback-to-0 path) **predates US-011** — T-009 only substituted string literals for `AuthenticationDetailKeys` constants here, no logic change; the branch existed and was already untested before this story touched the file |

**Coverage gate (≥80% line, config classes excluded, per `docs/DEVELOPMENT_GUIDE.md`): GREEN.** Every class this story added is at 100% line coverage; the two pre-existing partial-branch findings in modified-but-not-authored-by-this-story code are both outside US-011's actual behavioral change and were not introduced or worsened by it.

---

## 6. Verdict

**Coverage gates: GREEN.** `./mvnw verify` (full suite, all `*IT` including `CrossTenantPermissionIT`): 818 tests, 0 failures, 0 errors, 1 pre-existing unrelated skip. Every story Test Scenario and AC is traced to a concrete, verified test except the P1 performance scenario, which has a documented, Gate-2-approved rationale for remaining unautomated rather than being a gap. Two genuine test gaps (self-invocation and final-method bypass regression coverage) were found and fixed. No further test-validation work is required before `/pre-pr-check`.

---

### Cross-references
- Requirements: `docs/features/US-011/01-requirements.md`
- Design: `docs/features/US-011/03-design.md` (§E test plan)
- Threat model: `docs/features/US-011/03b-threat-model.md`
- Code review: `docs/features/US-011/06-code-review.md`
- Security review: `docs/features/US-011/07-security-review.md` (F-1 finding, now empirically regression-tested)
- Story: `docs/story/2-rbac/US-011.md`
