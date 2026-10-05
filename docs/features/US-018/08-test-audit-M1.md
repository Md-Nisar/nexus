# US-018 Milestone 1 test audit (Phase 8, T-004 A8 deny-by-default)

**Verdict: PASS.** Full `./mvnw -B verify` on JDK 25 (enforcer active, Docker up, no `-DskipITs`): BUILD SUCCESS, **1423 unit tests** (0 failures, 1 skipped) and **353 ITs** (0 failures). Checkstyle 0 violations, SpotBugs 0, JaCoCo met. Every item in T-004's "Tests (written first)" list and the M1 merge checklist is met. Eight gaps found and closed with 21 new test executions, all test-only; no production code changed and no existing test weakened (286 insertions, 0 deletions in this commit). The four M1 classes passed three consecutive runs with identical results. No flaky test found; three watch items below.

The qa-engineer's run was independently re-run by the session on the final tree with the same result (1423 / 353, BUILD SUCCESS).

## Scope

Branch `ccr-76994a18-now72v`; `git diff origin/main...HEAD` is backend and docs only, no frontend file. Read: `CLAUDE.md`, `PROJECT.md`, `docs/TESTING.md`, `04-tasks.md` (T-004 and the M1 checklist), `03-design.md` §3, §14, §15, `06-code-review-M1.md`, `07-security-review-M1.md`. Nothing either review already covered is repeated. Docker server 29.6.2, JDK 25. No PII: test principals use fixed synthetic UUIDs.

## What was run

| Run | Result |
|---|---|
| Baseline, four M1 classes | 240 tests (Hexagonal 20, Fixtures 36, Matcher 18, Web 166), 0 failures |
| After additions, same classes | 261 tests (20 / 40 / 25 / 176), 0 failures |
| Mutation check (temporary, reverted) | (a) caller given every RBAC permission; (b) authentication not attached; (c) wrong lambda message expected: 11 failures as intended (all 9 guarded-handler cases, the authenticated case, the lambda case); files restored |
| Stability x3, same four classes | 261/261 each run; timings stable (Hexagonal 0.84–0.97 s, Fixtures 2.0–2.1 s, Matcher 1.8–2.0 s, Web 16.5–16.8 s) |
| **Full backend run** | `cd nexus-backend && sh ./mvnw -B verify` — **BUILD SUCCESS**; Surefire 1423 / 0 failures / 1 skipped (`JpaAuthEventAdapterFailurePathBenchmarkTest`, pre-existing); Failsafe 353 / 0 failures across 55 IT classes against Testcontainers (MySQL 8.4, Redis 7.4) |
| Frontend | `npm run test:ci`: 29 files, 210/210 passed; statements 88.14%, branches 80.03%, functions 82.98%, lines 90.35% (system Node was below the Angular CLI minimum, so a newer Node was installed outside the repo; nothing in the repo changed) |

Gate details: Checkstyle `failsOnError=true`, 0 error-severity violations (177 pre-existing warning-severity entries across 68 `src/main` files; the M1 matcher and marker files have none). SpotBugs BugInstance 0. JaCoCo "All coverage checks have been met" (bundle line 98.4%).

| Package | Line | Branch |
|---|---|---|
| `identity.infrastructure.web` | 94.1% (160/170) | 90.3% (65/72) |
| `common.security` | 95.7% (44/46) | 90.9% (20/22) |
| `identity.interfaces.rest` (5 annotated controllers) | 100% (89/89) | 78.6% (11/14) |

`PublicEndpointRequestMatcher`: 100% line (31/31) and 100% branch (20/20).

**Not run:** frontend lint and format checks (no frontend change). No load scenario: T-004 adds no endpoint and the matcher is not wired into any request path until T-009, so no k6 or Gatling script was written.

## Changed main-source files mapped to tests

| Main-source file | Tests |
|---|---|
| `common/security/PublicEndpoint.java` | Marker rule (production scan plus fixtures); `PublicEndpointRequestMatcherTest` via the real `LoginController` methods; web public, equivalence, dispatch-order and `permitAll` sweeps |
| `common/security/AuthenticatedEndpoint.java` | Identifier rule (production scan, 12 negative fixtures, 1 positive); web completeness sweep; new authenticated-caller sweep |
| `identity/infrastructure/web/PublicEndpointRequestMatcher.java` | `PublicEndpointRequestMatcherTest` (25); web `should_match_exactly_when_handler_is_public_endpoint` (31 mappings) and `should_not_match_when_same_path_as_public_handler_uses_different_method` |
| `LoginController` (login, refresh, logout) | Matcher unit test with real `Method` objects (removing the marker fails it, the RC-24.1 pin); web public sweep (refresh's own `AUTH_004` 401 accepted); equivalence and dispatch-order sweeps |
| `RegistrationController` (3), `PasswordResetController` (2), `JwksController` (1) | Web public, equivalence, dispatch-order and `permitAll` sweeps; JWKS also by the matcher's HEAD→GET test |
| `UserProfileController.me()` | Matcher (non-public, including a CORS preflight); web non-public anonymous sweep (`AUTH_003`); identifier rule on production; new authenticated-caller sweep |

## Gaps found and closed

| Sev | Gap | Closed by |
|---|---|---|
| HIGH | Authorization matrix, signed-in caller with no permission, `@RequiresPermission` column: nothing showed a handler *classified* `@RequiresPermission` is *guarded* at runtime, per handler, for current and future handlers (the existing 403 tests are scattered across rbac `*SecurityIT`s and do not grow with new handlers) | `EndpointClassificationWebTest.should_deny_permission_absent_when_caller_without_permissions_invokes_guarded_handler` (9 dynamic tests) |
| MED | Authorization matrix, `@AuthenticatedEndpoint` column: nothing showed a signed-in caller with zero permissions gets through the chain to `me()` (Decision 1's premise; `SecurityConfigWebTest` covers only the 401 cases) | `should_pass_security_when_caller_without_permissions_calls_authenticated_endpoint` (1 dynamic test) |
| MED | Matcher error path: an exception thrown *after* `parseAndCache` (during condition evaluation) was untested, so cleanup of a just-cached path on the exception path was not exercised | `should_not_match_when_condition_evaluation_throws_after_path_is_parsed`; `should_leave_no_cached_request_path_when_condition_evaluation_throws` (with a precondition assertion so it cannot pass vacuously) |
| MED | Self-invocation rule: lambda bodies and anonymous classes were claimed as flagged but not pinned by any fixture | `should_fail_self_invocation_rule_when_lambda_calls_own_requires_permission_method`; `should_fail_self_invocation_rule_when_anonymous_class_calls_outer_requires_permission_method` |
| LOW | Marker rule: conflicting markers split across the hierarchy (`@PublicEndpoint` on the interface, `@RequiresPermission` on the implementation) had no fixture | `should_fail_marker_rule_when_interface_and_implementation_carry_different_markers` |
| LOW | Override rule: the "is not public" branch had no fixture | `should_fail_override_rule_when_override_of_guarded_base_method_is_not_public` |
| LOW | Matcher boundary values (trailing slash, upper-case path, double slash, lower-case method, unknown method) probed in review but not pinned; T-009 depends on them | `should_not_match_when_request_is_not_canonical_public_method_and_path` (5 cases) |
| — | Concurrency | Closed by inspection: `mappings` is a `final` unmodifiable list built once in the constructor; `Mapping` is a record of an immutable `RequestMappingInfo` and a boolean; `matches()` keeps all per-call state on the request (path attribute saved and restored in `finally`); logger is `static final`. No test written: pinning the construction-time snapshot would assert the fail-open limit L-2 documents |

Why the guarded-handler sweep calls the bean rather than MockMvc: MVC runs `@Valid @RequestBody` validation before the method-security proxy, so a placeholder body stops at 400 and never reaches the guard (create role, attach, assign). Each production handler is instead invoked on its registered proxy bean with null or default arguments as a signed-in caller holding no permission; the test asserts `InsufficientPermissionException` with `PERMISSION_ABSENT` and the permission the handler declares. `SecurityContextHolder` is set and cleared in `try/finally`.

Not duplicated, already covered: permission-holder outcomes (`RoleAssignmentSecurityIT`, `RolePermissionSecurityIT`, `CrossTenantPermissionIT`, `GrantSubsetIT`); anonymous outcomes for every marker (existing web sweeps); the `RBAC_001` response shape (`RequiresPermissionWebTest`).

## Tests added

- `EndpointClassificationWebTest.java` (+132): the two sweeps above and helpers (`performAs`, `authenticatedWithoutPermissions`, `assertDeniedWithoutPermissions`, `placeholderArguments`).
- `PublicEndpointRequestMatcherTest.java` (+46): three methods (7 executions) and the `requestWhoseMethodThrows` helper.
- `AccessMarkerRuleFixturesTest.java` (+108): four tests and their fixtures, all static nested classes outside the component scan (the existing no-nested-fixture-registered test stayed green).

Net +21 test executions (fixtures +4, matcher +7, web +10).

## M1 merge checklist and T-004 "Tests (written first)" evidence

| Item | Status | Evidence |
|---|---|---|
| Three ArchUnit rules green | Met | `HexagonalArchitectureTest` 20/20: `rest_handlers_must_carry_exactly_one_access_marker`, `no_self_invocation_of_requires_permission_methods`, `authenticated_endpoints_take_no_uuid_identifier`, plus follow-up rules `no_handlers_outside_annotated_controllers` and `requires_permission_overrides_must_be_proxyable` |
| Each rule's negative fixture proves it fires | Met | `AccessMarkerRuleFixturesTest` 40/40; every negative asserts the fixture's own method name. Marker rule 9 negatives and 1 positive; self-invocation 7 and 1; identifier 12 and 1; public/non-final 1 negative; override 3 and 1; handler type 3 and 1 |
| Rules cannot pass vacuously | Met | Marker and override rules have no `allowEmptyShould`; self-invocation and handler-type rules range over all classes; the identifier rule's `allowEmptyShould(true)` is legitimate and its predicate is proven by 13 fixtures; all web sweeps assert non-empty input |
| `EndpointClassificationWebTest` green | Met | 176/176: public sweep 9; non-public anonymous 10 (`AUTH_003`, no `instance`); equivalence 31 mappings; completeness 19; dispatch order 9; `permitAll` 17 and drift 56; nested probe 1; new sweeps 1 + 9 |
| All flags on | Met | `should_register_every_production_rest_controller_when_all_flags_enabled` |
| Matcher: login/refresh/logout POSTs match; GET refresh does not; parse-throw false; unknown path false | Met | `should_match_when_anonymous_post_to_public_auth_endpoint` x3; `should_not_match_when_method_differs_on_public_pattern`; `should_not_match_when_path_parsing_throws`; `should_not_match_when_path_unknown` |
| `GuardedTestController` unaffected | Met | No diff for it or `RequiresPermissionWebTest`; `RequiresPermissionWebTest` 10/10; ArchUnit excludes it, the web test allowlists it. Still component-scanned into test contexts (security review I-1) |
| No load scenario | n/a | No new endpoint; matcher not wired until T-009 |

## Flaky tests

None found. Three runs gave the same 261/261 with stable timings; no `Thread.sleep`, `@DirtiesContext`, `@TestMethodOrder`, real clock or unseeded `Random`, and no static mutable state in the four classes. Watch items, not failures:

1. **Random UUIDs in `Endpoint.expand`.** Path variables are filled with `UUID.randomUUID()` because the T-004 spec asks for it. Requests are classified before any handler reads the value, so outcomes do not depend on it; test names use the pattern, not the value.
2. **Two cached contexts share one named H2 database.** The nested `PermitAllOverlapProbe` has its own context but shares `jdbc:h2:mem:nexus-endpoint-classification-test;DB_CLOSE_DELAY=-1` with `create-drop`, so its startup recreates the schema under the main context. No test reads rows today; it would become order-dependent if one ever did.
3. **ArchUnit import caching is safe.** `@AnalyzeClasses` imports are cached per JVM and read-only; the fixture test uses a fresh `ClassFileImporter` per test; `PRODUCTION_CLASSES` is static and read-only.

Also: the guarded-handler sweep sets the global `SecurityContextHolder` and clears it in `finally`; Surefire's console line attributes the outer class's tests to `EndpointClassificationWebTest$PermitAllOverlapProbe` (cosmetic). `EndpointClassificationWebTest` takes about 16.5 s alone (about 6 s inside the full suite), mostly two Spring context starts; justified by the design's need for the full security chain.

## Final counts

| | Before audit | After |
|---|---|---|
| `HexagonalArchitectureTest` | 20 | 20 |
| `AccessMarkerRuleFixturesTest` | 36 | 40 |
| `PublicEndpointRequestMatcherTest` | 18 | 25 |
| `EndpointClassificationWebTest` (with nested probe) | 166 | 176 |
| Backend unit (Surefire) | 1402 / 1 skipped | **1423, 0 failures, 1 skipped** |
| Backend IT (Failsafe) | 353 | **353, 0 failures** |
| Frontend | n/a | **210/210** |

## Residual gaps (not closed; outside M1 test scope or accepted)

- `@AuthenticatedEndpoint` declared only on a supertype is not checked by the identifier rule, and identifiers inside a `@RequestBody` are out of scope (D-8); both stay review-only.
- The override rule's "is static" branch has no reachable fixture (Java will not let a static method override an instance method); defence in depth only.
- The construction-time snapshot limit (L-2) and the missing failed-closed counter (I-2) belong to T-009.
- Path-only `permitAll` (F-5 root cause), P-1 (rate-limit filter encoded-path bypass) and P-2 (actuator exposure) are pre-existing or deferred and need their own tickets.
- `@Valid` body validation runs before the `@RequiresPermission` check, so a caller without the permission gets 400 rather than 403 on create role, attach and assign. Existing behaviour, a small information-disclosure nuance, not an M1 regression; noted for the T-009 and security backlog.
- OWASP dependency-check is a CI-only gate for this project and was not run locally.
