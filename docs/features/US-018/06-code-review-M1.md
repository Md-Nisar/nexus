# US-018 Milestone 1 code review (T-004, A8 deny-by-default)

**Verdict: CHANGES REQUESTED.** No Blocker or High findings. Two Medium findings are bypasses of the build controls, reproduced by probe; both are fixable in test code only. Nothing in shipped behaviour is wrong today.

Scope: `git diff origin/main...HEAD` (one commit, `09c4c03`, 12 files, all under `nexus-backend/`; 1077 insertions, 0 deletions, so every pre-existing rule in `HexagonalArchitectureTest` is byte-unchanged). Checked against design §3.1, §3.3, §3.4, §14; threat model T-E39, T-E45, RC-24.1, RC-40.2, RC-44.1, RC-44.3; `04-tasks.md` T-004.

**Reviewer ran** (JDK 25): `sh ./mvnw -B -o verify -DskipITs` — BUILD SUCCESS, 1255 tests, 0 failures, 1 skipped; 0 Checkstyle violations; SpotBugs 0; JaCoCo met; `PublicEndpointRequestMatcher` 100% line (31/31) and branch (20/20). Targeted: `HexagonalArchitectureTest` 18, `AccessMarkerRuleFixturesTest` 10, `PublicEndpointRequestMatcherTest` 13, `EndpointClassificationWebTest` 52 (public sweep 9 handlers, non-public sweep 10, matcher-equivalence sweep 31 mappings). Scratch probes against the real matcher and real `ArchRule` constants (throwaway, not in the repo).
**Not run by the reviewer:** the Failsafe `*IT` suite (the session's own full `./mvnw verify` on JDK 25 ran 353 ITs, 0 failures, before this review). The reviewer did not directly confirm that nested fixture `@RestController`s are excluded from component scanning; the test results are consistent with `TestTypeExcludeFilter` excluding them.

**Approved deviations (not defects):** (1) identifier rule bans any `@PathVariable` plus UUID `@RequestParam` on `@AuthenticatedEndpoint` (user-approved Option B); (2) fixtures are static nested classes, not an `architecture/fixtures` package; (3) matcher intentionally not wired into a filter (T-009); (4) `SecurityConfig` `permitAll` is path-only (out of scope, flagged for T-009).

## What is correct

- **Matcher fails closed** (`PublicEndpointRequestMatcher.java`): method and path matched together; overlap with any non-public mapping returns false; a non-public mapping with no path-patterns condition counts as matching; a `@PublicEndpoint` handler with no HTTP method or no path patterns is non-public; `RuntimeException` returns false with a class-name-only DEBUG log (no stack trace, path or PII); path re-parsed rather than trusting a cached one; cached path attribute restored in `finally`.
- **Probes match MVC dispatch:** trailing slash, upper-case path, double slash, lower-case/unknown method, plain `OPTIONS` → false. CORS preflight for POST to login → true; preflight for GET on `/users/me` → false; `HEAD` on JWKS → true (dispatches to the GET handler); `;jsessionid` and `%6Cogin` → true (same handler as MVC; the firewall rejects `;`); valid context path → true. No request attributes left behind.
- **No meta-annotation bypass:** all three markers are `@Target(METHOD)` only.
- **Rule 1 cannot pass vacuously:** no `allowEmptyShould`, no `archunit.properties` override; a method with a bare `@RequestMapping` is selected and flagged. `@RequiresPermission` counts as a marker (otherwise all 9 RBAC handlers would be flagged).
- **Fixture assertions are meaningful:** they assert the fixture's method name, so an empty-should failure cannot masquerade as a real violation.
- **Self-invocation rule** flags plain calls, `this::m`, lambdas, anonymous and inner classes, and `super.` calls.
- **`EndpointClassificationWebTest`:** fingerprints the entry-point response (`AUTH_003` with no `instance` member), not just 401, which correctly lets refresh's own `AUTH_004` through; all flags on with a registration check proving no flag-gated controller dropped; every pattern × method swept; same-path different-method fixture registered via `@TestConfiguration` and included in the equivalence sweep.
- **Unit test pins production markers:** `PublicEndpointRequestMatcherTest` uses the real `LoginController`/`UserProfileController` `Method` objects, so removing `@PublicEndpoint` from login, refresh or logout fails it (the RC-24.1 pin).
- Layering: matcher depends only on `common.security` and Spring MVC. Nothing outside T-004 scope.

## Findings

### Medium

**M-1. Handlers not declared directly in a `@RestController` class escape both the marker rule and the anonymous sweep.**
`HexagonalArchitectureTest.java:250-251`; `EndpointClassificationWebTest.java:108-115, 263`.
The rule selects methods declared in a `@RestController` class that carry a mapping annotation themselves. MVC also registers mappings on an implemented interface, mappings inherited from an abstract base, and `@Controller` + `@ResponseBody` classes; the probe confirmed MVC registers all three and the rule selects none. The web test has no "exactly one marker" check (an unmarked interface-mapped handler gets `AUTH_003` and passes as non-public), and `PRODUCTION_CONTROLLERS` is defined as `@RestController` classes, so a `@Controller` handler is dropped from the sweep.
*Scenario:* `@RestController class TenantController implements TenantApi`, where `TenantApi` carries `@GetMapping("/api/v1/tenants/{id}")` and no marker. Build green; any signed-in caller with zero permissions reaches the handler — the "nobody decided that" situation FR-A8.a exists to prevent.
*Fix (test-only):* (1) in `EndpointClassificationWebTest`, add a completeness sweep over `handlerMapping.getHandlerMethods()` for production handlers asserting exactly one of the three markers via `AnnotatedElementUtils.hasAnnotation(handler.getMethod(), marker)`; (2) define "production" as bean type in the production class set (all classes from the `DoNotIncludeTests` import) rather than only `@RestController`; (3) optionally widen the ArchUnit selector to `areMetaAnnotatedWith(Controller.class)`.

**M-2. The `@AuthenticatedEndpoint` identifier rule misses an implicitly bound `UUID` parameter.**
`HexagonalArchitectureTest.java:376-383`.
MVC binds an unannotated simple-type parameter as an implicit `@RequestParam`; the rule checks only explicit `@RequestParam`.
*Scenario:* `@AuthenticatedEndpoint @GetMapping("/api/v1/users/profile") ProfileResponse profile(Authentication a, UUID userId)` serves `?userId=<another user>` — an IDOR with zero permissions; probe: "rule3 unannotated UUID param: PASSES". A `@ModelAttribute` or record parameter with a UUID field is the same gap.
*Fix:* flag any parameter whose raw type is `UUID`, annotated or not (an authenticated-only handler takes identity from the principal). Add a fixture with an unannotated `UUID` parameter. Related: `@RequestParam String userId` also passes (probe-verified); see open question 1.

### Low

**L-1. Self-invocation rule misses `@RequiresPermission` declared on an interface or superclass method that the class overrides.** `HexagonalArchitectureTest.java:345-346`. `resolveMember()` resolves to the unannotated override and `isAnnotatedWith` checks only direct annotations. *Scenario:* `interface S { @RequiresPermission("x") void g(); }`, `class Impl implements S { void caller() { g(); } }` — probe: not flagged; Spring Security finds the annotation through the interface, so `g()` is guarded on proxied calls but unguarded on the self-call. *Fix:* also treat the target as annotated when a same-signature method in `getAllRawSuperclasses()`/`getAllRawInterfaces()` carries it; add a fixture.

**L-2. Matcher knows only the `requestMappingHandlerMapping` contents at construction, but its Javadoc implies global exclusivity.** `PublicEndpointRequestMatcher.java:31-33, 58-62`. A higher-precedence `HandlerMapping` (actuator's is order -100) wins dispatch while the matcher still answers true; a mapping added later via `registerMapping` has the same effect. Neither overlaps a public pattern today (actuator is at `/actuator`; nothing calls `registerMapping` at runtime), but once T-009 wires the matcher in, either becomes a silent fail-open. *Fix:* state both limits in the Javadoc; in `EndpointClassificationWebTest`, for each public `(method, pattern)` resolve the handler through the DispatcherServlet's ordered `HandlerMapping` list and assert the first mapping to return a handler gives the same `@PublicEndpoint` `HandlerMethod`.

**L-3. M1 deviations are not recorded in the feature docs.** `09-technical.md` §6; `03-design.md` §3.1, §3.4; `04-tasks.md:259, 280`. Option B and the nested-fixture placement live only in code comments and the commit message; the design still says "UUID-only", "architecture/fixtures", and "7 rbac handlers" (actual: 9). *Fix:* add D-8 (Option B), D-9 (fixtures as nested classes) and a stale-count note in the style of D-5, or confirm deferral to Phase 9.

**L-4. `should_not_match_when_public_handler_has_no_path_patterns_condition` does not pin the documented "poison everything" behaviour.** `PublicEndpointRequestMatcherTest.java:110-122`. The class Javadoc says a mapping without a path-patterns condition is treated as matching every request. *Fix:* also assert `matches(request("POST", LOGIN))` is false after registering the ant-style mapping.

### Nit

- `PublicEndpoint.java`: document that the equivalence test effectively requires every `@PublicEndpoint` handler to declare an explicit HTTP method.
- `authenticated_endpoints_take_no_uuid_identifier` (`HexagonalArchitectureTest.java:290`) undersells what Option B bans; keep the name for traceability, add a `@DisplayName` or renamed constant.
- `ACCESS_MARKERS` (`HexagonalArchitectureTest.java:315`) is declared after the `@ArchTest` field that uses it; works only because it is read lazily in `check()`. Move it above the rules.
- Pin HEAD→GET, CORS preflight, plain `OPTIONS` and valid context path in the matcher unit tests; T-009 will rely on them (all correct today).
- The public sweep asserts only "not the entry-point 401"; a 403 from the access-denied handler would also pass. Cheap to also assert not `ACCESS_DENIED`.

## Counts by severity

| Severity | Count |
|---|---|
| Blocker | 0 |
| High | 0 |
| Medium | 2 |
| Low | 4 |
| Nit | 5 |

## Open questions

1. With Option B in force, should `@RequestParam String` (and `@ModelAttribute`) on an `@AuthenticatedEndpoint` handler be banned too? The house-style argument that led to banning all path variables applies equally. Story owner's call.
2. Is recording the deviations in `09-technical.md` §6 deferred to Phase 9, or expected in this PR?
3. For T-009: the matcher is a plain `@Component` in `identity.infrastructure.web`; `@WebMvcTest` slices will not load it once a filter depends on it. Is that planned for?

## Resolution (2026-10-05)

All findings fixed in a follow-up commit; no production behaviour changed (the `src/main` diff is Javadoc only). The fixes are verified by the gate only; no second fresh-context review has been run.

| Finding | Resolution |
|---|---|
| M-1 | Marker rule now selects any concrete class with `@Controller` meta-present on the class, a superclass or an interface, and groups same-signature methods across the hierarchy. New negative fixtures: interface-declared mapping, inherited-from-base mapping, `@Controller` + `@ResponseBody`. `EndpointClassificationWebTest` adds a completeness sweep (exactly one marker per production handler via `AnnotatedElementUtils`) and defines "production" as any main-source class. |
| M-2 + open question 1 | Identifier rule (name kept) now fails on any `@PathVariable`, `@RequestParam` (any type, String included), `@ModelAttribute`, `@MatrixVariable`, any `UUID` parameter, and any unannotated parameter that is not a principal/request/response type. Story owner decided "ban String too". `@RequestBody` identifiers remain out of scope. |
| L-1 | Self-invocation rule also treats a target as guarded when a same-signature supertype/interface method carries `@RequiresPermission`; fixture added. |
| L-2 | Matcher Javadoc states both limits; the web test resolves each public (method, pattern) through all `HandlerMapping` beans in `DispatcherServlet` order and asserts the first handler is the same `@PublicEndpoint` method. |
| L-3 | `09-technical.md` §6 gains D-8 (identifier rule), D-9 (nested fixtures), D-10 (9 RBAC handlers, not 7). `03-design.md` and `04-tasks.md` untouched. |
| L-4 | Test also asserts POST login does not match when a mapping has no path-patterns condition. |
| Nits | `PublicEndpoint` Javadoc requires an explicit HTTP method; `ACCESS_MARKERS` moved above the rules; HEAD→GET, CORS preflight, plain `OPTIONS` and context-path cases pinned; public sweep also asserts not `ACCESS_DENIED`; `AuthenticatedEndpoint` Javadoc updated. `@DisplayName` was not used: ArchUnit's JUnit 5 engine ignores it on `@ArchTest` fields, so the rule's condition text and `because()` carry the wording. |

Gate after fixes (JDK 25, enforcer active, Docker up): `./mvnw verify` — 1301 unit tests (1 skipped), 353 ITs, 0 failures; 0 Checkstyle violations; SpotBugs 0; JaCoCo met.

Known limits left as is: the identifier rule selects only methods carrying `@AuthenticatedEndpoint` directly (a marker declared only on a supertype method is not checked); `GuardedTestController` (test sources) is component-scanned despite its Javadoc and has an unmarked `/internal-test/self-invoke` handler (never shipped; the scan check is narrowed to nested test classes rather than touching an unrelated file).
