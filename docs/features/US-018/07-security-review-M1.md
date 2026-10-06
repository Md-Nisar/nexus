# US-018 Milestone 1 security review (T-004, A8 deny-by-default)

**Verdict: APPROVED.** No Critical or High findings. 1 Medium, 4 Low and 3 Info, all gaps in build-time or test-time controls. The production delta is two marker annotations, ten marker placements and a matcher that nothing calls yet, so runtime behaviour is unchanged. Fix F-1 before M9 adds the C1/C3 handlers and before T-009 makes the matcher load-bearing. One pre-existing Medium outside the diff (P-1, login rate-limit bypass) needs its own ticket and does not count toward this verdict.

**Auth, crypto and PII were reviewed.** The diff touches authorization classification only (markers, build rules, public-endpoint matcher, drift test). It does not touch authentication (token validation, `JwtAuthenticationFilter`, `SecurityConfig`), cryptography or PII handling. The matcher reads only the HTTP method and path; its single log line (`PublicEndpointRequestMatcher.java:103`) is DEBUG and records only the exception's simple class name: no path, header, stack trace or PII.

## Scope, what was run, what was not

- **Scope:** `git diff origin/main...HEAD`, three commits (`09c4c03`, `973708a`, `e0b575c`), 14 files, +1828/−0. Checked against SECURITY.md §1 and §3.1, threat model §M1, T-E39/RC-40.2, T-E45/RC-44, RC-24/RC-24.1, design §3, `04-tasks.md` T-004 and the M1 merge checklist. `06-code-review-M1.md` was read to avoid repeating it; none of the findings below are in it.
- **Reviewer ran (JDK 25, offline):** `HexagonalArchitectureTest` 18, `AccessMarkerRuleFixturesTest` 22, `PublicEndpointRequestMatcherTest` 18, `EndpointClassificationWebTest` 81, 0 failures. No manifest delta (`git diff origin/main...HEAD --stat -- '*pom.xml' '*package*.json'` is empty); production code imports only `spring-webmvc`, already a dependency. Secret/PII grep over added lines: only synthetic test values; new docs refer to people by role only. Packaged jar contains 0 test, fixture or `GuardedTestController` classes (the jar predates `e0b575c`, whose `src/main` change is Javadoc only). Scratch probes lived only in the session scratchpad; `git status` was clean.
- **Dependency scans (run by the session):**
  - `npm audit --omit=dev --audit-level=high`: 7 findings (6 moderate, 1 high), all `@angular/*` packages. This diff has no manifest change and no frontend file, so none is attributable to M1; they are the pre-existing findings the story baseline records.
  - Backend OWASP `dependency-check`: **not run locally.** It is a CI-only gate for this project (the sandbox proxy also returns 403 for the NVD and CISA feeds). `pom.xml` has no delta in this diff, so the backend dependency set is identical to `origin/main`; that is an inference, and the CI run is the authoritative result.
- **Not run:** full `./mvnw verify` by the reviewer (the session ran it separately: 1301 unit, 353 IT, 0 failures, JDK 25).

## What was checked and holds

- **Markers cannot be bypassed through meta-annotation:** all three are `@Target(METHOD)`. A handler with a marker and a raw `@PreAuthorize` fails closed in Spring Security's unique-annotation check.
- **`@RequiresPermission` on an interface method is enforced** (probe: zero-permission caller gets 403 `RBAC_001`), so widening the marker rule to the type hierarchy matches runtime behaviour, apart from the final-method case in F-3.
- **Matcher fails closed and is safe for T-E45:** method and pattern matched together after `parseAndCache`; overlap with any non-public mapping returns false; a non-public mapping with no path-patterns condition poisons every request; a public mapping with no HTTP method is non-public; any `RuntimeException` returns false and the cached path attribute is restored. Probe: with an overlapping non-public `GET /api/v1/auth/{action}`, `GET /api/v1/auth/login` is false and `POST /api/v1/auth/login` is still true. `%6Cogin` is true, correctly, since MVC dispatches it to login.
- **`AUTH_003` fingerprint is sound:** the entry point writes no `instance` member; every `GlobalExceptionHandler` `ProblemDetail` gets `instance`; a handler-thrown `AccessDeniedException` becomes a 403 with `instance`, so an anonymous request that reaches a non-public handler cannot pass as the entry-point 401. The `traceId` in the entry-point JSON is restricted to `[A-Za-z0-9._-]{1,64}` by `CorrelationIdFilter` (pre-existing), so no JSON injection.
- **Flag coverage:** every main-source `@Controller` must be registered with all flags on; the completeness sweep uses `AnnotatedElementUtils`; the dispatch-order guard walks every `HandlerMapping` in `DispatcherServlet` order.
- **Test-only code:** fixtures are static nested classes outside the component scan (pinned by a test); `SamePathOtherMethodController` is registered only through `@Import`; nothing in `src/main` references test code.
- **Tenant isolation unchanged:** no query, repository, tenant predicate, cache key or `TenantIsolationArchitectureTest` / `UNSCOPED_ALLOWLIST` change.
- `@RestControllerAdvice` / `@ExceptionHandler` cannot be routed to; no Kotlin, WebSocket, `RouterFunction`, `HttpRequestHandler`, `registerMapping`, `ServletRegistrationBean` or `@Endpoint` exists in `src/main`. The handler mapping holds 19 production handlers: 9 public, 1 authenticated-only, 9 permission-guarded.

## Findings

### Medium

**F-1. Handlers that `RequestMappingHandlerMapping` does not serve, or that are not main-source classes, escape all three ArchUnit rules and both web sweeps (OWASP A01, A04).**
`HexagonalArchitectureTest.java:382`; `EndpointClassificationWebTest.java:174, 193, 215-216, 320, 407-408`.
M-1's fix covers annotated controllers only. Functional endpoints (`RouterFunction` beans), `HttpRequestHandler` / `mvc.Controller` beans (`BeanNameUrlHandlerMapping`), and any `@RestController` shipped in a dependency bypass every M1 control; springdoc and Boot's `BasicErrorController` are already silently excluded by `isProduction()`.
*Proof:* the marker rule passes a production-style `@Configuration` declaring a `RouterFunction` `GET /api/v1/tenants/{id}`; that route is absent from `requestMappingHandlerMapping`; anonymous callers get `AUTH_003` (sweep satisfied) while a zero-permission caller gets `200 router-reached <id>`.
*Risk:* the "nobody decided" case FR-A8.a exists to prevent: IDOR or cross-tenant read if the handler trusts the id, with a green build. Not exploitable today because none of these handler types exists.
*Fix (test-only):* (1) pin the set of `HandlerMapping` beans by type; assert `RouterFunctionMapping.getRouterFunction()` is null and `BeanNameUrlHandlerMapping.getHandlerMap()` is empty, and that a `SimpleUrlHandlerMapping` holds only `ResourceHttpRequestHandler`s; (2) replace the silent `isProduction()` exclusion with an explicit allowlist of non-production handler bean types (springdoc resources, `BasicErrorController`), each with a reason, in the style of `UNSCOPED_ALLOWLIST`, and fail on anything unlisted; (3) optionally add an ArchUnit `noClasses()` rule against `RouterFunction`, `HttpRequestHandler` and `org.springframework.web.servlet.mvc.Controller` in production code.

### Low

**F-2. The marker rule skips static handler methods and `@HttpExchange` mappings; a static `@RequiresPermission` handler is silently unguarded and passes every M1 control (A01).** `HexagonalArchitectureTest.java:393` (`filter(!STATIC)`), `:398` (only `@RequestMapping`-meta-annotated methods count), `:178-179` (public/non-final rule ignores `static`).
*Proof:* MVC registers `public static` handler methods. `@RequiresPermission("role:write") @GetMapping public static ...` gives a zero-permission caller `200 static-reached`; the marker rule and `requires_permission_methods_must_be_public_and_non_final` both pass. An unmarked static handler and an unmarked `@GetExchange` handler also pass the marker rule (the web completeness sweep would catch those two for a main-source class, but not the static `@RequiresPermission` case).
*Risk:* a silent permission bypass of the kind FR-A8.b and SECURITY.md §3.1 aim to prevent; static handlers have no injected collaborators, which lowers likelihood.
*Fix:* select static methods and flag any static method that carries a mapping; treat `@HttpExchange` (meta-annotated) as a mapping; add `.andShould().notHaveModifier(STATIC)` to the public/non-final rule; fixtures for each.

**F-3. `@RequiresPermission` declared on an interface or base-class method now counts as a marker, but a `final` override of it is unguarded and no rule follows the hierarchy (A01).** `HexagonalArchitectureTest.java:400-404` (`anyMatch` across the hierarchy), `:178-195` (checks only the directly annotated method).
*Proof:* an interface with `@RequiresPermission @GetMapping` and an implementation with `public final` passes all three rules; a zero-permission caller gets `200 final-reached`; Spring logs only a startup WARN ("Unable to proxy interface-implementing method ... marked as final").
*Risk:* silent bypass for a handler that uses only its parameters or static state (one touching injected fields would NPE on the CGLIB proxy). M1 made this placement count as "classified", while SECURITY.md §3.1 says to annotate the controller method directly.
*Fix:* either require `@RequiresPermission` on the concrete class's own handler method (direct-only resolution for this marker), or add a rule that a concrete method overriding a `@RequiresPermission` supertype method must be public, non-final, non-static, in a non-final class; add a fixture.

**F-4. The `@AuthenticatedEndpoint` identifier rule allows request-bound identifiers from headers, cookies and the raw servlet request (A01, IDOR).** `HexagonalArchitectureTest.java:256-262, 508-535`.
*Proof:* each of these passes: `get(@RequestHeader("X-User-Id") String userId)`, `get(@CookieValue("uid") String userId)`, `get(HttpServletRequest r) { r.getParameter("userId") }`.
*Risk:* the same IDOR the story owner closed for `String` `@RequestParam`; a handler with no permission check reads another user's data by attacker-chosen header value. The rule's own `because()` text says "no request-bound identifier of ANY type"; headers and cookies were never discussed.
*Fix:* add `RequestHeader` and `CookieValue` to `REQUEST_BOUND_IDENTIFIER_ANNOTATIONS`; narrow `FRAMEWORK_PARAMETER_TYPES` to `Principal` and `ServletResponse` (drop `ServletRequest`; `me()` uses neither); allowlist a header by name if one is ever needed; record in D-8.

**F-5. The non-public sweep sends one canonical URI per pattern, but `permitAll` matches on path only, so a non-public pattern that can match a `permitAll` literal is reachable anonymously while the sweep stays green (A01, A05).** `EndpointClassificationWebTest.java:396`; `SecurityConfig.java:77-85`.
*Proof:* `@AuthenticatedEndpoint @GetMapping("/api/v1/auth/{action}") seg(Authentication a)` passes the identifier rule (no parameter binds `{action}`); the sweep-style `GET /api/v1/auth/<uuid>` gets `401 AUTH_003`; anonymous `GET /api/v1/auth/login` and `/refresh` get `200 segment-reached auth=null`. Wildcards (`/api/v1/auth/*`, `/.well-known/*`) behave the same. `@RequiresPermission` handlers are unaffected (method security denies anonymous).
*Risk:* an anonymous request reaches an authenticated-only handler, falsifying design §3.1's "drift test catches both directions" and the ✅ on threat-model §M1 "S". Needs an unusual pattern, hence Low; root cause is the path-only `permitAll`, an approved deviation already flagged for T-009.
*Fix:* sweep each `permitAll` literal × every HTTP method through the ordered `HandlerMapping`s and assert the first handler is null or `@PublicEndpoint`; better, in T-009, build `permitAll` from `PublicEndpointRequestMatcher` (method + pattern).

### Info

- **I-1.** `GuardedTestController` (test sources) is component-scanned in every `@SpringBootTest` context, bringing an unmarked `/internal-test/self-invoke` and a `final` guarded handler (CGLIB warning in the probe). Its Javadoc (`GuardedTestController.java:11`, "never component-scanned") is wrong. Not packaged (verified in the jar); test hygiene only; already listed as a known limit in the M1 resolution.
- **I-2.** When the matcher fails closed it leaves only a DEBUG log. After T-009 wires it in, a systematic false negative (T-D17: refresh blocked by the epoch check) would be invisible. Add a counter such as `nexus.security.public_match_failed_closed`, no path tag.
- **I-3.** Design §3.4 says "negative fixture in a test-only package"; fixtures are nested classes (D-9), the safer choice given I-1.

## Pre-existing, outside the diff (ticket separately; not counted)

**P-1 (Medium). `LoginRateLimitFilter` matches paths by raw `getRequestURI()` string equality, so percent-encoding an unreserved character bypasses all four auth rate limits (A07, A04).** `LoginRateLimitFilter.java:98-104, 113`.
*Proof* (`ProbeWebTest.rateLimitEncodedPath`, IP limit 3): `POST /api/v1/auth/login` returns 401, 401, 401, then 429, 429; `POST /api/v1/auth/%6Cogin` and `/logi%6E` then return `401 AUTH_001` with no IP or per-account bucket consumed; MVC and `permitAll` both resolve them to login.
*Risk:* unthrottled credential stuffing or password spraying across accounts (per-account lockout still bounds attempts per account); forgot, reset and refresh are bypassable the same way. *Mitigating factor:* `nexus-frontend/nginx.conf:35-37` normalises the path via `proxy_pass` with a URI part and applies its own `limit_req`; traffic reaching the backend directly (cluster-internal, another ingress) is exposed.
*Fix:* match with the same parsed path MVC uses (`ServletRequestPathUtils` / `PathPattern`) or reuse `PublicEndpointRequestMatcher`-style method + pattern matching (RC-24.1's "no filter keeps its own literal list" applies); add a regression test with an encoded path.

**P-2 (Low).** `management.endpoints.web.exposure.include: health,info,metrics,prometheus` (`application.yml:83`, not overridden in prod) exposes `/actuator/metrics` and `/actuator/prometheus` to any authenticated user of any tenant with zero permissions. Actuator is outside A8's classification and the M1 sweeps. Consider a separate management port/network or a required permission.

## Threat-model cross-check

| Threat / RC claimed by M1 | Mitigation visible in diff? | Evidence |
|---|---|---|
| T-E39 / RC-40.2: every flag on in the drift test | Yes | `@ActiveProfiles("test")` plus `should_register_every_production_rest_controller_when_all_flags_enabled` |
| T-E39 / RC-40.2: assert the entry-point 401, not just the status | Yes | `isEntryPointUnauthorized` (`AUTH_003`, no `instance`); public sweep also checks not `ACCESS_DENIED` |
| T-E39 / RC-40.2: mechanical "own data only" rule | Yes, stricter than designed; gap F-4 | `authenticated_endpoints_take_no_uuid_identifier` plus 9 fixtures |
| §M1 T: no handler ships unclassified | Partial: F-1, F-2 | Marker rule and web completeness sweep cover annotated MVC handlers only |
| §M1 S: `permitAll` drift caught in both directions | Partial: F-5 | Literal paths caught; templated or wildcard overlap not |
| T-E45 / RC-44.1: method + pattern, `parseAndCache`, false on exception or ambiguity | Yes | `PublicEndpointRequestMatcher.matches` / `mayMatch` / `isPublic`; probes and unit tests |
| T-E45 / RC-44.3: equivalence sweep and same-path other-method fixture | Yes | `should_match_exactly_when_handler_is_public_endpoint`, `SamePathOtherMethodController` |
| T-E45 / RC-44.2, RC-44.4: empty permissions on public requests, `TokenFreshnessIT` cases | Not in M1, correctly not claimed | T-009 |
| RC-24.1: one source of "public" | Partial, by design | Matcher exists and the web test uses it; no filter consumes it until T-009; `SecurityConfig` `permitAll` is still a literal list (tied only by the drift test) and `LoginRateLimitFilter` keeps its own literal list (P-1) |
| M1 merge checklist: `GuardedTestController` unaffected | Yes for ArchUnit (`DoNotIncludeTests`) | Still scanned into test contexts (I-1) |

## Counts by severity (in-diff)

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 0 |
| Medium | 1 (F-1) |
| Low | 4 (F-2 to F-5) |
| Info | 3 |

Pre-existing, outside the diff and not counted: 1 Medium (P-1), 1 Low (P-2).

## Remaining risks and items for T-009 and later milestones

- **T-009 wiring:** consume the matcher only as "skip the epoch check if true", never the reverse (its fail-closed property is directional); keep `JwtAuthenticationFilter` on `OncePerRequestFilter`'s default of skipping ERROR dispatches; add the failed-closed counter (I-2); resolve `@WebMvcTest` slices not loading the `@Component` matcher.
- **T-009 or sooner:** replace the path-only `permitAll` with a `RequestMatcher` backed by the matcher (closes F-5 and the `SamePathOtherMethod` anonymous reach noted in the test's own Javadoc).
- **Construction-time snapshot:** the matcher sees only `requestMappingHandlerMapping`'s contents at build time; any future `registerMapping` call, or any bean whose type cannot be resolved without instantiation, needs security review.
- **Public patterns:** nothing stops a broad `@PublicEndpoint` pattern (`/**`, `{*rest}`), the third T-E45 vector; consider a rule that `@PublicEndpoint` patterns are literal.
- **Remaining gaps by design:** identifiers inside `@RequestBody` on `@AuthenticatedEndpoint` (accepted in D-8) and `@AuthenticatedEndpoint` declared only on a supertype not being checked for the implementation's parameters (accepted known limit); both stay review-only.
- **Before M9:** land F-1, and ideally F-2 and F-3, so the C1/C3 handlers are added under complete controls.

## Resolution (2026-10-05)

F-1 to F-5 fixed in a follow-up commit; test code, Javadoc and `09-technical.md` only (D-8 updated, D-11 to D-14 added). Verified by the gate only; no second fresh-context security review has been run.

| Finding | Resolution |
|---|---|
| F-1 | New ArchUnit rule `no_handlers_outside_annotated_controllers` (empty allowlist) forbids production use of `RouterFunction`, `HttpRequestHandler` and `mvc.Controller`. The web test pins the `HandlerMapping` bean types and what each holds; the silent `isProduction()` exclusion is replaced by `NON_PRODUCTION_HANDLER_ALLOWLIST` (each entry with a reason), and an unlisted handler type fails every sweep. |
| F-2 | Static mapped methods are selected and always flagged; `@HttpExchange` counts as a mapping; the public/non-final rule also requires non-static. |
| F-3 | New rule `requires_permission_overrides_must_be_proxyable`: a concrete override of a `@RequiresPermission` supertype or interface method must be public, non-final, non-static, in a non-final class. |
| F-4 | `@RequestHeader` and `@CookieValue` banned on `@AuthenticatedEndpoint`; allowed framework parameter types narrowed to `Principal` and `ServletResponse` (`ServletRequest` dropped). |
| F-5 | New sweep over each `permitAll` entry × 7 HTTP methods through the ordered `HandlerMapping`s; the first handler must be absent, `@PublicEndpoint` or allowlisted. The `permitAll` list is a labelled test mirror (`PERMIT_ALL_PATTERNS`) with a two-way drift guard against the chain's own `AuthorizationManager`; a nested probe with `@AuthenticatedEndpoint @GetMapping("/api/v1/auth/{action}")` proves the sweep fires. The root cause (path-only `permitAll`) stays for T-009. |

Left open on purpose: I-1 (`GuardedTestController` Javadoc, unrelated file), I-2 (fail-closed counter, T-009), P-1 and P-2 (pre-existing, separate tickets).

Gate after fixes (JDK 25, enforcer active, Docker up): `./mvnw verify` — 1402 unit tests (1 skipped), 353 ITs, 0 failures; 0 Checkstyle violations; SpotBugs 0; JaCoCo met.
