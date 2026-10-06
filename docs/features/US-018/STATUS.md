# US-018 — Progress and handoff

**Updated:** 2026-10-06 · **Source of truth for scope:** `04-tasks.md` (Gate 3 approved). This file only tracks where we are.

**Decision 2026-10-05 — no staging, no deployment.** The app is not deployed and no environment exists; work starts without one. The same decision is recorded at the top of `04-tasks.md`. In short: M3's staging-soak gate is waived for starting M3 and its soak moves to the first staging deployment; rollout-order waits become "merged earlier"; environment-dependent checklist items are deferred to the first deployment and stay required before production (see "Deferred to the first deployment" below).

## Milestone status

| Milestone | Tasks | State |
|---|---|---|
| **M2** A1–A4 grant-subset core | T-001..T-003 | **Merged to `main`** as PR #81 (squash, `9820d4e`, 2026-10-04). Its deploy-side items are deferred to the first deployment, see below. |
| **M1** A8 deny-by-default | T-004 | **Merged to `main`** as PR #82 (squash, `0da1597`, 2026-10-06). Review, security review and test-validate done (below). |
| M3 | T-016..T-019 | **Blocked on M4 (T-006) and M7 (T-009..T-014) merging.** The staging-soak gate is waived (no environment); M3 still needs its own threat-model re-pass before merge. |
| M4, M5, M6, M7, M7b, M8, M9, M9-contract | see `04-tasks.md` | Not started. M6 (T-005) has no dependencies; M4 (T-006) is unblocked now that M2 is merged. M1 and M6 are the remaining M7 prerequisites. M5 needs M4; M7 needs M1 (done) and M6 *merged* (no longer "deployed"); M7b follows M7 with no wait; M9-contract follows M9 with no wait. |

Next in delivery order now that M1 and M2 are merged: M6 (T-005) and M4 (T-006) — both unblocked, neither depends on the other.

## M1 exit sequence

| Step | State |
|---|---|
| Implement T-004 | Done (markers, matcher, three ArchUnit rules plus follow-ups, `EndpointClassificationWebTest`) |
| `/review` (`06-code-review-M1.md`) | Done. CHANGES REQUESTED, then M-1, M-2, L-1..L-4 and the nits fixed. No second review of the fixes was run. |
| `/security-review` (`07-security-review-M1.md`) | Done, APPROVED. F-1..F-5 fixed afterwards. No second security review of the fixes was run. P-1 and P-2 (pre-existing, outside the diff) not fixed, see open items. |
| `/test-validate` (`08-test-audit-M1.md`) | Done, PASS: 1423 unit (1 skipped), 353 IT, 0 failures, JDK 25; frontend 210/210. |
| `/docs` | Not run. M1's merge checklist does not gate on runbook or alert content. Deviations D-8..D-14 are recorded in `09-technical.md` §6. |
| `/pre-pr-check` | Re-run 2026-10-05: **PASS**. `./mvnw verify` on JDK 25 with Docker up (1423 unit, 353 IT, 0 failures; Checkstyle, SpotBugs, JaCoCo green), artifact records present, diff hygiene clean, Definition of Done walked. The one open item (handler markers undocumented) is closed by `SECURITY.md` §3.2. Frontend gates not applicable (no frontend change). |
| Open PR | **Merged** as PR #82 (squash, `0da1597`, 2026-10-06). |

M1 was developed on the session branch `ccr-76994a18-now72v`, not on `feature/US-018/M1`, and merged to `main` from there.

## M1 facts a new session needs

- Build-time and test-time controls only; the production delta is two marker annotations, ten marker placements and `PublicEndpointRequestMatcher`, which nothing calls yet (T-009 wires it). No DB, API, UI or flag change.
- The identifier rule on `@AuthenticatedEndpoint` bans more than the design's UUID-only text, as decided by the story owner: any `@PathVariable`, `@RequestParam` (String included), `@ModelAttribute`, `@MatrixVariable`, `@RequestHeader`, `@CookieValue`, any `UUID` parameter, `ServletRequest`, and unannotated implicitly-bound parameters. `@RequestBody` identifiers stay out of scope (D-8).
- Negative fixtures are static nested classes of test classes, not an `architecture/fixtures` package (D-9). The design says 7 RBAC handlers; there are 9 (D-10). Later rule changes are D-11..D-14.
- Known limits, accepted: the identifier rule checks only methods that carry `@AuthenticatedEndpoint` directly; `GuardedTestController` (test sources) is component-scanned despite its Javadoc and has an unmarked `/internal-test/self-invoke` handler (never shipped); the matcher sees only `requestMappingHandlerMapping` as of construction.
- Local environment: backend gates need JDK 25 (`/usr/lib/jvm/java-25-openjdk-amd64`, installed via apt in this container, not persistent) and a running Docker daemon for the ITs. OWASP dependency-check is a CI-only gate. `mvnw` has no execute bit in git; run `sh ./mvnw`.

## Open items

M1 PR (#82) merged with the suggested Conventional Commit title verbatim. Whether its body covers F-5's deferral to T-009 was not independently re-verified here (GitHub API access was unavailable at update time).

Ticket separately (pre-existing, outside the M1 diff, found by the security review):
- **P-1 (Medium):** `LoginRateLimitFilter` matches paths by raw string, so `/api/v1/auth/%6Cogin` bypasses all four auth rate limits. Frontend nginx normalises the path, but direct backend traffic is exposed.
- **P-2 (Low):** `/actuator/metrics` and `/actuator/prometheus` are reachable by any authenticated user with zero permissions.

For T-009 (from the M1 reviews): build `permitAll` from `PublicEndpointRequestMatcher` (method + pattern); use the matcher only as "skip the epoch check if true"; add a fail-closed counter (e.g. `nexus.security.public_match_failed_closed`, no path tag); make `@WebMvcTest` slices load the matcher; consider a rule that `@PublicEndpoint` patterns are literal.

Still open, not tied to a deployment:
- EPIC-002 must report RES-1(b) as **"self path closed; transformed into RES-26"** (T-E32), never "fully closed".
- Move ADR-0021 from Proposed to Accepted (still **Proposed** on `main`).
- Tidy `DenialReason.NOT_TENANT_ADMIN` when B8 lands in M8 (throttled actors get it today; pre-existing).
- The earlier question whether the Claude settings trim commit belonged in the M2 PR is moot: the squash merge removed that commit hash, so it cannot be checked from here.

## Deferred to the first deployment

No environment exists, so none of these can run now. They stay **required before any production traffic** and need an owner when the first environment is created. Full lists are in the `04-tasks.md` merge checklists.

- **M2:** RES-6 log-retention sign-off; the A1 detection query per environment where the US-012 flag was ever `true`; the custom-admin exposure check (before and after deploy); permset cache flush (`SCAN`/`DEL nexus:rbac:permset:*`) after V6 applies; V6 version number confirmed at deploy; Ops confirms `application-prod.yml` / env vars do not override `feature.nexus-us012-rbac-role-assignment.enabled` and `feature.nexus-us015-rbac-role-management.enabled`.
- **The M3 soak (moved here):** M2, M1, M4 and M7 run in the first staging environment for at least one sprint with no `RbacAdministrators` anomalies, and the zero-admin sweep under the new definition is done, before production traffic.
- **M5:** Kubernetes API audit logging sign-off (RC-37.3), the staging drill that recovers a zero-admin tenant and receives the page (RC-37.4), the daily reconciliation alert, RES-6 retention for `RBAC_BREAK_GLASS_USED`.
- **M7:** Ops confirms production activates the `prod` profile (A-3); SRE and PM confirmation of the A9 availability consequence (RES-30).
- **M8 / M9:** V8 pre-flight and maintenance windows for V8 and V9; Ops items listed on their checklists.

Decide before the PR that needs them (the story owner, not silently waived):
- **T-009 (M7):** the merge-blocking k6 hot-path run (≤ 2 ms p95 at 200 RPS) names "the staging topology". Run it on a local Docker topology, or defer it to the first deployment.
- **T-023 (M8):** the B6 benchmark must run on the staging topology (shared CI runner numbers are meaningless); defer, or run on a local topology.

## Facts a new session needs (M2)

- Behaviour change: service-level callers must now hold the permission in the DB, not only in the JWT. Affects M7 load/seed fixtures; the break-glass CLI (M5) is not built yet.
- Order of checks in `assign()`: tenant checks → throttle → legacy gate → M13 → A4 → A2 → duplicate 409 → insert. `revoke()` runs the grant-subset check before the last-admin 409.
- One denial metric (`nexus.rbac.permission_denied{permission,reason}`) emitted centrally in `GlobalExceptionHandler`; one `ROLE_ASSIGNMENT_DENIED` audit row per denied request.
- Recorded design deviations D-1..D-3 (M14 signature, M15 host class, adapter constructor) are in `09-technical.md`.
- Unverified claims in the docs: Redis key prefix at runtime, Flyway behaviour on code revert, the SQL snippets, and M5/M7 statements (design only).
- The revoke 403 `@ApiResponse` text in `UserRoleController` does not yet mention the subset denial.
- `02-impact.md:450` and `04-tasks.md:150` still carry stale permission counts (8→9, 7→8 ordering) fixed in `03-design.md`.

## Branch convention

Milestone branches are `feature/US-018/M<n>`. M1 was developed on the session-mandated branch `ccr-76994a18-now72v` instead; rename or retarget when opening its PR.
