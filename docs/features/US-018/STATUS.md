# US-018 — Progress and handoff

**Updated:** 2026-10-05 · **Source of truth for scope:** `04-tasks.md` (Gate 3 approved). This file only tracks where we are.

## Milestone status

| Milestone | Tasks | State |
|---|---|---|
| **M2** A1–A4 grant-subset core | T-001..T-003 | **Merged to `main`** as PR #81 (squash, `9820d4e`, 2026-10-04). Owner-side deploy items still open, see below. |
| **M1** A8 deny-by-default | T-004 | **Code complete on the working branch; PR not yet opened.** Review, security review and test-validate done (below). |
| M3 | T-016..T-019 | **Blocked.** Needs M2 soaked in staging ≥ 1 sprint (M2 merged one day ago), and M4 and M7 merged. Neither is. |
| M4, M5, M6, M7, M7b, M8, M9, M9-contract | see `04-tasks.md` | Not started. M6 (T-005) has no dependencies; M4 (T-006) is unblocked now that M2 is merged. |

Next in delivery order after M1: M6 (T-005), then M4 (T-006).

## M1 exit sequence

| Step | State |
|---|---|
| Implement T-004 | Done (markers, matcher, three ArchUnit rules plus follow-ups, `EndpointClassificationWebTest`) |
| `/review` (`06-code-review-M1.md`) | Done. CHANGES REQUESTED, then M-1, M-2, L-1..L-4 and the nits fixed. No second review of the fixes was run. |
| `/security-review` (`07-security-review-M1.md`) | Done, APPROVED. F-1..F-5 fixed afterwards. No second security review of the fixes was run. P-1 and P-2 (pre-existing, outside the diff) not fixed, see open items. |
| `/test-validate` (`08-test-audit-M1.md`) | Done, PASS: 1423 unit (1 skipped), 353 IT, 0 failures, JDK 25; frontend 210/210. |
| `/docs` | Not run. M1's merge checklist does not gate on runbook or alert content. Deviations D-8..D-14 are recorded in `09-technical.md` §6. |
| `/pre-pr-check` | Run 2026-10-05: all executable gates and artifact records PASS; **one Definition of Done item open** (SECURITY.md does not document the three handler markers). Not ready to open the PR until it is closed. |
| Open PR | **Pending** (only on request). |

M1 was developed on the session branch `ccr-76994a18-now72v`, not on `feature/US-018/M1`.

## M1 facts a new session needs

- Build-time and test-time controls only; the production delta is two marker annotations, ten marker placements and `PublicEndpointRequestMatcher`, which nothing calls yet (T-009 wires it). No DB, API, UI or flag change.
- The identifier rule on `@AuthenticatedEndpoint` bans more than the design's UUID-only text, as decided by the story owner: any `@PathVariable`, `@RequestParam` (String included), `@ModelAttribute`, `@MatrixVariable`, `@RequestHeader`, `@CookieValue`, any `UUID` parameter, `ServletRequest`, and unannotated implicitly-bound parameters. `@RequestBody` identifiers stay out of scope (D-8).
- Negative fixtures are static nested classes of test classes, not an `architecture/fixtures` package (D-9). The design says 7 RBAC handlers; there are 9 (D-10). Later rule changes are D-11..D-14.
- Known limits, accepted: the identifier rule checks only methods that carry `@AuthenticatedEndpoint` directly; `GuardedTestController` (test sources) is component-scanned despite its Javadoc and has an unmarked `/internal-test/self-invoke` handler (never shipped); the matcher sees only `requestMappingHandlerMapping` as of construction.
- Local environment: backend gates need JDK 25 (`/usr/lib/jvm/java-25-openjdk-amd64`, installed via apt in this container, not persistent) and a running Docker daemon for the ITs. OWASP dependency-check is a CI-only gate. `mvnw` has no execute bit in git; run `sh ./mvnw`.

## Open items

Before or at the M1 PR:
- **Close the open Definition of Done item:** SECURITY.md §3.1 documents only `@RequiresPermission`. Add a short subsection (and a line in `docs/coding-standards.md` if it lists handler conventions) saying every REST handler must carry exactly one of `@RequiresPermission`, `@PublicEndpoint` or `@AuthenticatedEndpoint`, that `@AuthenticatedEndpoint` handlers take no request-bound identifier, and that the build enforces both. No ADR is planned for A8 in the design; the D-8..D-14 deviations are in `09-technical.md`. Then re-run `/pre-pr-check`.
- PR title as a Conventional Commit, e.g. `feat(security): classify every REST handler as public, authenticated or permission-guarded (US-018 M1)`; description covers what, why and how to test.
- Decide whether the PR body must say that F-5's root cause (path-only `permitAll`) is deferred to T-009.

Ticket separately (pre-existing, outside the M1 diff, found by the security review):
- **P-1 (Medium):** `LoginRateLimitFilter` matches paths by raw string, so `/api/v1/auth/%6Cogin` bypasses all four auth rate limits. Frontend nginx normalises the path, but direct backend traffic is exposed.
- **P-2 (Low):** `/actuator/metrics` and `/actuator/prometheus` are reachable by any authenticated user with zero permissions.

For T-009 (from the M1 reviews): build `permitAll` from `PublicEndpointRequestMatcher` (method + pattern); use the matcher only as "skip the epoch check if true"; add a fail-closed counter (e.g. `nexus.security.public_match_failed_closed`, no path tag); make `@WebMvcTest` slices load the matcher; consider a rule that `@PublicEndpoint` patterns are literal.

M2 owner-side items, unverified from the code (the PR is merged; none of these can be confirmed here). Full list in `04-tasks.md` M2 merge checklist:
- RES-6 log-retention sign-off, A1 detection query per environment, custom-admin exposure check, permset cache flush after V6, V6 version number confirmed, staging soak started (it gates M3).
- Ops: confirm `application-prod.yml` / env vars do not override the parent flags `feature.nexus-us012-rbac-role-assignment.enabled` and `feature.nexus-us015-rbac-role-management.enabled`.
- EPIC-002 must report RES-1(b) as **"self path closed; transformed into RES-26"** (T-E32), never "fully closed".
- Move ADR-0021 from Proposed to Accepted (still **Proposed** on `main`).
- Tidy `DenialReason.NOT_TENANT_ADMIN` when B8 lands in M8 (throttled actors get it today; pre-existing).
- The earlier question whether the Claude settings trim commit belonged in the M2 PR is moot: the squash merge removed that commit hash, so it cannot be checked from here.

## Facts a new session needs (M2)

- Behaviour change: service-level callers must now hold the permission in the DB, not only in the JWT. Affects M7 load/seed fixtures; the break-glass CLI (M5) is not built yet.
- Order of checks in `assign()`: tenant checks → throttle → legacy gate → M13 → A4 → A2 → duplicate 409 → insert. `revoke()` runs the grant-subset check before the last-admin 409.
- One denial metric (`nexus.rbac.permission_denied{permission,reason}`) emitted centrally in `GlobalExceptionHandler`; one `ROLE_ASSIGNMENT_DENIED` audit row per denied request.
- Recorded design deviations D-1..D-3 (M14 signature, M15 host class, adapter constructor) are in `09-technical.md`.
- Unverified claims in the docs: Redis key prefix at runtime, Flyway behaviour on code revert, the SQL snippets, and M5/M7 statements (design only).
- The revoke 403 `@ApiResponse` text in `UserRoleController` does not yet mention the subset denial.
- `02-impact.md:450` and `04-tasks.md:150` still carry stale permission counts (8→9, 7→8 ordering) fixed in `03-design.md`.
- `04-tasks.md` M2 status line still says the PR and merge items are open; the merge itself is done (this file is the current record).

## Branch convention

Milestone branches are `feature/US-018/M<n>`. M1 was developed on the session-mandated branch `ccr-76994a18-now72v` instead; rename or retarget when opening its PR.
