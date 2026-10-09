# US-018 — Progress and handoff

**Updated:** 2026-10-08 · **Source of truth for scope:** `04-tasks.md` (Gate 3 approved). This file only tracks where we are.

**Decision 2026-10-05 — no staging, no deployment.** The app is not deployed and no environment exists; work starts without one. The same decision is recorded at the top of `04-tasks.md`. In short: M3's staging-soak gate is waived for starting M3 and its soak moves to the first staging deployment; rollout-order waits become "merged earlier"; environment-dependent checklist items are deferred to the first deployment and stay required before production (see "Deferred to the first deployment" below).

## Milestone status

| Milestone | Tasks | State |
|---|---|---|
| **M2** A1–A4 grant-subset core | T-001..T-003 | **Merged to `main`** as PR #81 (squash, `9820d4e`, 2026-10-04). Its deploy-side items are deferred to the first deployment, see below. |
| **M1** A8 deny-by-default | T-004 | **Merged to `main`** as PR #82 (squash, `0da1597`, 2026-10-06). Review, security review and test-validate done (below). |
| **M6** A11 token claim validation | T-005 | **Merged to `main`** as PR #84 (`b11dbde`, 2026-10-07). Code review (APPROVE WITH NITS), security review (APPROVED, 2 Low) and test audit are in `06/07/08-*-M6.md`. The OWASP dependency-check could not run locally (NVD 403) and was left to CI. |
| **M4** A6 atomic RBAC audit | T-006 | **Merged to `main`** as `25ceeed` (2026-10-06 commit; its title carries no PR number). No `*-M4.md` review, security or test-audit file exists in this folder, so whether those phases ran is not recorded here. |
| M3 | T-016..T-019 | **Blocked on M7 (T-009..T-014) merging.** M4 is merged. The staging-soak gate is waived (no environment); M3 still needs its own threat-model re-pass before merge. |
| M7 | T-009..T-014 | **T-009, T-010, T-011, T-012, T-013 and T-014 implemented** on `ccr-4e9e7cbe-4vl9v6`; T-009's code review findings fixed (`06-code-review-M7.md`, Resolution); **not merged**. **M7 merges as ONE PR containing T-009..T-014; T-009 must not merge or be released alone.** |
| M5, M7b, M8, M9, M9-contract | see `04-tasks.md` | Not started. M5 (T-007, T-008) is unblocked (it needed M4). M7b follows M7 with no wait; M9-contract follows M9 with no wait. |

**M7 / T-009 (A9 core): implemented on `ccr-4e9e7cbe-4vl9v6`, code review findings fixed, not merged.** Backend `verify` passes with and without ITs after the review fixes (1521 unit, 376 IT, 0 failures; the k6 figures below are from before the fixes). Local-Docker k6 hot-path run (200 RPS, 5 min, one JVM at `-Xmx1g`, MySQL and Redis in Docker; **not the staging topology**): server-side `nexus.rbac.epoch.check.latency` p95 0.58 ms (≤ 2 ms), `GET /api/v1/roles` p95 4.99 ms against a 4.25 ms baseline on `25ceeed` (+0.74 ms, budget < 5 ms), 0 dropped iterations, 0 `skipped_error`. Local Redis round-trips are about 0.1 ms, so this is optimistic: the staging re-run stays under "Deferred to the first deployment". T-009 must not merge or ship without T-011: M7 merges as one PR containing T-009..T-014, because an outage fails open on every request until the T-011 state machine exists. `/review` ran (`06-code-review-M7.md`, all findings fixed, re-review pending); `/security-review` and `/test-validate` for M7 have not run.

**M7 / T-014 (Redis auth at startup): implemented on `ccr-4e9e7cbe-4vl9v6`, not merged.** `nexus.rbac.redis.require-auth` (default `false`) fails startup when the main or either dedicated epoch factory has no effective password; the `prod` override line `nexus.rbac.redis.require-auth: true` in `application-prod.yml` must be added by hand (the hook blocks agent edits), and until then `RedisAuthStartupAssertionTest.should_resolveRequireAuthTrue_when_prodProfileActive` stays `@Disabled` (it is skipped, not red, so nothing enforces the line yet). The explicit merge-checklist item for both the line and removing `@Disabled` is in `04-tasks.md` (H-3 of `09-code-review-M7-part2.md`).

**M7 / T-010 (A10 holder fan-out, epoch-keyed cache): implemented on `ccr-4e9e7cbe-4vl9v6`, not merged.** After a detach commits, `RoleManagementService` reads the role's active holders in a new read-only transaction and calls `PermissionFreshnessService.invalidateHolders`, which bumps them in sequential batches of 500 (no cap; the first failed batch stops the fan-out and one `RBAC_EPOCH_BUMP_FAILED` counts that batch and the unsent ones, which T-012 enqueues for replay), counts `nexus.rbac.epoch.fanout{holders}` and WARNs `RBAC_EPOCH_FANOUT_LARGE` above 1000. The batches are sequential, not pipelined as design §9.4 says, so a down Redis costs one bump timeout (§9.3). After an attach commits, every holder's cache entry is evicted with no bump. The permission cache is keyed `{keyPrefix}:rbac:{permset|roleset}:{tenantId}:{userId}:{epoch}` and the bump script also deletes the entry under the replaced epoch. Scope is detach only (A-17); user deactivation is open item O-6; out-of-band permission removal is `runbook.md` §8. Old cache keys without an epoch expire within 900 s; no flush is needed.

**M7 / T-011 (A9 outage policy): implemented on `ccr-4e9e7cbe-4vl9v6`, not merged.** `PermissionFreshnessService` now holds the per-instance state machine of design §9.5 (Healthy, DegradedOpen, DegradedClosed, Recovering) behind one lock, on an injected `Clock`: 3 epoch-read or probe failures within a 10 s sliding window enter DegradedOpen with `t0` at the first; `fail-open-window` (15 min) after `t0` it is DegradedClosed; a probe success moves to Recovering once the replay queue is empty (T-012); `recovery-sustain` (60 s) without a counted failure returns to Healthy and clears `t0`; a relapse uses the same rule and keeps `t0`. A read answered "unavailable" because the adapter is not warmed up is a read failure; bump failures never count. Verdicts gain `SKIPPED_DEGRADED` and `UNAVAILABLE`; the filter answers 503 `AUTH_005` with `Retry-After: 30` (RFC 9457 body written in the filter, since `GlobalExceptionHandler` does not see filter output) and never on a `@PublicEndpoint` request. `PermissionEpochPort` gained `probe()` (a `PING` on the 50 ms read template, false until warmed). The 1 s `@Scheduled` probe is enabled by `rbac.infrastructure.cache.EpochSchedulingConfig`, unconditional (`EpochSchedulingIndependenceTest` runs it with the retry buffer off). Config under `nexus.rbac.epoch.*`: `fail-open-window`, `entry-failure-threshold`, `entry-failure-window`, `recovery-sustain`; `application-prod.yml` is untouched. Signals: gauge `nexus.rbac.epoch.degraded{state=open|closed|recovering}`, counters `degraded_entries`, `degraded_flap` and `last_seen_dropped`; WARN `RBAC_EPOCH_DEGRADED_ENTER` and `_FLAP`, INFO `RBAC_EPOCH_DEGRADED_RECOVERING` and `_EXIT` (`instance` from `HOSTNAME`, `cause`), no user ids. **Security review M-1 is resolved here** by a bounded per-instance last-seen-epoch map (decision A-18 in `04-tasks.md`); its residual (a bump this instance never saw) and parts (b) and (c) of the review remain for the M7 docs pass and k6 gate. Not done in T-011: the frontend does not yet special-case 503 `AUTH_005`; `docs/` error-code catalogues were not extended because none lists `AUTH_*` codes. `/review`, `/security-review` and `/test-validate` have not run on T-011.

**M7 / T-012 (A9 lost-bump replay): implemented on `ccr-4e9e7cbe-4vl9v6`, not merged.** A bump that Redis refuses (`invalidateUser`, or a fan-out batch plus every batch not yet sent) is queued in the package-private `EpochReplayQueue`: bounded by `nexus.rbac.epoch.replay-capacity-users` (default 100000, env `NEXUS_RBAC_EPOCH_REPLAY_CAPACITY_USERS`), coalesced per `(tenantId, userId)` keeping the oldest `failedAt`, overflow drops the newest and counts `bump_failed{reason="overflow"}` per dropped id. T-011's 1 s task drains it on every tick in every state, Healthy included (in a degraded state only after that tick's probe succeeded), in batches of 500 on the bump template; a failed batch goes back with its original `failedAt`, entries older than `key-ttl-seconds` are dropped, and a successful replay updates the last-seen map like a normal bump. "Replay queue empty" is now T-011's drain-complete predicate. Replay and bump failures never count towards the 3-in-10 s window and never restart the 60 s sustain (RC-53, L-4; stated in design §9.5). Signals: `nexus.rbac.epoch.bump_failed{operation,reason}`, `bump_replayed` (users), gauge `replay_queue_users`; ERROR `RBAC_EPOCH_BUMP_FAILED`, INFO `RBAC_EPOCH_BUMP_REPLAYED {tenantId,userCount,ageMs}`, no user ids. Decisions in A-19 (`04-tasks.md`). `application-prod.yml` is untouched. `/review`, `/security-review` and `/test-validate` have not run on T-012. Residual: while Healthy with a write-only Redis failure the drain fails and logs an ERROR once a second until Redis accepts writes.

**M7 / T-013 (refresh limits): implemented on `ccr-4e9e7cbe-4vl9v6`, not merged.** `RefreshTokenUseCase` now owns two buckets through `RateLimitStore.tryConsume` (store unchanged): `REFRESH_FAMILY:{sha256(familyId)}` 30/60 s, consumed after the reuse branch and before expiry and rotation (429 `RATE_001` with `Retry-After`; unknown and non-hex tokens never reach it), and `REFRESH_IP_FAIL:{ip}` 30/60 s, consumed only on failure outcomes before the `TOKEN_REFRESH_FAILURE` write (a rejection is 429, no audit row, counter `nexus.auth.refresh_failure_throttled`, one WARN `AUTH_REFRESH_FAILURE_THROTTLED suppressedCount` per window, no IP). A valid token is never gated by the failure bucket. `LoginRateLimitFilter` keeps only the `REFRESH_IP` total, raised to 300 (`refresh-ip-max-attempts`, renamed from `refresh-max-attempts`). Reuse first (RC-51): a revoked token always runs `revokeFamily` before any bucket; the count of unrevoked rows revoked travels as an `int` through repository, `RefreshTokenPort`, `JpaRefreshTokenAdapter` and `SecureEventService` (REQUIRES_NEW); count of 1 or more writes `TOKEN_REFRESH_REUSE` and returns the 401 `AUTH_004`, count 0 is an ordinary failure; the count is never returned, logged or stored. New `RefreshThrottledException` (`common.domain`) lets `GlobalExceptionHandler` log the 429 at DEBUG so the use case's single WARN per window holds. Details and one spec ambiguity (the successor token after a family revocation gets 401 when the bucket permits, 429 when still exhausted, never 200) are in decision A-20. New: `RefreshFailureThrottleIT` (Redis and MySQL), and the k6 gate `nexus-test/performance-test/tests/load/detach-refresh-storm.js` with its scenario and README section. **The k6 gate has not been run**: it needs the dev stack, MailHog and a raised login IP limit, and it must be run once per deployment shape (direct, behind the proxy) before M7 merges; it was syntax-checked (`node --check`, `k6 inspect`, Prettier). Merge checklist item "NAT refresh gate" therefore stays open. L-1 wording ("unrevoked") done in design §0 #19 and §9.7, ADR-0022 D8 and the code Javadoc. `application-prod.yml` untouched. `/review`, `/security-review` and `/test-validate` have not run on T-013.

**M7 part 2 security review fixes (`10-security-review-M7-part2.md`): implemented on `ccr-4e9e7cbe-4vl9v6`, not merged. H-1 stays open (human action).** M-1: filter Javadoc, RES-40, design and ADR amended (junk counts against `REFRESH_IP`; the SPA keeps the session on a refresh 429), new k6 case `refresh-junk-flood.js` (not run, no dev stack). M-2: role-level replay of a failed detach holder read (`RoleReplayQueue`, 1 s tick, 1 s read timeout). L-1: one valid epoch range for the Lua script and the Java parser. L-2: rate-limited `RBAC_EPOCH_UNPARSEABLE` WARN and `epoch.check{outcome=unparseable}`. L-3: per-tenant last-seen cap, own bumps in a separate per-tenant pool, `last_seen_dropped{reason}`. See A-22 in `04-tasks.md`, runbook §8 and `monitoring.md` §6.

Next in delivery order now that M1, M2, M4 and M6 are merged: M5 (T-007, T-008) and M7 (T-009..T-014), neither depending on the other. M7 then unblocks M3 and M7b.

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
