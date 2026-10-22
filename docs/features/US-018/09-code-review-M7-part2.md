# Code review: US-018 M7 part 2 (T-014, T-010, holder-read fix, T-011, T-012, T-013)

**Verdict: CHANGES REQUESTED.** 0 Blocker, 3 High, 2 Medium, 6 Low, 4 Nit.

Scope: `git diff f2cb1ea^..HEAD` on `ccr-4e9e7cbe-4vl9v6`, HEAD `98c79f6` (7 commits, 65 files). Fresh-context `code-reviewer` agent, read-only. Findings already resolved in `06-code-review-M7.md` are not re-raised. The reviewer ran the unit tests offline (409 in the touched classes, 0 failures, 1 skipped = the `@Disabled` prod-profile test). It did not run the ITs or the k6 storm gate.

The reviewer confirmed the following match the design: state-machine atomicity and 3-in-10 s window, RC-53 (only read/probe failures count), L-4 (drain failure does not reset the sustain), filter 503 `AUTH_005` and public-endpoint exemption, reuse-first `revokeFamily` count through four layers, bucket ordering, epoch-keyed cache and bump script, unconditional `@EnableScheduling`, bounded metric tags, no user ids or raw IPs in logs/metrics.

## Findings

### H-1 Full scan of the last-seen map on request threads once the map is full
`PermissionFreshnessService.java:508-523` (`remember`, `removeIf` at :513), called from `evaluate`, `epochForMint` and `rememberBump` (which `invalidateHolders` calls per holder). With 100,000 live entries, every new key triggers a full scan on the request thread (and inside the detach fan-out in `afterCommit`, JDBC connection held). A 200,000-holder detach is ~10^10 visits; other instances scan on the hot path for ~16 min.
Fix: never scan on the request path. Purge expired entries in the 1 s scheduler tick; when full, only count `last_seen_dropped`. Test a full map without any scan.

### H-2 Local bumps recorded with the instance wall clock instead of the value the store wrote
`PermissionFreshnessService.java:526-533`, `RedisPermissionEpochAdapter.java:46-57`. The store writes `max(old+1, Redis TIME)`; the instance records `max(seen+1, local ms)` after the call, which exceeds the store value by at least the round trip, even with synced clocks. Availability: a token minted with the store value is STALE whenever the instance falls back to `lastSeen` (read blip, DegradedOpen), and the SPA clears the session on a failed replay after refresh. Authorization: an instance clock d ms ahead can mint a token whose epoch exceeds a revoke landing within d ms, so a revoked token is FRESH. Design §9.2 uses Redis TIME so that no instance clock enters this decision.
Fix: the bump script returns the new values; `PermissionEpochPort.bump` returns them; `rememberBump` (and replay) records exactly those; drop the local-clock term. Tests: a token minted with the store value is not STALE when reads then fail; a clock ahead of the store does not raise the minted epoch.

### H-3 T-014 does nothing in production: `application-prod.yml` lacks `require-auth: true`
The file has no such key, the only test that would catch it is `@Disabled` (`6124d2a`), and the `application.yml` comment claiming prod sets true is currently false. Production could start against an unauthenticated Redis (RES-32).
Fix: add `nexus.rbac.redis.require-auth: true` to `application-prod.yml` (human edit; a repo hook blocks agents), remove `@Disabled`, add an explicit M7 merge-checklist item next to "Ops confirms the prod profile is active" (04-tasks.md :539).

### M-1 Replay queue drops a coalesced user by the age of their oldest lost bump
`EpochReplayQueue.java:63-67`, `:99`. A second revoke for the same user at t=900 coalesces and keeps `failedAt`=0; at t=960 the entry is dropped by age although a token minted at t=899 lives to t=1799. After Redis recovers, no bump is replayed and the revoked token stays FRESH.
Fix: store `oldestFailedAt` (for `ageMs`) and `newestFailedAt` (for expiry); compare the newest in `poll`; keep both on `requeue`; correct §9.3 (`03-design.md:743`). Test: offer at T and T+900, poll at T+960, expect replay.

### M-2 A detach whose post-commit holder read fails loses the revocation with no paging signal and no retry
`RoleManagementService.java:544-562`, call site :377. After `224ea88` there is no 500, but `invalidateHolders` is never called: `bump_failed` does not increment, nothing is queued, the only trace is the ERROR log `RBAC_HOLDER_READ_FAILED`. Credible trigger: two pooled connections held, pool pressure, Hikari timeout.
Fix: on a detach holder-read failure increment a paging counter (`bump_failed{operation="detach", reason="holder_read"}`), retry the read once, optionally queue a role-level replay. Unit test.

### L-1 An unparseable stored epoch counts as a store failure
`RedisPermissionEpochAdapter.java:79-85`, `PermissionFreshnessService.java:314-317`. Three requests in 10 s from the user with a corrupt key push the instance to DegradedOpen (needs Redis write access). This was a forward requirement from `07-security-review-M7.md:83-98`.
Fix: distinct port result for an unparseable value, map to STALE for that user, WARN `RBAC_EPOCH_UNPARSEABLE` (tenantId only), not counted in the window. Adapter tests for `"abc"` and `"9223372036854775808"`.

### L-2 The 60 s recovery sustain is measured from before the drain
`PermissionFreshnessService.java:346-353`. `now` is captured before `drainReplayQueue()`; a drain of 60 s or more lets the next successful read go Healthy, clearing `t0` (RC-31.2 forbids a fresh window).
Fix: re-read the clock after the drain. Test with the clock advancing during the drain.

### L-3 A mint that fell back to an unverified epoch uses a cache key no bump deletes
`JwtRs256Service.java:119-121`, fallbacks at `PermissionFreshnessService.java:272, 284`. The cache entry under `:0` / `:E_l` survives a later detach, so a fallback mint can carry a removed permission.
Fix: `epochForMint` reports whether the epoch was verified; when not, skip the cache in `resolve` (read the DB, do not `put`).

### L-4 Attach eviction races a concurrent mint
`RoleManagementService.java:309-310`. A mint that read pre-attach permissions can `put` them after the eviction, so the holder lacks the new permission for up to 900 s. Fail-safe, same race §9.4 fixes for detach.
Fix: record as accepted next to Decision 15, or make `put` conditional, or evict again shortly after commit.

### L-5 A failed bump is not recorded locally
`PermissionFreshnessService.java:550-561`, `:595-598`; test `should_notRecordLocalBump_when_bumpFails` pins it. During a full outage, the instance that processed a compromised-account revoke still serves the revoked token (SKIPPED_DEGRADED).
Fix: also record failed-bump users with a lower bound (`seen + 1`, which cannot cause a false STALE); amend A-18; invert the test.

### L-6 Runbook §8 holder query prints ids in the wrong form
`runbook.md` §8 uses `HEX(...)` (upper-case, no dashes); the keys need dashed lower-case UUIDs, so the `EVAL` bumps keys nothing reads.
Fix: `BIN_TO_UUID(ur.tenant_id)`, `BIN_TO_UUID(ur.user_id)`, `UUID_TO_BIN(?)` for the parameter.

### N-1 `require-auth` has no env placeholder
`application.yml:178`: use `${NEXUS_RBAC_REDIS_REQUIRE_AUTH:false}`.

### N-2 First throttle WARN says `suppressedCount=1` when nothing was suppressed
`RefreshTokenUseCase.java:260-274`: rename to `rejectedCount` or document in A-20.

### N-3 Unexpected exceptions from `probe()` escape the scheduler tick unaccounted
`RedisPermissionEpochAdapter.probe` catches only `DataAccessException`; catch `RuntimeException` and return false.

### N-4 Batches are sequential although T-010 says pipelined; the service is 687 lines
Record the deviation or pipeline; consider extracting `OutageStateMachine` and `LastSeenEpochs`.

## Observation for the security reviewer
`REFRESH_IP` (300/60 s) counts invalid refreshes too. An attacker behind a shared NAT above 300/min causes 429s for valid refreshes and the SPA logs users out on a refresh 429. Confirm RES-40 covers this, or add a k6 scenario above 300/min.

## Additional finding from the automated commit security review (not the reviewer agent)
`RefreshTokenUseCase.consumeFamilyBucket` rejections are logged only at DEBUG and have no counter, so abuse of one family leaves no signal (the failure bucket has both). Fix: a dedicated counter (e.g. `nexus.auth.refresh_family_throttled`) and a rate-limited WARN without the family id or IP.

## Summary

| Severity | Count |
|---|---|
| Blocker | 0 |
| High | 3 |
| Medium | 2 |
| Low | 6 |
| Nit | 4 |

Verdict: **CHANGES REQUESTED.** ITs and the k6 storm gate were not run by the reviewer and must be re-run after the fixes.

## Resolution (2026-10-09)

Fixed on `ccr-4e9e7cbe-4vl9v6` with tests. Gate: `./mvnw verify` with Docker up, 1737 unit tests (0 failures, 2 skipped, one of them the `@Disabled` prod-profile test) and 426 ITs (0 failures), Checkstyle 0 violations, SpotBugs and JaCoCo checks green. The k6 storm gate and the NAT refresh gate were not re-run (no dev stack here) and stay open merge-checklist items.

| Finding | State | Where |
|---|---|---|
| H-1 | Fixed | `remember` never scans; the 1 s tick purges expired entries (`purgeExpiredSeen`); a full map only counts `last_seen_dropped`. A-18, A-21. |
| H-2 | Fixed | Bump script returns the new values, `PermissionEpochPort.bump` returns `Map<UUID, Long>`, `rememberBump` and the replay record exactly those; no local-clock term. Design §9.2, ADR-0022 D1, A-18. |
| H-3 | Partly: needs a human | `application-prod.yml` and `@Disabled` deliberately untouched. Explicit merge-checklist item added in `04-tasks.md` next to "Ops confirms the prod profile is active"; the inaccurate STATUS.md line corrected (`@Disabled`, not red). |
| M-1 | Fixed | `EpochReplayQueue` keeps `oldestFailedAt` and `newestFailedAt`; expiry compares the newest; both kept on `requeue`. Design §9.3, ADR-0022 D3, A-21. |
| M-2 | Fixed | A detach holder read is retried once; the second failure increments `bump_failed{operation=detach, reason=holder_read}`. No role-level replay (holders unknown). Runbook §8 has the page response. |
| L-1 | Fixed | `EpochUnparseableException` from the adapter; `STALE` for that user, WARN `RBAC_EPOCH_UNPARSEABLE` (tenantId only), not counted in the window. The bump script treats a non-numeric or above-2^53 value as 0. |
| L-2 | Fixed | The recovery sustain starts from a clock read after the drain. |
| L-3 | Fixed | `mintEpoch` returns `(epoch, verified)`; unverified mints use `RoleResolutionService.resolveUncached`. |
| L-4 | Accepted | Recorded next to Decision 15 (design §9.3, ADR-0022 D3); no trivial conditional fix. |
| L-5 | Fixed | A failed bump records the lower bound `seen + 1`; A-18 amended; `should_notRecordLocalBump_when_bumpFails` inverted. |
| L-6 | Fixed | Runbook §8 uses `BIN_TO_UUID` and `UUID_TO_BIN(?)`. |
| N-1 | Fixed | `${NEXUS_RBAC_REDIS_REQUIRE_AUTH:false}`. |
| N-2 | Fixed | WARN field renamed to `rejectedCount`; A-20 and design §9.7 updated. |
| N-3 | Fixed | `probe()` catches `RuntimeException` and returns false. |
| N-4 | Deviation recorded, extraction not done | Sequential batches recorded in design §9.4, T-010 and ADR D4. `OutageStateMachine` and `LastSeenEpochs` extraction left as an open refactor (A-21). |
| Extra (family throttle) | Fixed | `nexus.auth.refresh_family_throttled` counter and a rate-limited WARN `AUTH_REFRESH_FAMILY_THROTTLED rejectedCount` (no family id, no IP), its own window. |
