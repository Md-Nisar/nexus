# Coverage audit for Task US-017

**Phase:** 8 (Test-Validate)
**Scope:** `feature/US-017` working-tree changes only (branch has zero commits; HEAD == `origin/main`). Diffed via `git diff --stat origin/main -- nexus-backend/src/main nexus-backend/src/test`. Excluded per the invocation's own scoping note: `.claude/*`, `.mcp.json`, `.github/workflows/ai-test-coverage.yml`. No frontend files are touched by this story (confirmed independently again via the diff stat below) — frontend testing/audit skipped entirely.

```
 RoleAssignmentService.java                  |  716 +++++++--
 RoleManagementService.java                  |   98 +-
 UserRoleAssignmentPort.java                 |   91 +-
 RbacDangerousPermissions.java               |   35 +
 RbacZeroActiveAdminsHealthIndicator.java    |   87 +-
 JpaRoleRepository.java                      |   29 +
 JpaUserRoleAssignmentAdapter.java           |   59 +-
 JpaUserRoleRepository.java                  |  191 ++-
 (+ new) ActiveAssignmentHolder.java, RbacAdminEquivalence.java, RolePermissionName.java,
         ZeroAdminTenantReader.java
 16 test/main files changed, 3217 insertions(+), 712 deletions(-)
```

Phase 6 (code review) verdict: APPROVE WITH NITS. Phase 7 (security review) verdict: originally BLOCKED on H-1/M-1, both since fixed and independently re-verified in `07-security-review.md` §9 ("Resolution"); three Low findings (L-1, L-2, L-3) were deliberately deferred. This audit closes L-3 (the only one that is a test-coverage gap — L-1/L-2 are code-level findings with no test-only fix) and checks the authorization matrix and load-scenario shape the security review flagged as worth a second look.

## Existing tests

- `nexus-backend/src/test/java/com/example/nexus/rbac/AdminEquivalentLockoutIT.java` (3 IT methods): the story's central concurrency proof — cross-role, distinct-**holder** (not distinct-row) counting under a genuine `CyclicBarrier`-driven race; cross-tenant lock-set containment; and the H-1 regression (`should_blockSelfRevoke_when_onlyRemainingHolderIsAnyQualifyingButNotCallerQualifying_H1`) reproducing the reviewer's exact sole-admin-self-revokes-while-an-ANY-only-holder-remains sequence against a real database.
- `nexus-backend/src/test/java/com/example/nexus/rbac/LastAdminLockoutIT.java` (12 IT methods): Harness C (RES-10 closure, mixed assign/revoke concurrent race, ≥5 green runs evidenced in `07-security-review.md`), MC-A/MC-C/MC-E/MC-6 mechanical controls, D18 lock-hold timer outcome tags.
- `nexus-backend/src/test/java/com/example/nexus/rbac/infrastructure/health/RbacZeroActiveAdminsHealthIndicatorIT.java` (5 IT methods): including the H-1 regression scenario at the health-indicator layer.
- `nexus-backend/src/test/java/com/example/nexus/rbac/infrastructure/health/AdminEquivalenceSqlJavaEquivalenceIT.java` (2 IT methods, MC-I): Java/SQL predicate equivalence, ANY-only fixtures asserting INVISIBLE, the ALL-three-revoked fixture asserting DOWN.
- `nexus-backend/src/test/java/com/example/nexus/rbac/security/RoleAssignmentSecurityIT.java` (26 IT methods, pre-audit): cross-tenant isolation (all 3 verbs), 404s, permission-pair 403/2xx for assign/list/revoke, stale-JWT/out-of-band-revocation for both the name-match and dangerous-custom-role gate branches, the ALL-three stale-JWT extension, the self-assign canary acceptance test, malformed-principal/UUID handling, `assignedBy` redaction.
- `nexus-backend/src/test/java/com/example/nexus/rbac/application/RoleAssignmentServiceTest.java` (107 test methods): exhaustive MC-B…MC-G matrix, Edge Cases 1/2/3/6/9/10/11/12 each present as a named test (not merely referenced in a comment — verified by direct inspection, see Gaps), the M-1 ordering regression (`should_readCanaryStateBeforeTheInsert_notAfter_when_selfAssigningATenantAdminRole_M1`).
- `nexus-backend/src/test/java/com/example/nexus/rbac/application/RoleManagementServiceTest.java` (51 test methods): D13 holder-count buckets, the new detach gate (mocked) — `should_throwNotTenantAdminAndNotWrite_when_detachingDangerousPermissionAsNonAdmin`, `should_detachDangerousPermission_when_callerIsActiveAdmin`, `should_detachOrdinaryPermissionWithoutGate_when_nonAdminCaller`.
- `nexus-backend/src/test/java/com/example/nexus/rbac/domain/RbacAdminEquivalenceTest.java` (15), `RbacDangerousPermissionsTest.java` (13, incl. `carriesAny`/`carriesAll`), `ActiveAssignmentHolderTest.java` (1), `RolePermissionNameTest.java` (1).
- `nexus-backend/src/test/java/com/example/nexus/rbac/infrastructure/persistence/JpaUserRoleAssignmentAdapterTest.java` (23), `infrastructure/health/RbacZeroActiveAdminsHealthIndicatorTest.java` (7), `infrastructure/health/HealthProbeConfigurationTest.java` (2, TTL/probe-group pinning), `AdminEquivalenceEquivalenceIT.java` (1, MC-H).
- `nexus-backend/src/test/load/role-assignment-denial-pool-pressure.k6.js`, `role-change-privileged-denial-throttle.k6.js` (pre-existing, from US-014/US-016): concurrency-burst and sustained-denial-rate scripts against `POST/DELETE /api/v1/users/{userId}/roles`.

## Gaps identified

- **[HIGH]** `07-security-review.md` finding **L-3**: the new D13 detach gate (`RoleManagementService.detachPermission`'s dangerous-permission caller check) had only mocked unit coverage — no HTTP-level proof that (a) a `role:write`-only non-admin gets 403 on `DELETE /api/v1/roles/{roleId}/permissions/{dangerousPermId}` with the row still present, (b) detaching a never-attached dangerous permission also 403s (not 404, T-I14), (c) detaching an ordinary permission succeeds with 204 for the same non-admin `role:write` holder. Rated High here (not Low) because it is an authorization-control test gap on the gate that protects the lockout guard's own input, per this repo's QA convention of treating untested authorization branches as high-priority regardless of the security review's exploitability-weighted severity. — added in `nexus-backend/src/test/java/com/example/nexus/rbac/security/RolePermissionSecurityIT.java`.
- **[MED]** Authorization-matrix asymmetry: the widened caller gate (`requireCallerHoldsAdminEquivalentRole`) is identical code shared by `assign()` and `revoke()`, and `RoleAssignmentSecurityIT` proved the ANY-only-custom-role-caller 403 (`NOT_TENANT_ADMIN`) and both stale-JWT branches **only on the POST (assign) verb**. The DELETE (revoke) verb's HTTP-level coverage stopped at `PERMISSION_ABSENT` (missing `user:write` entirely) and a benign-role 204 — the privileged-gate 403 branch on `revoke()`, and a genuine privileged-revoke 204 success, were unproven above the service layer (unit tests in `RoleAssignmentServiceTest` covered them, but not an end-to-end HTTP round trip). — added two tests to `RoleAssignmentSecurityIT.java` (one denial, one success — a negative-only addition risks passing for the wrong reason, e.g. a gate that denies every privileged revoke unconditionally).
- **[LOW]** `role-change-privileged-denial-throttle.k6.js`'s header comment pre-dates US-017 D7 and states the pre-gate lock "never applies" on the assign side, deferring to "the revoke scenario below" — which does not exist in the file (only two assign-side scenarios are defined). Post-D7, both of the file's existing scenarios (grant of `TENANT_ADMIN` by a non-admin) **already** exercise the new pre-gate M11 tenant-wide lock on `assign()`'s denial path, since the target role name-matches; the comment just didn't say so, and the watch-list omitted the new `nexus.rbac.privileged_revoke_lock_hold{operation="assign",outcome="denied"}` series design doc §"Impact on other docs" says this story must add. — corrected the header comment and watch-list in place; no new script needed since the existing scenarios already have the right shape.

Gaps considered and **not** added (already adequately covered, avoiding duplication per this story's own A-4 convention against duplicating harness shape across files):
- Cross-role, multi-holder concurrent revocation (Edge Case 3, Risk R1/R5) — already a dedicated, deliberate real-database proof in `AdminEquivalentLockoutIT`; not extended further per the invocation's own instruction.
- The mixed assign/revoke deadlock-freedom proof (RES-10/D7) — already Harness C in `LastAdminLockoutIT`, ≥5 green runs evidenced in the security review's own resolution notes; re-verified green in this audit's full run (below), not re-run 5x again here (would be redundant with what Phase 7 already evidenced).
- TOCTOU on `role_permissions` changing mid-revoke (Edge Cases 4/5) — a resolved, documented design ruling (`03-design.md` §7.5, RES-16), not an open test gap: M10 is deliberately non-locking by design (a lock on `permissions` would be rejected in production and silently pass every Testcontainers IT — MC-A already guards this), and both directions of the race are argued safe in the design doc. No test was missing; the design explicitly rules out the "fix" a naive test might expect.
- Edge Case 7 (health-indicator staleness under a hypothetical cached signal) — moot: FR-2 shipped as a live query, not a new cache: the only cache in play is the pre-existing 30 s actuator TTL, already pinned by `HealthProbeConfigurationTest`.
- Edge Case 8 (RES-9's caller-incapable-but-lockout-protected asymmetry) — moot: Gate 1 resolved RES-9 as fixed-in-story (not deferred), so the asymmetric state this edge case worried about no longer exists; nothing to test against.
- L-1 (health indicator's UNKNOWN-branch message leaks `e.getMessage()`) and L-2 (D22's `REPEATABLE READ` race can silently suppress the threshold-crossing WARN under two concurrent attaches) — both are **code**-level findings, not test-coverage gaps; the security review's own fix recommendation for each is a code change (a fixed string; moving the M7 read into `afterCommit`), not a missing test. Deferred to follow-up tasks per the security review's explicit instruction; out of this audit's scope by the invocation's own text ("Do not modify `07-security-review.md`... report your findings").

## Tests added

`RolePermissionSecurityIT.java` (L-3 closure):
- `should_return403AndLeaveRowIntact_when_nonAdminDetachesADangerousPermission`
- `should_return403NotFound_when_nonAdminDetachesADangerousPermissionNeverAttached`
- `should_return204_when_nonAdminRoleWriteHolderDetachesAnOrdinaryPermission`

`RoleAssignmentSecurityIT.java` (authorization-matrix symmetry, assign vs. revoke):
- `should_return403WithNotTenantAdmin_when_nonAdminHoldingUserWriteAttemptsToRevokeAnActiveTenantAdmin`
- `should_return204_when_activeTenantAdminRevokesADangerousCustomRoleFromAnotherUser`

`nexus-backend/src/test/load/role-change-privileged-denial-throttle.k6.js` (doc-only correction, no new scenario):
- Header comment and watch-list updated to record that, as of US-017 D7, the file's existing assign-side scenarios already exercise the new pre-gate M11 lock on the denial path, and to add `nexus.rbac.privileged_revoke_lock_hold{operation="assign",outcome="denied"}` to the watch-list.

## Run results

Backend, full Docker-backed run (`./mvnw verify` from `nexus-backend/`, real Testcontainers MySQL 8.4 + Redis, no `-DskipITs`, per this repo's CLAUDE.md §4 rule for changes touching persistence/locking):

- Aggregated directly from `target/surefire-reports/*.txt` + `target/failsafe-reports/*.txt` (183 test-class report files): **1437/1437 tests passing, 0 failures, 0 errors, 1 skipped** (the pre-existing skip, unrelated to this story).
- `RolePermissionSecurityIT` standalone: 16/16 passing (13 pre-existing + 3 new).
- `RoleAssignmentSecurityIT` standalone: 26/26 passing (24 pre-existing + 2 new).
- Maven exit code: `0`.
- Note on the total count: the security review's own §9 resolution cites "1389/1390 tests" as its baseline immediately before this audit. This run measured 1437 — 47 more than that baseline, not the 5 this audit added. All 1437 pass with zero failures/errors, so this is not a red flag for this audit, but it is a discrepancy worth flagging: either the reviewer's count was taken under a different profile/scope, or additional tests landed on this working tree between the security review and this audit. Recommend reconciling the exact baseline the next time this number is quoted, rather than carrying it forward unverified.

No frontend changes on this branch (confirmed via the diff stat above); `npm test`/`npm run lint` not applicable and not run, per the invocation's own scoping note.

## Load scenarios

- `nexus-backend/src/test/load/role-assignment-denial-pool-pressure.k6.js` (pre-existing, US-014): targets `CROSS_TENANT_TARGET`, resolved in `verifySameTenant`/`resolveRoleInTenant` before `nameMatch`/`privileged` is ever computed. **Unaffected by US-017 D7** (the denial happens before the point where D7 added the new pre-gate lock) — confirmed still accurate as-is, no change made.
- `nexus-backend/src/test/load/role-change-privileged-denial-throttle.k6.js` (pre-existing, US-016; **comment/watch-list corrected by this audit**): both scenarios grant the literally-named `TENANT_ADMIN` role from a non-admin `user:write` holder — the name-match branch of `assign()`'s privileged path. As of US-017 D7, this path now acquires the tenant-wide M11 lock *before* the caller gate, so this script already is the load-side proof of the RES-19 residual (a pre-authorization X lock, bounded only by the D14 throttle) on the `assign()` side specifically — it just needed its documentation to say so and to name the new `nexus.rbac.privileged_revoke_lock_hold{operation="assign",outcome="denied"}` metric on its watch-list, both now done. No new script was warranted: a genuinely new scenario would only be justified if the *existing* scripts didn't already reach the D7 code path under load, and they do.
- Neither `assign()`/`revoke()` nor `attachPermission`/`detachPermission` are expected to see >10 RPS in production (all are `*:write`-gated, reachable only by already-privileged callers per `03-design.md`'s own NFR table) — consistent with why both existing scripts are framed as targeted threat-model regression checks, not routine endpoint-sizing scenarios, and why no new Gatling/k6 script was added for a routine-throughput scenario.

## Flaky tests

- None newly introduced. The 5 new tests added by this audit are all single-request HTTP round trips against a real `@SpringBootTest` + Testcontainers context — no timers, no threads, no `Thread.sleep`, deterministic fixtures (fresh `UUID`s per tenant/user/role, no shared mutable state across test methods).
- Pre-existing, already-flagged-elsewhere concurrency harnesses (`AdminEquivalentLockoutIT`, `LastAdminLockoutIT`) use `CyclicBarrier.await(5, TimeUnit.SECONDS)` / `ExecutorService.awaitTermination(15, TimeUnit.SECONDS)` — timing-bounded by design (real multi-thread races against Testcontainers MySQL), the same accepted pattern flagged in `docs/features/US-016/08-test-audit.md`. Not touched by this audit; all green in this run's full `./mvnw verify`.
- No other timing-, ordering-, or external-state-dependent test was identified in the changed-file set.
