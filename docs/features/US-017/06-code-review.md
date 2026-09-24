# US-017 — Code Review

**Reviewer:** code-reviewer agent (fresh context, read-only)
**Branch:** `feature/US-017` (no commits yet — reviewed against the uncommitted working-tree diff vs. `origin/main`)
**Scope:** Java main + test files only (T-001–T-007's code changes). Documentation/governance files (T-008) were reviewed separately as part of that task's own Definition of Done and are out of scope here.

**Cross-referenced against:** `docs/features/US-017/03-design.md` (Revision 2), `03b-threat-model.md`, `04-tasks.md`, `CLAUDE.md`, `docs/coding-standards.md`.

## Overview

Overall this is a strong, carefully-executed implementation that tracks `03-design.md` (Revision 2) and `03b-threat-model.md` closely — D1–D25 all landed, MC-A through MC-J all have corresponding tests, and the RES-10 empirical exit gate (harness C reshape with the restored `assign(TENANT_ADMIN)` thread + new benign thread) is genuinely done, not faked. No authorization-correctness bugs, cross-tenant leaks, or missing gates were found. Findings below are a real, undocumented protocol deviation and two low-severity cleanups.

Files reviewed in full: the 4 new domain/infrastructure files, the 8 modified main files, and the test suite sampled in depth (`RoleAssignmentServiceTest`, `RbacAdminEquivalenceTest`, `RbacDangerousPermissionsTest`, `AdminEquivalentLockoutIT`, `LastAdminLockoutIT`, `RbacZeroActiveAdminsHealthIndicatorIT`, `AdminEquivalenceEquivalenceIT`, `AdminEquivalenceSqlJavaEquivalenceIT`, `JpaUserRoleAssignmentAdapterTest`, `RoleManagementServiceTest`).

---

## Findings

### [MEDIUM] Caller gate issues two sequential locking reads instead of the one pinned union read

**File:** `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java:794-827` (`requireCallerHoldsAdminEquivalentRole`)

**Problem:** `03-design.md` §7.2's protocol (and §8.5's performance table, "M5 → M5b (same statement count)", and §9.2's `privileged_role_change_allowed` note, "4 series, **zero new queries**") pin M5b as **one** locking `FOR SHARE` call over the union `callerSet = fullyAdminEquivalentIds ∪ {namedAdminRoleId}`. The shipped code instead calls `hasActiveAssignmentOfAnyRole` up to **twice**: once with just `{namedAdminRoleId}`, and — only if that returns false — again with `fullyAdminEquivalentIds`. This is deliberate (the method's own Javadoc explains it: splitting the query is what lets `callerMatchedOn` be attributed), and it's covered by `RoleAssignmentServiceTest.should_callM5bOnlyWithActorIdAndCallerQualifyingRoleIds_when_revokingPrivilegedRole_MCF` (which asserts `times(2)`), so it's not an accident — but it was never fed back into the design doc.

**Why it matters:** §7 is explicitly called out as "the load-bearing section" for this story, and the design's own cost/lock-hold-duration reasoning (§7.3, RES-19, T-D13 — the tenant-wide X lock acquired before the authorization decision, reachable by any `user:write` holder) assumes M5b costs one statement. Doubling the locking round-trips for exactly the new `ALL_DANGEROUS_PERMISSIONS` population (the population FR-3 exists to serve) extends the time the M11 X-lock is held under contention, which is the one thing the design spent the most words bounding. It also means anyone reading `03-design.md`/`04-tasks.md` in isolation (e.g. for the next story built on this gate) will reason from a cost model that's no longer accurate.

**Suggested fix:** Either (a) go back through the design with a short addendum documenting the two-query shape and its effect on the RES-19/T-D13 bound, or (b) collapse to one `hasActiveAssignmentOfAnyRole(actor.userId(), unionSet, tenantId)` call and derive `callerMatchedOn` from data already in hand (e.g. a cheap follow-up check against the already-fetched `roles.namedAdminRoleId()`/`fullyAdminEquivalentIds` membership only in the WARN/log path, not on every pass). Either is fine; shipping the current shape silently, with no note in `03-design.md`/`monitoring.md`, is the part that should be fixed.

**Resolution (2026-09-24): fixed via option (a), design addendum — no code change.** Option (b) was rejected: `hasActiveAssignmentOfAnyRole`'s boolean-return, single-role-set-per-call shape is depended on by ~100 existing test call sites across `RoleAssignmentServiceTest` and `JpaUserRoleAssignmentAdapterTest`; deriving `callerMatchedOn` without a second query would require changing the port method to return the matched role id(s) instead of a boolean, an invasive interface/adapter/test-suite change disproportionate to a non-security, bounded-cost Medium finding. Added a dated amendment to `03-design.md` §7.2 (immediately after the protocol pseudocode) documenting the shipped two-call shape, why it's deliberate (per-population query-cost asymmetry, `callerMatchedOn` attribution), and that it's still fully contained inside M11's X-region (D8's containment proof unaffected). Also corrected the §8.5 performance table's `assign()`/`revoke()` privileged-role rows to caveat "same statement count" as true only for a literal-`TENANT_ADMIN` caller, +1 for an `ALL_DANGEROUS_PERMISSIONS`-only caller. No test or production code changed; `RoleAssignmentServiceTest`'s existing `times(2)` assertion (MC-F) remains the source of truth for this shape going forward.

### [LOW] Stale, now-incorrect Javadoc left over from an intermediate task state

**File:** `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java:642`

**Problem:** `resolveAdminEquivalentRoles`'s Javadoc says "Wired up by `revoke()` (US-017 T-002); `assign()` (T-003) is still pending." Both `assign()` (line 242) and `revoke()` (line 457) call this method in the shipped code — the comment is a leftover from when T-002 landed before T-003 and was never updated.

**Why it matters:** Misleading to the next reader; looks like an unfinished migration if read in isolation from git history.

**Suggested fix:** Delete the "still pending" sentence (or replace with "used by both `assign()` and `revoke()`").

### [LOW] Redundant/awkward test class name

**File:** `nexus-backend/src/test/java/com/example/nexus/rbac/AdminEquivalenceEquivalenceIT.java:44`

**Problem:** The doubled word ("Admin**Equivalence** **Equivalence**IT") is easy to confuse with the similarly-purposed but functionally distinct `AdminEquivalenceSqlJavaEquivalenceIT` (MC-I, SQL-vs-Java drift) sitting in a different package. The two tests are genuinely different (this one is MC-H: M10-bulk-read-vs-M7-per-role equivalence), but the names don't make that obvious at a glance.

**Why it matters:** Minor discoverability/maintenance friction only — not a functional issue.

**Suggested fix:** Rename to something like `AdminEquivalencePartitionM10VsM7IT` if touched again; not worth a standalone change now.

---

## Positive notes

- `RbacDangerousPermissions.carriesAll` is implemented exactly per the design's fail-open warning (per-name `anyMatch`, never a count, never `containsAll`), and all three MC-B regression assertions (duplicate-name, case-variant, exactly-two-of-three) plus null/empty cases are present in `RbacDangerousPermissionsTest`.
- M11's locking read was correctly changed from the design's tentative JPQL+`@Lock` sketch to a native `FORCE INDEX` query after the team's own IT (`LastAdminLockoutIT#should_pinKeyToFkUserRolesRole_acrossInListCardinalities_forM11AndM5b_MCC`) empirically caught the JPQL/`@Lock` form falling back to a full table scan at IN-list size 25 — exactly the failure mode the design flagged as a risk to verify, and it was verified and fixed rather than assumed.
- The ascending-order comparator (`UNSIGNED_BYTEWISE_UUID_ORDER`) is implemented correctly and is pinned with tests (`should_sortLockSetByUnsignedBytewiseOrder_notUuidCompareTo_when_revoking_MCE` and its `assign()` sibling) that specifically construct a UUID pair that sorts *differently* under `UUID.compareTo` vs. the required unsigned byte-wise order — this is exactly the kind of test that would have caught the trap the design called out (RC-20.7/T-D15).
- `AdminEquivalentLockoutIT`'s cross-role holder-counting test is a genuine concurrent race (`CyclicBarrier`, two real threads, self-revocation on both sides to avoid order-dependence) that specifically targets the D5 defect (row-vs-holder confusion across two different roles) that a single-role harness cannot exercise. Good test design, not a sequential test dressed up as concurrent.
- `LastAdminLockoutIT`'s harness C reshape correctly restores the `assign(TENANT_ADMIN)` thread and adds the new benign `assign(BENIGN)`/`revoke(BENIGN)` pair against the *same* rows the privileged threads touch, exactly as RC-20.6 requires — this is the story's central empirical claim (RES-10 closure) and it's not a token gesture.
- `RbacZeroActiveAdminsHealthIndicator` never leaks tenant ids via the actuator detail (count-only), confirmed both by inspection and by a real-DB IT (`RbacZeroActiveAdminsHealthIndicatorIT`) that correctly handles the shared-Testcontainers-DB contamination risk by scoping assertions to the log line rather than the aggregate health status (except in the one scenario where that's provably safe).
- `RoleManagementService.becameFullyAdminEquivalent`'s "before" state is correctly derived in-memory from the "after" state minus the just-attached permission, avoiding a second query, exactly as D22 specifies — and it's called at the right point (after the actual `attachPermission` INSERT, so `namesAfterAttach` correctly reflects the just-attached permission).

---

## Summary

| Severity | Count |
|---|---|
| Blocker | 0 |
| High | 0 |
| Medium | 1 |
| Low | 2 |

**Verdict: APPROVE WITH NITS**

The one Medium finding (two sequential M5b reads vs. the pinned single union read) is worth a follow-up — either a short design addendum or a small refactor — but it is not a security defect (both reads are still fully contained inside M11's X-region, so D8's containment proof holds either way) and it's already covered by tests, so it does not block merge on its own.

## Files reviewed

- `nexus-backend/src/main/java/com/example/nexus/rbac/domain/ActiveAssignmentHolder.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/domain/RbacAdminEquivalence.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/domain/RolePermissionName.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/domain/RbacDangerousPermissions.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/persistence/ZeroAdminTenantReader.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleManagementService.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/port/out/UserRoleAssignmentPort.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/persistence/JpaUserRoleRepository.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/persistence/JpaRoleRepository.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/persistence/JpaUserRoleAssignmentAdapter.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/health/RbacZeroActiveAdminsHealthIndicator.java`
- `nexus-backend/src/test/java/com/example/nexus/rbac/AdminEquivalentLockoutIT.java`
- `nexus-backend/src/test/java/com/example/nexus/rbac/AdminEquivalenceEquivalenceIT.java`
- `nexus-backend/src/test/java/com/example/nexus/rbac/LastAdminLockoutIT.java`
- `nexus-backend/src/test/java/com/example/nexus/rbac/domain/RbacAdminEquivalenceTest.java`
- `nexus-backend/src/test/java/com/example/nexus/rbac/domain/RbacDangerousPermissionsTest.java`
- `nexus-backend/src/test/java/com/example/nexus/rbac/application/RoleAssignmentServiceTest.java`
- `nexus-backend/src/test/java/com/example/nexus/rbac/application/RoleManagementServiceTest.java`
- `nexus-backend/src/test/java/com/example/nexus/rbac/infrastructure/health/RbacZeroActiveAdminsHealthIndicatorIT.java`
- `nexus-backend/src/test/java/com/example/nexus/rbac/infrastructure/health/AdminEquivalenceSqlJavaEquivalenceIT.java`
- `nexus-backend/src/test/java/com/example/nexus/rbac/infrastructure/persistence/JpaUserRoleAssignmentAdapterTest.java`
