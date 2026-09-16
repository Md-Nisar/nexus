# US-016 Code Review -- Gate role assignment/revocation by actual privileges, not role name

**Reviewer:** Staff Engineer (automated review agent)
**Date:** 2026-09-16
**Scope:** git diff HEAD (24 tracked files) plus all untracked US-016 files (design docs, ADR-0017, threat model, new port/adapter, new tests)
**Cross-referenced:** docs/features/US-016/03-design.md (rev 2), docs/features/US-016/03b-threat-model.md, docs/adr/0017-privilege-based-role-assignment-gate.md, CLAUDE.md

**Verification performed:** mvnw -o compile and mvnw -o test-compile both succeed cleanly. Running the unit tests for RoleAssignmentServiceTest, RoleManagementServiceTest, RateLimitRoleChangeThrottleAdapterTest, JpaUserRoleAssignmentAdapterTest, RbacAuthEventAdapterTest yields 200/200 passing. Integration tests (Testcontainers/Docker-backed) were not executed in this review session; per the story's own EPIC-002.md status note, Phase 8 (/test-validate) and the staging soak are explicitly still pending, consistent with that being out of this review's scope.

---

## Summary of what this diff does

Implements the privilege-based (not name-based) authorization gate for RoleAssignmentService.assign()/revoke(), symmetric across both verbs, plus:
- D13: mint-side holder-count signal on RoleManagementService.attachPermission (detective control for the T-E21 residual)
- D14: a new per-(tenantId, actorUserId) denial throttle (RoleChangeThrottlePort / RateLimitRoleChangeThrottleAdapter)
- D15/D17/D18: precision improvements to alerting and a new composed lock-hold timer
- D16: M7's query hosted on JpaRoleRepository to avoid the assignment adapter gaining write capability
- A native FORCE INDEX query for M5 plus a mechanical EXPLAIN-based test (MC-5) proving the lock-containment claim empirically rather than by assumption

## Overall assessment

This is an unusually rigorous piece of work. The implementation tracks the design document line-for-line: check ordering (Section 6.2), the unified gate condition (Section 6.1/D4), the MC-3 caller/target argument discipline, the D2 lock-acquisition order and its EXPLAIN/isolation-level mechanical proofs (MC-5/MC-6), the D14 throttle's fail-safe/never-throw contract (MC-7), and the D13 mint-side signal are all present in code exactly as specified, and each has a corresponding unit or integration test. The "replace, never delete" Javadoc/threat-model-register discipline is followed consistently across every touched doc. The previously-vulnerable RoleAssignmentEscalationIT test was correctly inverted, not deleted, with a clear explanation of what it now proves and what it explicitly does not (T-E21 is out of scope for that test). There are very few findings, and none are blockers.

---

## Findings

### [Medium] Composed lock-hold timer stops before the transaction actually commits, on the success path
File: nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java:347-366

Problem: nexus.rbac.privileged_revoke_lock_hold{outcome} is designed (03-design.md Section 7.5/D18) to measure the whole interval the X lock (M1) is held, specifically so pool pressure or lock queueing around the final COMMIT is visible in the published p99 figure. For the outcome="revoked" (success) case, stopLockHoldTimer(lockHoldSample, OUTCOME_REVOKED) is called immediately after registerPostCommitSideEffects(...) returns -- but that call only registers an afterCommit synchronization callback; it does not run it, and it does not itself commit anything. The actual COMMIT happens later, when Spring's TransactionInterceptor calls commit() after the @Transactional method returns to the proxy -- i.e. after the timer has already been stopped. The X lock is physically held by InnoDB until that COMMIT completes, so the timer under-measures the true lock-hold duration by the time it takes the method to return through the call stack plus the COMMIT round-trip to MySQL.

Contrast this with the denied/lockout/error outcomes, which stop the timer in a catch block after the exception has already propagated out of the locked-region logic -- those are subject to the same "before the transaction actually rolls back" bias, but for those paths the inline, REQUIRES_NEW audit write -- the step Section 7.5 explicitly calls out as part of the measured interval -- has already completed by the time the timer stops, so they are much closer to accurate. The revoked outcome is the one case where a non-trivial, load-sensitive step (the final COMMIT) happens strictly after the stop point.

Why it matters: Section 7.5/D18 exists specifically because "revision 1 costed the pieces separately and never composed them" was the threat-model finding (RC-9.5) this design revision was required to fix, and the published p99 ceiling (under 50ms) and the "p99 over 250ms over 10m" ticket alert are meant to catch exactly the pool-pressure-or-lock-queueing scenario a slow final commit represents. Missing that step means the instrument is least accurate in precisely the failure mode it was built to detect, on the most common outcome (successful revokes).

Suggested fix: Use TransactionSynchronization's afterCompletion(int status) instead of (or alongside) afterCommit() to stop the timer at actual transaction completion for the revoked outcome, keeping the existing inline stopLockHoldTimer calls in the catch blocks for the no-transaction-synchronization test fallback path. Alternatively, document this as an accepted, understood measurement bias in docs/features/US-016/monitoring.md Section 4 (currently marked PENDING anyway) so the staging-soak baseline is not read as more precise than it is.

---

### [Low] .mvn/jvm.config added without design-doc or PR-level justification
File: nexus-backend/.mvn/jvm.config (new)

Problem: Adds -Xmx4096m -XX:+UseParallelGC -XX:TieredStopAtLevel=1 for the Maven build JVM. This file is not listed anywhere in 03-design.md Section 15's "Files this design implies" (which is otherwise exhaustive down to individual Javadoc edits), and there is no comment in the file or elsewhere in the diff explaining why it is needed now.

Why it matters: Per CLAUDE.md's "surgical changes" principle, every changed line should trace to the request; a build-tuning file with no stated rationale is the kind of change a future reader (or git blame archaeologist) cannot evaluate -- was it needed because RoleAssignmentServiceTest grew to roughly 2,300 lines and started OOMing forked test JVMs, or is it unrelated infrastructure work that landed on this branch by accident? Either is plausible given the scale of this PR's test suite growth, but it should say which.

Suggested fix: Add a one-line comment in the file (or the PR description) stating the trigger, e.g. "increased heap to accommodate the concurrency-IT-heavy RBAC test suite growth in US-016."

---

### [Nit] recordDenial naming collision between two unrelated concepts
File: nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java:481-505, 637-661; RoleChangeThrottlePort.java:53

Observation: throttlePort.recordDenial(tenantId, actorUserId) (throttle bookkeeping, boolean return) and the service's own private recordDenial(actor, targetUserId, roleId, ...) (durable audit-row write, void) are both named recordDenial, and the private method recordThrottleDenialAndMaybeWarn calls the former and is itself invoked immediately before the latter. It is unambiguous today because the two are always called through different receivers/signatures, and the names are individually well-chosen for what they do -- but "denial" is being recorded twice, under the same verb, for two different subsystems, in the same 15-line block. Not asking for a rename here -- just flagging it as a place worth a short comment if it ever gets touched again.

---

## What was checked and found solid (worth calling out)

- Gate correctness vs. design (Section 4.1/6.1): the unified nameMatch OR carriesDangerousPermission(...) condition, name-first short-circuit, single call site of hasActiveAdminAssignment, and fail-closed-on-empty-M8 behavior all match the design exactly, in both assign() and revoke().
- MC-3 (RC-14): every privilege-path unit test sampled uses a target role id/user id deliberately different from the admin role id/actor id, with explicit never() verifications on both argument axes -- this is the control that prevents T-E22's two fail-open bugs from compiling silently, and it is exercised thoroughly (109 matches across the test file).
- Lock ordering (D2/Section 7.2): revoke() acquires M1 (X) before the gate's M5 (S) read whenever nameMatch is true, exactly as designed; M7 (permission read) is proven to run outside the locked region on every path. The native FORCE INDEX (fk_user_roles_role) query for M5, with a mutation-tested EXPLAIN-based IT asserting the actual chosen index, is a genuinely strong mechanical control -- it turns an optimizer-dependent proof into something CI enforces rather than something a comment merely asserts.
- Concurrency harnesses (LastAdminLockoutIT A/B/C): real 8-thread/CyclicBarrier/Testcontainers races, not simulated. Harness C's explicit decision to drop a concurrent assign(TENANT_ADMIN) thread rather than hide a real, reproduced, pre-existing deadlock (RES-10) behind a broader catch is the right call and is documented honestly in the test's own Javadoc.
- D14 throttle: fails safe on every exception path (isThrottled/recordDenial in both RoleAssignmentService and the adapter itself), never able to permit -- only to add an extra 403 -- and its interaction with the concurrency ITs is defused correctly via a max-denials override property rather than leaving a latent test flake.
- RoleAssignmentEscalationIT inversion: the previously-vulnerable test asserting the exploit now asserts the denial, with a clear Javadoc boundary explaining it is not T-E21 evidence (that is DangerousPermissionHolderSignalIT, a separate, well-targeted new test).
- D17/D13 audit metadata: operation/holderCount are correctly omitted-when-null (never serialized as JSON null), and the audit_write_failed metric's operation="deny" tag is deliberately kept separate from the new operation metadata field -- both the code and its Javadoc are explicit that these are different axes.
- Hexagonal architecture (ADR-0002): RateLimitRoleChangeThrottleAdapter correctly lives in identity.infrastructure.security implementing an rbac-declared port, keeping the identity-to-rbac dependency direction consistent with the existing RbacAuditPort/UserDirectoryPort precedent.
- RbacDangerousPermissions/RbacRoleNames: confirmed unchanged, as the design requires, and RbacDangerousPermissions.contains is already case-insensitive/null-safe.
- No migrations, no new grants, no DTO/wire changes -- confirmed; the diff touches exactly the files 03-design.md Section 15 said it would (plus the undocumented jvm.config, see Low finding above).
- Unit test suite (200 tests across the 5 core changed/new classes) passes cleanly when run offline against the existing local Maven cache.

---

## Summary

Findings by severity: Blocker: 0, High: 0, Medium: 1, Low: 1, Nit: 1.

Verdict: APPROVE WITH NITS.

The Medium finding (lock-hold timer stopping before actual commit on the success path) is real and worth fixing or explicitly documenting as a known measurement bias before the staging-soak baseline in docs/features/US-016/monitoring.md is finalized, but it affects only the accuracy of an internal SLO/alerting instrument, not the correctness or security of the gate itself, and does not block merge. The jvm.config addition should get a one-line justification. Everything else -- the actual privilege gate, its symmetry, its concurrency safety, its fail-closed/fail-safe behavior, and its test coverage -- is implemented exactly as the (extremely thorough) design specifies, and the unit test suite is green.
