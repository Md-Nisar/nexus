# US-014 Code Review — Audit role assignment and revocation events

Branch: feature/US-014
Reviewer: code-reviewer sub-agent (fresh context)
Scope: uncommitted diff covering the US-014 implementation surface (build-cache/CVSS/Maven-wrapper/hook-path changes on this branch are unrelated branch-hygiene work and are excluded)

## Findings

### [Medium] Orphaned Javadoc comment mis-attaches to the wrong method
File: `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java:354-382`

The pre-existing Javadoc block documenting `registerPostCommitSideEffects` (the `afterCommit` inline-fallback invariant) was left in place, and the new `recordDenial` method plus its own Javadoc were inserted directly **between** that comment and the method it actually describes:

```java
  /**
   * Runs {@code sideEffects} (cache evict + audit) after the enclosing transaction commits. ...
   */
  /**
   * Emits a {@code ROLE_ASSIGNMENT_DENIED} audit row for a 403 authorization denial (US-014 AC4).
   ...
   */
  private void recordDenial(...) { ... }

  private void registerPostCommitSideEffects(Runnable sideEffects) { ... }
```

Javadoc tooling and IDEs attach a doc comment only to the declaration it immediately precedes, so the first block is now a dangling comment sitting above `recordDenial`, and `registerPostCommitSideEffects` — a method whose semantics (afterCommit-vs-inline fallback) are load-bearing enough that other Javadoc in this same class explicitly warns about them — has silently lost its documentation.

Why it matters: a future reader skimming top-to-bottom will misread the first comment as applying to `recordDenial` (which is wrong — `recordDenial` is *not* post-commit, it's the opposite: inline, pre-throw, which its own correct second comment says).

Suggested fix: move the `registerPostCommitSideEffects` Javadoc back to sit directly above `registerPostCommitSideEffects`, e.g. place `recordDenial` (with its own Javadoc) either before both existing methods or after `registerPostCommitSideEffects`, not wedged between a comment and its subject.

### [Low] `RbacAuditPort`'s class-level contract doc is now only half-true
File: `nexus-backend/src/main/java/com/example/nexus/rbac/application/port/out/RbacAuditPort.java:11-15`

The interface-level Javadoc states as a blanket contract: "Callers invoke these methods after commit (or, absent an active transaction, inline as a best-effort fallback) and do not handle exceptions from them." That was accurate when the interface had only the two post-commit success methods. `recordRoleAssignmentDenied`'s own method-level Javadoc (correctly) describes the opposite invocation timing — inline, pre-throw, from a transaction that is about to roll back — which contradicts the class-level statement above it.

Why it matters: a reader who only reads the type-level Javadoc gets a wrong mental model for one of the three methods. Documentation-accuracy nit, not a functional bug — the method-level doc is correct and overrides.

Suggested fix: soften the class-level sentence to something like: "Callers invoke the two success methods after commit (or inline as a fallback absent an active transaction); `recordRoleAssignmentDenied` is invoked inline, pre-throw, before the caller's transaction commits or rolls back — see its own Javadoc."

## Things verified correct

- **Three denial call sites are correct and complete.** `assign()`'s `try/catch` around T1/T2 and inline T3 emission, and `revoke()`'s `try/catch` around T1/T2, exactly match `03-design.md` §3.3 and `04-tasks.md` §0.1's authoritative scope table. `roleName` is `null` at T1/T2 (by construction) and populated at T3. `catch (InsufficientPermissionException e)` structurally excludes the two 409s (`DuplicateRoleAssignmentException`, `LastAdminRoleException`) and the 404s (`ResourceNotFoundException`) — verified none of those types is assignable to `InsufficientPermissionException`. `listActive()` has zero diff, as required.
- **Durability claim (`REQUIRES_NEW`) is real and correctly exercised.** `recordDenial` runs synchronously before the throw, never through `registerPostCommitSideEffects`. New `RoleAssignmentAuditIT` tests assert on the DB row **after** `assertThatThrownBy(...)` completes — the only assertion shape that actually proves survival across TX1's rollback.
- **`AuthEventType.PRIORITY` exclusion rationale is framed correctly** — "cost-and-uniqueness per row, not mere triggerability by an authenticated caller", matching the corrected Gate-2 framing, both in the enum comment and verbatim in the ADR-0011 §8 amendment. `EnumSet` body and `isPriority()` untouched.
- **Metadata JSON ordering is correct** — `traceId, roleId, roleName, reason, attemptedBy`, with `reason` between `roleName` (attacker-influenceable) and the actor field per design §4.2's duplicate-key defense-in-depth rationale. Pre-existing `traceId`-injection detector test is explicitly protected by a "do not retire" comment.
- **Test quality is strong** — value-equal `RbacAuditEvent` matchers, load-bearing negative assertions explicitly flagged, `listActive` exclusion pinned with `verifyNoInteractions(rbacAuditPort)` and a T-E14 comment, and the four pre-existing `outcome == "SUCCESS"` assertions flagged load-bearing given `record(...)` now takes a parameterised `outcome`.
- **No architecture/ArchUnit violations** — `DenialReason` import stays within `common.security`; `AuthEventType` selected only inside the adapter; no new `rbac → identity` import; `RbacAuditEvent` unchanged (6 components, no widening).
- **No PII exposure, no new logging risk** — no new log statement at the throw sites; new metadata fields carry only UUIDs and an enum name.
- **T-D6/T-D7** are pre-existing, explicitly-accepted-at-Gate-2 residuals; correctly untouched and deferred to ops config / US-015.

## Summary

- **Blocker:** 0
- **High:** 0
- **Medium:** 1
- **Low:** 1

**Verdict: APPROVE WITH NITS**

The implementation is a faithful, well-scoped translation of the design and correctly incorporates every Gate-2 wording correction into the actual shipped comments/ADR text. Both findings are documentation-hygiene issues with no runtime impact — worth a quick follow-up fix but not blocking.

Relevant files:
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java`
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/port/out/RbacAuditPort.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/infrastructure/audit/RbacAuthEventAdapter.java`
- `nexus-backend/src/main/java/com/example/nexus/identity/domain/AuthEventType.java`
- `nexus-backend/src/test/java/com/example/nexus/rbac/application/RoleAssignmentServiceTest.java`
- `nexus-backend/src/test/java/com/example/nexus/identity/infrastructure/audit/RbacAuthEventAdapterTest.java`
- `nexus-backend/src/test/java/com/example/nexus/rbac/RoleAssignmentAuditIT.java`
- `nexus-backend/src/test/java/com/example/nexus/identity/domain/AuthEventTypeTest.java`
- `docs/adr/0011-in-process-bounded-retry-buffer-for-audit-writes.md`
