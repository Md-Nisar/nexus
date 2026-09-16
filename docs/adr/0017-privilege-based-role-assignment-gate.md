# ADR 0017 — Privilege-Based (Not Name-Based) Authorization Gate for Role Assignment and Revocation

**Status:** Accepted
**Date:** 2026-09-13
**Feature:** EPIC-002 (RBAC Foundation) — US-016; extends ADR-0013 D1/D3; **partially** closes a residual accepted at US-015's Gate 2
**Related:** `docs/features/US-016/03-design.md`, `docs/features/US-016/03b-threat-model.md`, `docs/features/US-015/03b-threat-model.md` (RES-1, T-E16, T-E17), `docs/adr/0013-rbac-data-model-and-enforcement-contract.md` (not modified by this ADR)

---

## Context

`RoleAssignmentService.assign()` has, since US-012, gated the grant of the `TENANT_ADMIN` role on the caller holding an active `TENANT_ADMIN` assignment (AC8), implemented as a **case-insensitive comparison against the role's name**. `revoke()` has no equivalent gate at all.

US-015 made that name comparison insufficient. It lets a tenant administrator attach any permission — including `role:write`, `user:write`, `tenant:write` (`RbacDangerousPermissions.NAMES`) — to any custom role, gated by an admin check on the *attach* side (AC11). A role that is **not** named `TENANT_ADMIN` can therefore legitimately carry admin-equivalent authority. Because the assignment gate matches on name only, any holder of `user:write` can grant that role to anyone including themselves, with the gate never firing (T-E16), or strip an administrator's role entirely (T-E17). US-015's Gate 2 accepted this as a documented residual (RES-1 / R-3), compensated it with detection counters, and forward-tracked it to US-016 with an explicit note that closing it "requires an ADR" because it changes the authorization contract of a shipped API.

This is that ADR. Five decisions were made; each had a cheaper-looking alternative that was rejected for a stated reason.

---

## Decision

### D1 — The gate tests privilege, symmetrically, and additively

`assign()` and `revoke()` both deny the operation unless the caller holds an active `TENANT_ADMIN` assignment **in the same tenant**, whenever the target role either (a) is literally named `TENANT_ADMIN` (case-insensitively — ADR-0013 D1's naming convention plus `utf8mb4_0900_ai_ci`) **or** (b) carries at least one permission in `RbacDangerousPermissions.NAMES`.

- **One condition, one call site, one denial.** Not two chained checks: the seeded `TENANT_ADMIN` satisfies both halves, and two independent checks would double-deny and double-audit.
- **Symmetric by decision, not omission.** Gating only `assign()` would leave a hole in which a non-admin can *strip* administrators — which US-015's threat model rated worse than fixing neither verb.
- **Additive.** The name match is retained and evaluated **first**, short-circuiting the permission read, so the pre-existing gate's behaviour does not depend on any new code path.
- **The admin check is a fresh, locking read on the caller** (`PESSIMISTIC_READ`), never derived from a JWT claim (T-E7), and the tenant's admin role id is resolved by a `(tenantId, name)` lookup that **fails closed** when empty (the R-10/T-E18 precedent). **Both arguments to that check come from the caller, never the target** — passing either from the target fails open, so both are pinned by unit assertions rather than by review.
- **Enforcement stays in the service layer.** `@RequiresPermission` / `TenantAwarePermissionEvaluator` compare flat JWT `permissions[]` membership and cannot express this rule (ADR-0013 D3's contract is about *response shape*, not about where the decision is made).

**Rejected:** deriving "is this role privileged?" from `is_system_role` (orthogonal — a custom role is not a system role but can be dangerous); computing it from the JWT (stale, and the caller's claims say nothing about the *target role*); gating only self-assignment (a non-admin granting a privileged role to a confederate is the same escalation).

### D2 — Two narrow reads on `UserRoleAssignmentPort`, not an injection of `RoleManagementPort` — and no write capability at the adapter layer either

The gate needs two capabilities: the target role's permission names, and the tenant's `TENANT_ADMIN` role id. Both are added to the port `RoleAssignmentService` already depends on, as read-only methods. `RoleManagementPort` is **not** injected: it exposes `createRole`, `attachPermission` and `detachPermission`, so injecting it would hand this service write authority over the very `role_permissions` rows its gate reads — the authority the gate exists to protect. This codebase has rejected that trade twice in writing, and no ArchUnit rule forbids the coupling, so it would have shipped silently.

**The same argument applies one layer down, and is applied there.** The permission read's query is hosted on the repository the persistence adapter **already** injects (`JpaRoleRepository`), not on the `role_permissions` repository — which is a full Spring Data `JpaRepository` and would have handed the *assignment* adapter `save`/`delete`/`deleteAll` over `role_permissions`: the one RBAC table with both `INSERT` and `DELETE` grants, no trigger and no soft delete, i.e. the only one where an accidental write from the wrong layer actually executes. The adapter's constructor therefore gains **zero** dependencies.

Two shape rulings follow: the permission read returns **names**, not a boolean and not a projection, so the "which permissions are dangerous" policy never crosses the port in either direction (stronger than passing the set in as a parameter, and it keeps the case-insensitive comparison inside the already-unit-tested `RbacDangerousPermissions`); and the role-id read is backed by the **same repository method** the mint side already uses, so there is one query and one index-discipline site. The permission read **must not** be a locking read: `nexus_app` holds `SELECT` only on `permissions`, so a locking read would be rejected in production and would pass every Testcontainers integration test.

### D3 — Reuse `DenialReason.NOT_TENANT_ADMIN`; add no enum value; add one counter instead

The privilege-path denial reuses the existing reason. The enum classifies **why the caller was denied** — identical on both paths. **Why the gate applied** (role name vs. dangerous permission) is a property of the target role and is carried by `matchedOn` on a new WARN marker **and on a new counter** `nexus.rbac.privileged_role_change_blocked{operation, matchedOn}`.

Reasons: it keeps the enum's deliberately bounded cardinality on one axis; and, decisively, the existing alert `nexus_rbac_self_escalation_attempt` (`increase(nexus_rbac_permission_denied_total{reason="NOT_TENANT_ADMIN"}[5m]) > 0`) keeps matching every denial the new gate produces with **zero PromQL edits**. A sixth value would have required editing that expression in the same change; forgetting it would have meant the new gate's denials page nobody — a detection regression created by the fix itself.

That property is preserved **as a floor, not as the whole answer.** Reusing the reason also widens a page-severity population from a near-zero-base-rate attack to include routine, correctly-denied offboarding attempts by non-admin operators, on two verbs. A log field cannot re-tier a pager. So the expression stays byte-identical and drops to ticket, and **page severity moves to the new counter's high-signal shape** (`matchedOn="DANGEROUS_PERMISSION"`). Detection coverage is unchanged; detection precision is restored. Both alerts are renamed, because after this story their old names no longer describe what they match.

*(Note for future readers: `DenialReason` is a log/metric/audit dimension only — it is **not** part of the 403 response body, which carries `code`, `traceId` and `requiredPermission`.)*

### D4 — On `revoke()`: the 403 gate precedes the 409 lockout, and the exclusive lock is acquired first

**Decision order — authorization (403) before the last-admin lockout (409).** An authorization outcome must not depend on business state; the 409 discloses "this is the tenant's last active admin" and must not be handed to a caller who is about to be rejected anyway (this removes a real pre-existing information leak); and it mirrors `assign()`, where the admin gate already precedes the duplicate-assignment 409.

**Lock order — the `PESSIMISTIC_WRITE` set lock is acquired before the gate's `PESSIMISTIC_READ`.** On the `TENANT_ADMIN` path the lockout guard's row set and the gate's row necessarily overlap on the legitimate path, so taking the shared lock first and the exclusive lock second is the classic S→X upgrade deadlock. Acquiring the exclusive set lock first makes the subsequent shared read a lock this transaction already holds in a stronger mode, and leaves `revoke()`'s *first-acquired* lock identical to today's, so no new cross-method cycle is introduced. Promoting the gate's read to `PESSIMISTIC_WRITE` was rejected: it does not fix the cycle between two *different* admins revoking each other, because the defect is acquisition order, not lock mode.

**Two dependencies of that proof are stated rather than assumed**, because both are decided outside the source file: InnoDB locks **index records**, not logical rows, so containment holds exactly only if both statements use the same access path — asserted by an `EXPLAIN` integration test; and the serialization claim requires **REPEATABLE READ** gap locking — asserted by a `SELECT @@transaction_isolation` check in the concurrency test.

**Consequence, recorded because a documented resolution changes meaning:** once the gate is symmetric, the last-admin lockout's actor-agnostic scenario ("a *different* caller revokes the tenant's last admin") becomes **structurally unreachable** for the `TENANT_ADMIN` role. The guard's code and its actor-agnostic property are unchanged; its *reachable population* narrows to self-revocation. Note that this is also a **strengthening**: the ≥1-active-admin invariant is now enforced earlier and more strongly, by the gate rather than by the guard — the guard must **not** be deleted as dead code, because it remains the last defence if the gate is ever weakened or bypassed by a new call path. US-012's AC5 documentation and Gate 1 Resolution 5 are amended accordingly, and one integration test changes from asserting 409 to asserting 403.

### D5 — This story closes the propagate side; it does not close the attach-after-assign path, and it says so

The gate evaluates at assign/revoke time. A user may hold a role that is benign today and is made admin-equivalent tomorrow by an administrator attaching a dangerous permission to it — a legitimate, Epic-3-required action. **No gate evaluates at that moment, and the escalation is silent at both ends.** It requires no race, no collusion, and no privilege the holder did not already have. This ADR therefore records **T-E16 as closed for the direct propagate path only**, and **T-E17 as closed outright**; the attach-after-assign path is carried forward as a named residual with an owner, a review date and an Epic-3 hard expiry.

**Mitigation shipped here (detection, not prevention):** on the mint side, when a **dangerous** permission is attached, `RoleManagementService.attachPermission` counts the role's existing active holders (reusing a port method that already exists for the remediation runbook) and emits that count on the durable `ROLE_PERMISSION_GRANTED` audit event, on a WARN marker when it is non-zero, and as a bounded bucket tag on the existing counter. One bounded query, on a rare, already-admin-gated path; no schema change, no new port, no new gate, no status-code change.

**Rejected:** blocking the attach when holders exist (a functional regression on a legitimate administrative action, for a risk detection addresses); re-validating every existing assignment at attach time (the right eventual answer, materially larger than this story, and it needs its own decision about what to do with the assignments it finds); deferring the signal to a successor story (it leaves a standing, zero-signal escalation primitive open across the Epic-3 kickoff that the residual's own expiry clause names).

**Also rejected, and worth recording:** making the denial path unbounded. Both verbs are deliberately un-rate-limited, which was defensible when the only reachable denial was "a non-admin tried to grant literal `TENANT_ADMIN`" — an event with a near-zero base rate. This story makes the denial population much larger, and each denial costs an exclusive lock over the tenant's admin rows, two reads, a nested transaction on a second pooled connection, a durable audit row and an alertable metric. A per-`(tenant, actor)` **denial** throttle — not an endpoint rate limit — bounds all of that, fails safe (it can only ever produce the same 403 the gate would), and reuses the platform's shipped sliding-window store rather than introducing a dependency.

---

## Consequences

**Benefits:** the direct propagate path of the escalation chain (T-E16) and administrator stripping (T-E17) are closed in code rather than compensated by alerting; the gate cannot be defeated by naming a role something other than `TENANT_ADMIN`; a pre-existing information leak on `revoke()` is removed; `RoleAssignmentService` keeps exactly one persistence port and gains no write capability, and neither does its adapter; the existing detection floor keeps working with no PromQL edit while page precision improves; the surviving escalation path becomes visible at the moment it is created; no migration, grant, dependency, endpoint, DTO or frontend change.

**Trade-offs:** two shipped verbs get stricter, and three behaviours break by design (both flag-gated, both flags default-off, so the production blast radius at deploy time is zero); `revoke()` gains up to two reads and, on the admin path, its first locking read pair, whose ordering is a correctness requirement enforced by concurrency tests and two mechanical assertions rather than by the compiler; the denial metric remains coarse by design and precision is carried by a second instrument; an actor who produces repeated denials is briefly denied benign role changes too; the enforcement remains "check at the moment of assign/revoke", so a role that becomes dangerous after an assignment exists is **not** re-validated — only reported.

**Follow-on rules for future work:**
- Any future "is this role special?" decision in `rbac` must be expressed as a test over the role's **permissions**, not its name. A name comparison is acceptable only as an additive, short-circuiting fast path for the seeded system roles, never as the whole rule.
- **That rule is applied to the *target* role only. The *caller*-side admin test deliberately remains name-based** — the gate asks whether the caller holds the literally-named `TENANT_ADMIN` role, not whether they hold an admin-equivalent set of permissions. This asymmetry is a decision, not an oversight: it matches US-015 AC11, which gates the mint side on the same literal role. Its cost is recorded as US-016 RES-9 — a user holding a custom role that carries all three dangerous permissions is *subject to* this gate but can never *pass* it. Making the caller-side test privilege-based is a separate, larger decision that belongs with RES-3; do not assume this ADR made it.
- Any new read added for an authorization decision must state its lock mode explicitly and be checked against `nexus_app`'s actual grants — a locking read on a `SELECT`-only table fails in production and passes every test.
- When a transaction takes more than one row lock, the acquisition order must be documented at the call site and proved by a multi-threaded integration test, not reasoned about in review — **and the proof must name the index access path and the isolation level it depends on, both asserted mechanically.**
- A control that closes an escalation path must record, in the same change, what it does **not** close. Flipping a risk-register entry to "closed" when only one of its paths is closed deletes the record of the survivor.
- Last-admin-style lockout protection still covers only the literally-named `TENANT_ADMIN`. Extending it to admin-equivalent custom roles is tracked separately (US-016 RES-3); do not assume this ADR covers it.

---

## Appendix — provenance and decision-numbering map

_This appendix is navigational only. It records **no** decision and is **not** part of what was accepted above; it exists so a reader can check this ADR against its source without re-deriving the mapping._

**Provenance.** Everything from the title line down to the end of "Follow-on rules for future work" is the verbatim text approved at Gate 2 as `docs/features/US-016/03-design.md` §13.2, reproduced without paraphrase — the rejected-alternatives records in D1, D2, D4 and D5 are the part of this ADR that has value in two years, and paraphrasing them would lose them. Two changes were made in transcription, both non-semantic: the `**Date:**` field carries the merge date (2026-09-13) rather than §13.2's drafting date of 2026-09-10, per §13.1's instruction that the accepted date **is** the merge date; and `---` section rules were inserted to match the house ADR template (0013, 0015, 0016). No sentence was added, removed or reworded.

**Form.** This is a standalone ADR, not an amendment to ADR-0013 (US-016 design D9). ADR-0013 is **not** edited and gets no second amendment section: US-016 does not correct ADR-0013's D1–D6, it adds a new decision at a different layer that builds on D1 (permission naming) and D3 (the `403` + `RBAC_001` contract). The two have independent lifecycles, and this ADR can be superseded later — if "is this role privileged?" becomes a computed property, or if RES-3/RES-9 are taken up — without touching an ADR four stories depend on. ADR-0001's append-only rule is satisfied; 0017 was the next free number.

**Numbering.** The D1–D5 above are this ADR's **own** local numbering. They consolidate the eighteen numbered decisions in the design body (`03-design.md` §3 / §4 / §7 / §9); no decision below is new here, and none is dropped.

| This ADR | Consolidates design D-numbers | What the consolidation covers |
|---|---|---|
| **D1** — privilege test, symmetric and additive | **D4** (one condition, one call site, name-first short-circuit, M8 fail-closed), **D11** (no new error code — the denial stays `403` + `RBAC_001` + `requiredPermission="user:write"`, which is why enforcement sits in the service and not in `@RequiresPermission`) | The gate itself, its shape, and its response contract |
| **D2** — two narrow reads, no write capability at either layer | **D3** (port choice: two read-only methods on `UserRoleAssignmentPort`, permission **names** not a boolean, `RoleManagementPort` not injected), **D16** (the permission query lives on the already-injected `JpaRoleRepository`; the adapter's constructor gains zero dependencies), **D5** (the permission read is non-locking — a `@Lock` is a production-only failure against `nexus_app`'s `SELECT`-only grant on `permissions`) | Where the two reads live, what they return, and what capability they must not confer |
| **D3** — reuse `NOT_TENANT_ADMIN`, add a counter instead of an enum value | **D6** (no sixth `DenialReason`; the existing alert expression needs zero PromQL edits), **D8** (the new `RBAC_PRIVILEGED_ROLE_CHANGE_BLOCKED` WARN marker), **D15** (the new `nexus.rbac.privileged_role_change_blocked{operation, matchedOn}` counter; page severity moves to it; the old expression stays byte-identical and drops to ticket; both alerts renamed), **D7** (the FR-6 canary's `privileged` and `callerIsAdmin` tags), **D17** (`operation` persisted in the denial's audit metadata, which is what makes the counter's `operation` dimension discriminable after the fact) | The denial's classification and the whole observability story around it |
| **D4** — 403 before 409; exclusive lock acquired first | **D1** (gate/lockout ordering on `revoke()`, and the resulting narrowing of US-012 AC5's reachable population), **D2** (lock order: `PESSIMISTIC_WRITE` set lock first, gate's `PESSIMISTIC_READ` second, with the index-record and REPEATABLE READ dependencies asserted mechanically), **D18** (the denial audit write stays inline inside the locked region but is instrumented, with the *composed* hold time published) | `revoke()`'s ordering, its locking proof, and the cost of the locked region |
| **D5** — closes the propagate side, not the attach-after-assign path | **D13** (the mint-side holder-count signal on `attachPermission` — detection, not prevention), **D14** (the per-`(tenantId, actorUserId)` denial throttle, recorded here as the rejected "leave the denial path unbounded" alternative) | What this story closes, what it does not, and the two compensating controls shipped alongside |

**Design decisions that intentionally have no ADR decision of their own:**

- **D9** (ADR form — standalone, ADR-0013 untouched) is discharged by this file's existence and is recorded under "Form" above rather than as a decision about the system.
- **D10** (no new feature flag; the gate rides the two existing default-off flags, because a dedicated flag's "off" position would *be* the vulnerability) appears in **Consequences → Trade-offs** as the reason the deploy-time blast radius is zero.
- **D12** (last-admin lockout for admin-equivalent *custom* roles — out of scope per Gate 1 #8, tracked as RES-3) appears in the **final follow-on rule**, which exists precisely so no future reader assumes this ADR covered it.

**Forward pointers.** RES-9 / T-E26 (the deliberate caller-side / target-side asymmetry) is the second follow-on rule. RES-1(b) / T-E21 (the surviving attach-after-assign path) is D5 and the fifth follow-on rule; its owner, `2026-11-27` review date and Epic-3 hard expiry are carried in `docs/features/US-016/03-design.md` §12.3, not here — an ADR records the decision, the risk register tracks the residual.
