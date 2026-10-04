# ADR 0021 — Grant-Subset Authorization Model for Role Assignment and Role Definition

**Status:** Proposed (Revision 1: threat-model RC-23, RC-25 to RC-28 and RC-38 folded in, 2026-09-26; Revision 2: delta review RC-48 and RC-50(a)/(b) folded in, 2026-09-30)
**Date:** 2026-09-26
**Feature:** EPIC-002 (RBAC Foundation), US-018 milestones M2 (A1–A4) and M3 (A5)
**Supersedes in part:** ADR-0017 D1, D3, D5; ADR-0018 D1, D2, D3, D8, and the population of D4; amends ADR-0013 D1 (naming). Bodies of accepted ADRs are not edited (ADR-0001).
**Related:** `docs/features/US-018/01-requirements.md` §14, `02-impact.md`, `03-design.md` §2.1, §4, §5

---

## Context

US-015 through US-017 protected the role-assignment path with three layers of predicates: the literal name `TENANT_ADMIN`, "ANY of three dangerous permissions" on the target side, and "ALL three" on the caller side, plus tenant-wide lock sets, canaries and detective signals. Two escalation residuals remained open by the project's own register: US-016 RES-1(b)/T-E27 (self-assign a benign role, then wait for an administrator to make it powerful) and US-017 RES-13 (the attach gate is name-based). The root cause was that `user:write` meant both "edit users" and "manage role assignments", and that the epic never adopted the standard rule used by Kubernetes RBAC and AWS IAM permission boundaries: **a caller may only grant what they already hold.**

## Decision

### D1 — Role assignment is its own permission: `user:role:assign`

A new code-seeded permission gates `POST` and `DELETE /api/v1/users/{userId}/roles`. `user:write` keeps only "edit user accounts". V6 seeds the permission and grants every missing permission to every tenant's system `TENANT_ADMIN`, which is the first instance of the B7 footer. There is **no backfill** to custom roles that hold `user:write`; a pre-deploy detection query is a runbook step, because a backfill would carry the old conflation into new data.

**Admin-defining preservation (Revision 1, RC-27.1).** The B7 footer, V6 included, also attaches the permissions a migration inserts to every role, system or custom, that carried **every permission of the pre-migration catalogue**. This is **not** the backfill rejected above: it touches only roles that were already full stand-ins for the catalogue, whose holders were already administrators by D3, and a role holding `user:write` without the whole catalogue receives nothing. Without it, every permission-adding migration would demote working custom administrators, and because A3 forbids attaching a permission the attacher does not hold, a tenant whose administrators were custom-only could not repair itself (recovery would need break-glass, available only where a system `TENANT_ADMIN` is seeded). The B7 scanner and the `RbacSchemaMigrationIT` footer test cover both footer statements.

**Checkable footer (Revision 2, RC-48).** The preservation statement's exclusion list (the ids the migration inserts) differs per file, so the footer is published as a **template with one placeholder**, that id list. The scanner asserts that the preservation statement's exclusion list equals **exactly** the ids inserted by the same file, and that from V9 on it filters `deleted_at IS NULL`. A footer copied verbatim from an earlier migration therefore fails the build instead of silently attaching nothing. Every permission-adding migration's IT seeds a full-catalogue custom role and asserts it gains the new permission.

**Naming amendment to ADR-0013 D1.** A three-token name is permitted only where the middle token names a relationship between two catalogue resources (here, user-role membership). It still carries no hierarchy or wildcard semantics. `role:assign` was rejected: `role:*` permissions govern role *definitions*.

During the M2→M3 interim `user:role:assign` is **not** added to `RbacDangerousPermissions`. Adding it would silently shrink the ALL-three caller population and the lockout population.

### D2 — Grant-subset on assign (A2) and attach (A3)

- `assign()` denies with 403 `RBAC_001` unless the target role's permission ids are a subset of the caller's held permission ids.
- `attachPermission()` denies unless the caller holds the permission being attached. This applies to **every** permission, not only the formerly dangerous ones.
- The caller's holdings come from one live DB read inside the write transaction. That read returns `(roleId, permissionId)` rows and is named for authorization. It is **never** the JWT, and **never** the canary read that is documented as unfit for authorization.
- Permissions are compared by **id**, which removes the case-insensitive name comparison and keeps names off the port (ADR-0017 D2, ADR-0018 D3 upheld).
- The read is a non-locking `REPEATABLE READ` snapshot. A locking read on the caller's rows driven by `fk_user_roles_user` would be a new acquisition outside the set-lock region (ADR-0018 D6).
- **Administrator status on the set-lock path comes from the set lock's own rows (Revision 1, RC-25.1).** The snapshot's read view is created at the transaction's first consistent read, which can predate a wait on the set lock. So on every request that takes the set lock (an admin-defining target: assign, revoke, the break-glass CLI; from M3), the caller's administrator status is computed from the rows the single-statement set lock returns: current and X-locked, the caller being an active holder in that result. It is never computed from the snapshot. This costs no extra read, and it restores US-017 D8's containment (T-E7) without the M5b read. The snapshot remains the source only for the subset comparisons.
- A read failure propagates as a 500 and never allows the request.
- A role with no permissions passes (it grants nothing).

### D3 — One definition of "administrator"

A role is **admin-defining** iff it carries every permission in the catalogue. A user is an **administrator** iff they hold an active admin-defining role. The definition is per role, not the union across roles. It is used by A4 (from M2) and, from M3, by the last-admin lockout, the zero-admin health indicator, the break-glass CLI's precondition and `listActive` redaction.

- A caller who holds everything cannot be escalated by any later attach, so their self-assignment is provably harmless.
- Names stop mattering: `TENANT_ADMIN` qualifies because the B7 footer guarantees its contents.
- **Union versus per role (Revision 1, RC-26).** Grant bounds ("could the caller have granted this?") use the **union** of held permissions: A2, A3, and the subset part of revoke-subset and role-subset. Every administrator question uses **this per-role definition and nothing else**, including the extra requirement D5 applies on admin-defining targets. A union-holder is therefore not an administrator anywhere.

### D4 — No self-assignment for non-administrators (A4), and precedence

- A caller who is not an administrator cannot assign any role to themselves.
- Order inside `assign()`: tenant 404 checks, then the throttle, then the legacy gate (M2 only), then A4, then A2, then the duplicate 409.
- One `ROLE_ASSIGNMENT_DENIED` row per request, carrying the first reason (`REQUIRES_NEW`, ADR-0009).
- `DenialReason` gains `SELF_ASSIGNMENT` and `GRANT_EXCEEDS_CALLER`.
- The 403 body's `requiredPermission` is always the endpoint permission, never the missing one, so it is not an oracle on a role's contents.
- The break-glass path never calls `assign()`, so A4 needs no exemption (see ADR-0025).

### D5 — Revoke-subset and role-subset replace the ANY/ALL gates (M3)

- **Revoke-subset:** to revoke role R, the caller must hold every permission of R. **When R is admin-defining, the caller must also be an administrator** (D3), evaluated from the set lock's rows (D2). So a non-administrator, including a union-holder, cannot strip an administrator, and T-E17 stays closed.
- **Role-subset:** to detach any permission from role R, the caller must hold every permission of R. **When R is admin-defining, the caller must also be an administrator through a role other than R** (from the snapshot's per-role sets), so no single detach removes the last administrator status the caller relies on. A non-administrator cannot demote an admin-defining role, which is US-017 D13's intent expressed without names. Role-subset also bounds the role lifecycle operations (US-018 C1: `PATCH` and `DELETE` on a role).
- **Decision record (Revision 1, RC-26.2).** Both administrator requirements are adopted, as Security recommended. They make "administrator" mean one thing in every administrator decision, they close the non-self zero-administrator detach that retiring D13 would otherwise open, and they cost no extra read. The only callers newly denied are union-holders, who can ask an administrator.

### D6 — The last-admin lockout and its lock protocol are kept, re-scoped (M3)

- The distinct-holder invariant (ADR-0018 D4) now counts holders of admin-defining roles, and the lock set is the tenant's admin-defining role ids plus the target role id.
- ADR-0018 D5, D6 and D7 (a single ascending statement in unsigned-byte order; containment; RES-10 closure, with assign taking the lock first when the target is admin-defining) are **upheld**.
- The H-1 caller-qualifying filter is removed, because the lock population and the holder population are now the same set.

### D7 — Retirement ledger (M3)

The design's §5.1 is the authoritative, row-by-row list.
- **Removed:** the ANY/ALL predicates and their domain types; the name-based attach and detach gates; the self-assignment canary's M12 mechanism and tags, and M12 itself; the "admin minted by a non-named admin" signal; `privileged_role_change_allowed{callerMatchedOn}`.
- **Replaced, not retired (Revision 1, RC-28):** the canary becomes an **independent runtime check**. On every successful self-target assign, one non-locking statement that does not use the snapshot read is captured before the INSERT. It groups by role, `GROUP BY ur.role_id HAVING COUNT(DISTINCT rp.permission_id) = (catalogue count)`, driven by `fk_user_roles_user`, and carries its own tenant (`r.tenant_id = ur.tenant_id`), active-assignment and soft-delete predicates (Revision 2, RC-50(b)). A union-level count would page on every union-holder. Disagreement with A4 raises the paging `RBAC_SELF_ASSIGN_ADMIN_DISAGREEMENT`, and the page alert `nexus_rbac_gate_bypass_canary` is kept, re-pointed at it. The reason: the snapshot read feeds A2, A3, A4, revoke-subset and role-subset together, so an over-broad read would fail open on all five at once, and unit tests are no substitute for an independent derivation (US-016 M-2, US-017 T-E29). An IT (MC-H') also asserts that the snapshot's per-role partition equals the per-role read. The untagged `self_role_assignment_total` counter and its ticket are dropped: after A4 they fire only on legitimate administrator self-assignments.
- **Kept and re-derived:** the lock-hold timer and lock-set-size summary; the holder-count signal on attach, **extended with provenance** (Revision 1, RC-23.2: ticket when holders were assigned by non-administrators, page when the attach is escalating); the "role became admin-defining" signal (paged when the role already has holders); the zero-admin health indicator.

### D8 — Narrow assignment-provenance rule on attach (Revision 1, RC-23.3)

An attach of P that would make role R **admin-defining** is refused with 409 `RBAC_010` while R has an active holder whose assigner is not currently an administrator. The administrator revokes (or has an administrator re-assign) those holders first. **Condition, stated exactly (Revision 2, RC-50(a)):** R is **not** admin-defining now **and** M14(R) ∪ {P} ⊇ M15 (R's permission ids plus P cover the catalogue). A duplicate attach to a role that is already admin-defining therefore still gets `RBAC_005`.

- **The general rule was rejected.** Security's candidate refuses *any* attach of P to R while R has a holder assigned by someone who does not hold P. That would block routine catalogue maintenance on every widely held role that delegated assigners hand out, which is exactly what D1 enables. "Re-assign" is not an operation (`user_roles` is append-only), so clearing the block would mean a revoke and assign per holder, for thousands of holders.
- **The narrow rule is adopted** because making a role admin-defining is rare and never routine, so it blocks almost no legitimate work, and it removes RES-26's largest payoff (a second account becoming an administrator) preventively.
- **Residual.** Partial escalations (for example R gaining `user:role:assign` or `role:write`) remain detective, paged by D7's provenance signal. The Architect rates RES-26 **Medium**, and Security confirmed Medium in its delta review. Owner: the Platform Security Owner; **acceptance pending at Gate 2**, re-confirmed at the M3 re-pass.

**Retirement rule:** a test is obsolete only if this ADR names the control that now enforces its assertion **and** an equivalent test against that control lands in the same change.

## Relationship to ADR-0017 and ADR-0018

| Superseded point | Replacement |
|---|---|
| ADR-0017 D1 (privilege test on the target: name OR ANY dangerous; caller must be `TENANT_ADMIN`) | D2 (assign), D5 (revoke) |
| ADR-0017 D3 (reuse `NOT_TENANT_ADMIN`, no new enum value) | D4. Two new values are justified: they classify different caller failures, and the M2 alert rules are written for them in the same change |
| ADR-0017 D5 (attach-after-assign path left open) | D4 closes the literal **self-target** step. The primitive survives through a second account (RES-26, below), reduced by D7's provenance signal and D8 |
| ADR-0018 D1/D2 (two predicates; ALL-three caller test; the vacuity proof resting on "every caller holds `user:write`") | D3. The vacuity premise is void after D1, and the interim legacy gate remains fail-closed |
| ADR-0018 D3 (names may not cross the port) | moot: after D2 no names are passed at all |
| ADR-0018 D4 population | D6 |
| ADR-0018 D8 (name-based detach gate) | D5 (role-subset) |

ADR-0017 follow-on rules 1, 3, 4 and 5, and ADR-0018's follow-on rules on lock order, the benign harness thread, and bounding a lock taken before an authorization decision, are **upheld**.

## Consequences

**Benefits:**
- Covers every current and future permission automatically.
- Closes the literal self path of RES-1(b), and closes RES-13. RES-1(b) is reported in EPIC-002 as **"self path closed; transformed into RES-26"**, not as fully closed.
- Collapses four notions of "admin" into one.
- `RoleAssignmentService` loses the predicate machinery (the measurable proxy: no symbol from the retired types is referenced from `rbac.application`).

**Trade-offs:**
- The benign assign path gains two indexed reads (budget: under 10 ms p95).
- **Intended loosening:** a partial administrator can now propagate exactly the permissions they hold, which the ALL-three gate used to forbid.
- **Tightening:** a caller without `user:read` can no longer revoke `MEMBER`.
- Catalogue coupling (revised, Revision 1): the definition depends on the catalogue, and D1's admin-defining preservation keeps full stand-in roles qualifying across permission-adding migrations. The permission-migration runbook still runs the custom-admin exposure check as a confirmation. A tenant that nonetheless ends at zero administrators is recoverable only by break-glass, and only where a system `TENANT_ADMIN` is seeded (RES-41).
- **Access review (Revision 1, RC-38).** US-018 C3 is the **first live use of `audit:read`**; no earlier endpoint exposed `auth_events`. Its holder endpoints disclose the tenant's **administrator roster** to every `audit:read` holder, and `audit:read` is a non-admin permission that A2/A3 let its holders propagate (RES-37, Low). **Decision (RC-38.2):** C3's `RoleHolder.assignedBy` follows the same rule as `listActive`: redacted unless the caller is an administrator (D3). One rule per field, so no widening needs accepting. The M9 runbook detects which custom roles carry `audit:read`.

**What this ADR does not close:**
- **Pre-positioning through a second account (RES-26; restated, Revision 1, RC-23.1).** It needs two *accounts*. Where self-registration is open (today the default tenant: `RegistrationController.java:54`) one attacker can hold both. D4 closes the literal self-target step of RES-1(b); the primitive survives through a second account. RES-26 cites RES-1(b) and carries its accountable owner role (the Platform Security Owner), its 2026-11-27 review date and its Epic-3 hard expiry. Its acceptance is **pending at Gate 2**; this ADR does not record it as accepted. Controls: D7's provenance signal and D8's narrow 409.
- **Snapshot TOCTOU (RES-27; restated, RC-25.2).** The window runs from the transaction's first consistent read to the snapshot read, and it would include any set-lock wait. After D2's set-lock rule it applies only to paths that take no lock, where it is milliseconds.
- **Detach to zero administrators (RES-28; rewritten, RC-26.3).** Newly reachable when D13 is retired, because US-017 D13 required a literal `TENANT_ADMIN`, who stayed an administrator by construction. After D5's administrator-through-another-role requirement, no single detach can reach zero; only two concurrent detaches (or a detach racing a revoke), each authorized by a snapshot that still shows the other role, can. The health indicator pages on the outcome, and break-glass recovers it where a system `TENANT_ADMIN` is seeded.
- **Object-level authorization** is ADR-0023.

## Alternatives considered

| Alternative | Rejected because |
|---|---|
| Keep ANY/ALL predicates and add `user:role:assign` to the dangerous set | Still name- and list-based; would not cover future permissions; silently changes the admin populations |
| "Administrator" = union of held permissions covers the catalogue | Does not match the role-id shape the lock set protects; a two-role holder failing A4 costs nothing |
| Locking read of the caller's assignments | New acquisition outside the set lock; reopens ADR-0018 D6's hazard. On the set-lock path the set lock's own rows already give a current, locked answer (D2) |
| The general assignment-provenance 409 (Revision 1) | Blocks routine attaches to widely held, delegated roles; clearing it needs a revoke and assign per holder (D8) |
| Leaving revoke-subset and role-subset as pure union checks (Revision 1) | Lets a union-holder strip administrators and detach a tenant to zero administrators (D5) |
| Backfill `user:role:assign` to custom `user:write` roles | Carries the conflation forward; the detection query plus an administrator's explicit attach is sufficient |
| Return the missing permission in `requiredPermission` | Oracle on role composition for callers without `role:read` |

## Follow-on rules

- Any new grant-like operation (a new way to confer permissions) must apply grant-subset against a live, id-based read, and must state its lock mode against `nexus_app`'s grants.
- "Administrator" has exactly one definition (`RbacAdministrators`). A new call site must use it, not a name or a permission list.
- Every migration that inserts into `permissions` ends with the B7 footer, **both statements** (admin-defining preservation and the system `TENANT_ADMIN` re-sync), instantiated from the one-placeholder template with exactly its own inserted ids (D1, Revision 2), and triggers the permission-migration runbook (the custom-admin exposure check and the permission-cache flush).
- A decision that asks "is the caller an administrator?" on a path that holds the set lock takes the answer from the set lock's rows, never from a snapshot (D2).
