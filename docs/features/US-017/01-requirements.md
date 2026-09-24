# US-017 — Requirement Analysis Document (Gate 1)

**Story:** Extend last-admin lockout protection to admin-equivalent custom roles
**Epic:** EPIC-002 — RBAC Foundation
**Source documents:** `docs/story/2-rbac/US-017.md`; `docs/story/2-rbac/EPIC-002.md` (§ "US-017", § "US-016", Open Decisions #7); `nexus-backend/.../RoleAssignmentService.java` (`assign()`/`revoke()`, `requireActiveTenantAdmin`, `nameMatch`/`privileged` split, `lockedActiveAdminIds`); `nexus-backend/.../RbacZeroActiveAdminsHealthIndicator.java`; `nexus-backend/.../JpaUserRoleRepository.java` (`findTenantsWithZeroActiveAssignmentsForRole`); `nexus-backend/.../UserRoleAssignmentPort.java` (full Javadoc); `nexus-backend/.../RbacDangerousPermissions.java`; `nexus-backend/.../RbacRoleNames.java`; `nexus-backend/.../RoleManagementService.java` (`attachPermission`, D13 holder-count signal); `docs/features/US-016/01-requirements.md`, `03-design.md` §12.2-§12.3, `03b-threat-model.md` (RES-3, RES-9)
**Status of story as received:** explicit DRAFT stub, "not yet through Gate 1" (its own AC table — all three rows are framed as open questions, not settled criteria). This document is the Gate 1 analysis, not a rubber stamp of the stub.

---

## 1. Context

US-016 changed `RoleAssignmentService.assign()`/`revoke()` so that granting or revoking a role is gated by what the role actually *does* (does it carry `role:write`, `user:write`, or `tenant:write` — the `RbacDangerousPermissions` set — or is it literally named `TENANT_ADMIN`), not merely by its name. That closed the "propagate" escalation path: a non-admin can no longer be handed, or strip from someone else, admin-equivalent power just because the role granting it happens not to be called `TENANT_ADMIN`.

Two adjacent controls in the same subsystem were **not** updated to match that shift, and this story exists to close both, plus evaluate a third, related gap:

1. **AC5's last-admin lockout guard** (originally from US-012, living in `revoke()`) — the check that blocks revoking a tenant's sole active `TENANT_ADMIN` holder — only evaluates when the role being revoked is literally named `TENANT_ADMIN`. A tenant whose *only* active administrator holds a custom, admin-equivalent role instead can be revoked straight to zero admins with no lockout protection at all.
2. **`RbacZeroActiveAdminsHealthIndicator`** — the runtime detection control that pages/alerts when a tenant has zero active `TENANT_ADMIN` holders — has the identical name-only blind spot. A tenant already silently zeroed out via (1) produces no health signal either, because the indicator only ever looks for holders of the literal name.
3. **RES-9 (paired, not built here by default)** — the *caller*-side admin test in the same privilege gate (`requireActiveTenantAdmin`, used by both `assign()` and `revoke()`) still resolves the tenant's admin role by literal name and checks whether the *caller* holds an active assignment of that literally-named role. A user who holds an admin-equivalent custom role can be the lockout-protected *target* of fix (1) but can never *pass* this test to *act* as an admin. The story's own AC3 asks that this be evaluated in the same Gate 1 pass, not that it be fixed here — it does not commit to a code change.

All three sit inside `RoleAssignmentService`/its health-check companion, the exact subsystem that has already needed two rounds of threat-modeled hardening (US-012 AC5's original lockout, US-016's privilege-based gate). This is not routine CRUD, and the story's own stub explicitly declines to pre-scope the design — that is what this Gate 1 pass is for.

---

## 2. Functional Requirements

Each item is tagged:
- **[SPEC]** — directly stated by the story's AC table or EPIC-002's US-017 section.
- **[INFERENCE]** — not stated outright; derived from the cited code, prior stories' Javadoc, or US-016's own analogous Gate 1 document. Requires explicit sign-off before being treated as settled.
- **[OPEN]** — the story itself frames this as unresolved; no functional requirement can yet be written. See §7.

### FR-1 [SPEC, mechanism OPEN] — Lockout guard recognizes admin-equivalent custom roles
The last-admin lockout guard in `revoke()` must block revocation of a tenant's sole active admin-equivalent role holder, where "admin-equivalent" includes both the literal `TENANT_ADMIN` role and any custom role carrying at least one `RbacDangerousPermissions` member. (Story AC1.)
- Not yet defined by this FR: whether "admin-equivalent" for this purpose is identical to `assign()`/`revoke()`'s own `nameMatch || carriesDangerousPermission` definition, and whether the lockout must count the union of holders across potentially *multiple* admin-equivalent roles in the tenant, not just the one role being revoked (see Open Question 2, Edge Cases 1-3, Risk R1).

### FR-2 [SPEC, mechanism OPEN] — Health indicator recognizes zero holders of any admin-equivalent role
`RbacZeroActiveAdminsHealthIndicator` must report unhealthy for a tenant with zero active holders of *any* admin-equivalent role (literal or custom), not only zero literal-`TENANT_ADMIN` holders. (Story AC2.)
- Not yet defined by this FR: whether this resolves the role→privilege mapping live on every health check, or via a new/extended cached signal (see Open Question 3, Risk R2/R6).

### FR-3 [OPEN] — Caller-side admin test (RES-9)
The story's AC3 only commits to RES-9 being "evaluated in the same Gate 1 pass" — it does not commit to changing `requireActiveTenantAdmin`'s name-based caller check. No functional requirement can be written here (fix in this story / fix in a separate story / no fix) until Gate 1 resolves the disposition. See Open Question 4.

### FR-4 [INFERENCE] — Existing literal-`TENANT_ADMIN` behavior is preserved, not replaced
FR-1 and FR-2 are additive: the existing lockout/health behavior for the literally-named `TENANT_ADMIN` role must continue to fire exactly as it does today. Basis: the story's own title ("**extend**... protection"), and both US-012's and US-016's precedent of additive, non-regressive privilege-gate changes (US-016 FR-3 made the identical commitment for the assign/revoke gate).

### FR-5 [INFERENCE] — `LastAdminRoleException`/409 contract reused, trigger condition widened only
The existing `LastAdminRoleException` → 409 `RBAC_002` response contract, and the existing `RBAC_LAST_ADMIN_REVOCATION_BLOCKED` WARN log shape, must be reused unchanged for the widened trigger condition — no new response code or contract is implied anywhere in the source material. Basis: the story text never mentions a new API contract; it describes only a broadened *condition* under which the existing guard fires.

### FR-6 [INFERENCE] — Health indicator's existing disclosure discipline is preserved
The extended health indicator must preserve its existing privacy-preserving pattern: only an affected-tenant *count* in the actuator response body, with full tenant ids reserved for the application WARN log (07-security-review.md M-1, already implemented). Basis: nothing in the story proposes relaxing this; the underlying disclosure risk (any authenticated principal of any tenant can read `/actuator/health`) is unchanged by widening the query's role-matching logic.

### FR-7 [INFERENCE] — Consistent definition of "admin-equivalent" across FR-1 and FR-2
Whatever set of roles counts as "admin-equivalent" for FR-1 (the lockout guard) must be the identical set used for FR-2 (the health indicator) — the two controls exist to protect and detect the same invariant, and a definitional mismatch between them would itself be a gap (a tenant could pass the lockout guard's test yet still be flagged unhealthy, or vice versa). Not stated explicitly by the story; inferred from the shared purpose stated in the story's own title and User Story.

---

## 3. Non-Functional Requirements

| Category | Requirement / finding |
|---|---|
| **Performance** | No documented p95/RPS target exists anywhere in the source material for either the lockout guard or the health indicator (mirrors the identical gap noted in US-016's own Gate 1 doc, still unresolved). The lockout guard already carries a monitored lock-hold timer (`nexus.rbac.privileged_revoke_lock_hold`, US-016 D2/D18); if FR-1's mechanism widens the locked/counted row set from one `role_id` to a union across multiple `role_id`s, that timer's shape and baseline must be re-evaluated, not assumed unchanged. **[CONFIRM]** an explicit lock-hold budget with the Architect before design. |
| **Scalability** | The health indicator today runs one cheap `NOT EXISTS` query per literal role name, independent of tenant count. Extending "admin-equivalent" to arbitrary custom roles requires resolving role→permission membership somewhere — a live join across `roles`/`role_permissions`/`permissions` for every tenant on every health-check cadence has fundamentally different scaling behavior (grows with tenant × role count) than today's query. Not yet sized — see Risk R2. |
| **Availability** | No SLO stated for either control in any inspected source document. The health indicator is explicitly a **detection**, not a prevention, control (its own Javadoc: "by the time this reports DOWN, the tenant is already locked out and needs manual... remediation"); its own availability characteristics (does it need to stay cheap/synchronous, or can it tolerate an async/cached signal with some staleness?) is an open design question — see Open Question 3. |
| **Security** | This entire story is a security control extension — see §6/§7. One explicit posture requirement, consistent with US-015/US-016 precedent (T-E18/R-10, "fail closed on empty lookup"): if FR-1's mechanism needs a new lookup (e.g., resolving which roles in a tenant are admin-equivalent), an empty, unresolvable, or error result must fail toward **blocking the revocation** (deny/409), never toward silently allowing a tenant to be zeroed out. |
| **Scalability / concurrency** | FR-1 potentially changes the lockout guard's locking shape from "lock the active-assignment rows of one `role_id`" to "lock the union of active-assignment rows across N admin-equivalent `role_id`s in the tenant." This is a materially different concurrency primitive, not a parameter widening — see Risk R1 and Edge Case 3. Lock-acquisition ordering across multiple `role_id`s (if that is the chosen mechanism) must be deterministic to avoid new deadlock classes, compounding the already-accepted RES-10 finding (US-016 §12.3) on this exact code path. |
| **Observability** | Must integrate with, not duplicate, the existing signal set: `RBAC_LAST_ADMIN_REVOCATION_BLOCKED` WARN + `nexus.domain.conflict{code="RBAC_002"}` counter (lockout), the `rbacZeroActiveAdmins` health indicator, and (if RES-9 is in scope) the `RBAC_PRIVILEGED_ROLE_CHANGE_BLOCKED` WARN + `nexus.rbac.privileged_role_change_blocked{matchedOn}` counter, which already distinguishes `ROLE_NAME` from `DANGEROUS_PERMISSION` matches on the *target* side. Whether the lockout guard's own denial signal needs an equivalent `matchedOn`-style tag once it can fire on the admin-equivalent-custom-role path is an open question (see §7 Open Question 8). |
| **i18n** | Not applicable — backend authorization/health-check logic, no new user-facing strings identified. **[CONFIRM]** if a widened lockout condition needs any new frontend-facing copy for the 409 case (no Angular consumer of this specific error is confirmed in scope — see Gaps). |
| **Audit / compliance** | The existing `RBAC_LAST_ADMIN_REVOCATION_BLOCKED` WARN log (operator-facing, not the durable audit stream) must continue to fire on the widened condition. Whether a lockout block should *also* produce a `ROLE_ASSIGNMENT_DENIED`-style durable audit row (today it does not — the lockout guard raises `LastAdminRoleException`, which is a business-rule conflict, not an authorization denial, and is not currently routed through `recordDenial`) is unaddressed by the story and worth confirming is unchanged, not silently altered. |

---

## 4. Edge Cases

1. **Sole admin-equivalent holder holds it via two different roles simultaneously** (e.g., a user holds both the literal `TENANT_ADMIN` role and a custom role carrying `user:write`). Revoking either role alone must **not** trigger the lockout, since the user still holds the other admin-equivalent role afterward — the invariant to protect is "does the tenant retain at least one admin-equivalent holder," not "does this specific role retain a holder."
2. **Two different users each hold a different single admin-equivalent role** (User A: literal `TENANT_ADMIN`; User B: a custom role carrying `role:write`). Revoking either user's role alone must **not** trigger the lockout, since the union of admin-equivalent holders in the tenant is still ≥ 1 afterward.
3. **Concurrent revocation of two different admin-equivalent roles, each the sole route to admin-equivalent access for a different user** (the cross-role analogue of the exact race AC5 already protects against for a single role). Two concurrent `revoke()` calls, each individually evaluated only against its own `role_id`'s holder count, could each see "not the last holder of *this* role" and both succeed — jointly zeroing the tenant. This is the central structural risk this story exists to close and is easy to under-scope if FR-1 is implemented as a straightforward per-role extension rather than a true tenant-wide union check. See Risk R1/R5.
4. **TOCTOU: a role's permission set changes (via `RoleManagementService.attachPermission`/`detachPermission`) between the lockout guard's read and the revoke's write.** Direct precedent: US-015's threat model (T-E14) rated a non-locking read on an equivalent mint-side check as High. Whatever mechanism FR-1 uses for "is this role admin-equivalent" must be evaluated against the same locking-vs-non-locking rigor, not left to be discovered at implementation time.
5. **A role stops being admin-equivalent (its last dangerous permission is detached) at the same moment its sole holder is being revoked.** Order-of-operations here determines whether the lockout guard fires or not; the "correct" outcome is not stated anywhere in the source material and needs an explicit answer (does the guard evaluate against the role's admin-equivalence *before* or *after* the concurrent detach commits?).
6. **Tenant has no admin-equivalent role of any kind** (a mis-seeded or not-yet-seeded tenant). The literal-`TENANT_ADMIN` health check already has to handle "role doesn't exist for this tenant" implicitly (its query is a `NOT EXISTS` over roles named `TENANT_ADMIN`, which naturally returns no rows for a tenant with none). The extended, admin-equivalent version must define the same "no admin-equivalent role exists at all" case explicitly rather than have it fall out incidentally of a differently-shaped query.
7. **Health-check staleness, if a cached/materialized signal is adopted** (Open Question 3): a lag between a tenant actually reaching zero admin-equivalent holders and the indicator reflecting it inverts the control's purpose — it exists specifically to catch the case where the *preventive* lockout guard (FR-1) was somehow bypassed. An acceptable staleness bound (if any) is undefined.
8. **RES-9 interaction, if left unresolved:** a user who holds only a custom admin-equivalent role is (post-FR-1) *protected* from being revoked to zero, yet (with RES-9 unresolved) can never *act* as the caller for another `assign()`/`revoke()` — `requireActiveTenantAdmin` still tests only for the literally-named role. A tenant could therefore have its "last admin" be provably lockout-protected but functionally unable to administer the tenant at all, an asymmetric state not addressed anywhere in the source material.
9. **Denial/lockout ordering, if RES-9 changes the caller-side test:** today, the caller-privilege check (403) always runs before the AC5 lockout check (409) on `revoke()` (D1 in existing code). If RES-9's caller-side test also becomes privilege-based, this ordering must be explicitly preserved — a change here would alter which HTTP status a given bad request returns.
10. **Role carries none of the three dangerous permissions and isn't literally named `TENANT_ADMIN`** — must not be treated as admin-equivalent by either FR-1 or FR-2 (mirrors US-016's own Edge Case 1 for the target-side gate; this is the negative-case baseline the "ANY, not ALL" semantics rest on).
11. **Empty tenant / user has zero role assignments at all** — revocation of a nonexistent assignment already 404s before the lockout guard runs today (`findAssignmentRefOrThrow` precedes `nameMatch`/`lockedActiveAdminIds` in `revoke()`); FR-1's extension must not change this ordering.
12. **Network/partial failure of the (possibly new) admin-equivalence lookup** — must fail toward blocking the revocation (see NFR Security row), not toward silently treating an unresolvable lookup as "not admin-equivalent, safe to revoke."

---

## 5. Assumptions

1. US-016 has merged and its privilege-based `assign()`/`revoke()` gate (`nameMatch || carriesDangerousPermission`, `RbacDangerousPermissions.NAMES`, `hasActiveAdminAssignment`) exists exactly as described — **settled fact**, verified directly in code, not an assumption requiring confirmation.
2. **[CONFIRM]** "Admin-equivalent," for the purposes of FR-1 and FR-2, is defined identically to `assign()`/`revoke()`'s own `nameMatch || carriesDangerousPermission` test — i.e., a role holding **any** (not all) of `RbacDangerousPermissions.NAMES`, or literally named `TENANT_ADMIN`. The story's own Notes column suggests this ("likely reuses `RbacDangerousPermissions.NAMES`") but frames it as TBD.
3. **[CONFIRM]** The lockout guard's protected invariant is tenant-wide: "at least one user in the tenant holds an active assignment of *some* admin-equivalent role," evaluated as the union across however many such roles exist in the tenant — not a per-role count. This is the reading implied by the story's own framing ("silently zeroed out of admin-equivalent access"), but it is a materially larger scope than today's single-role-id mechanism and is not spelled out as such by the stub. See Open Question 2.
4. **[CONFIRM]** No REST endpoint, request/response DTO, or public API contract changes are in scope — this story is scoped to `RoleAssignmentService.revoke()`'s internal lockout logic and `RbacZeroActiveAdminsHealthIndicator`'s internal query, mirroring the equivalent assumption in US-016's own Gate 1 document. Not stated explicitly by the stub.
5. **[CONFIRM]** No frontend (Angular) change is in scope. Not addressed anywhere in the source material.
6. **[CONFIRM]** No database migration is assumed necessary to satisfy FR-1 as literally stated (reuse of `user_roles`/`roles`/`role_permissions`/`permissions`). This assumption does **not** extend to FR-2: if the health indicator's chosen mechanism (Open Question 3) requires a new materialized/cached signal, that could require new schema or infrastructure and must not be assumed away.
7. **[CONFIRM]** RES-9 (FR-3) is, per AC3's literal wording, scoped in this Gate 1 pass to an *evaluation*, not a committed code change. Whether it ships as part of US-017's implementation or is split into its own successor story is an explicit PM/Security decision (Open Question 4), not something this document decides.
8. **[CONFIRM]** The existing `LastAdminRoleException` → 409 `RBAC_002` contract and the existing `RBAC_LAST_ADMIN_REVOCATION_BLOCKED` WARN log format are reused unchanged; only the *condition* that triggers them widens (FR-5).
9. **[CONFIRM]** `RbacZeroActiveAdminsHealthIndicator`'s existing disclosure posture (count-only in the actuator body; full tenant ids only in the WARN log — 07-security-review.md M-1) is preserved for the widened check (FR-6).

---

## 6. Risks

| # | Risk | Severity | Mitigation |
|---|---|---|---|
| R1 | Extending the lockout guard's locking scope from "the active-assignment rows of one `role_id`" to "the union of active-assignment rows across potentially several admin-equivalent `role_id`s in the tenant" is a materially different concurrency mechanism, not a drop-in parameter change. A naive implementation risks either (a) failing to lock the full at-risk set, reopening exactly the TOCTOU/race gap this story exists to close (Edge Case 3), or (b) introducing new lock-ordering/deadlock hazards on top of the already-documented, accepted RES-10 finding (US-016 §12.3) on this exact `revoke()` code path | **Critical** | Architect must specify the exact locking protocol (e.g., deterministic ascending `role_id` ordering across all admin-equivalent roles, or a non-multi-lock alternative design) before Gate 2 design starts. Do not treat this as a mechanical extension of `lockActiveAssignmentIds`. |
| R2 | `RbacZeroActiveAdminsHealthIndicator` currently runs one cheap, name-scoped query. Extending "admin-equivalent" to arbitrary custom roles requires resolving role→permission membership somewhere. D13 (US-016 §4.7, `RoleManagementService.attachPermission`'s holder-count signal) is an **event-time** signal fired only when a dangerous permission is attached — it does not track ongoing holder counts as later revocations happen, so it cannot be reused as-is to answer "is tenant X *currently* at zero." A live per-check join across `roles`/`role_permissions`/`permissions` for every tenant is a different, and unbounded-by-tenant-count, cost profile than today's query | **High** | Architect decision required on caching/materialization strategy (Open Question 3) before Gate 2; do not assume D13 is directly reusable. |
| R3 | RES-3 (this story) and RES-9 are explicitly framed by the story's own Background as "one Epic-3 question... evaluated... before either ships." If Gate 1 concludes RES-9 must be fixed here without descoping, story size could grow substantially — `requireActiveTenantAdmin` is shared, identical code between `assign()` and `revoke()`, and any privilege-based rework of it touches the exact path US-016 hardened, security-critically, twice already | **High** | PM/Security must make an explicit RES-9 disposition decision (Open Question 4) before Phase 2 impact analysis sizes the work; do not let scope grow by default. |
| R4 | Definitional drift: if "admin-equivalent" for the lockout guard/health indicator (this story) ends up even slightly different from "privileged" for the `assign()`/`revoke()` authorization gate (US-016), the codebase carries two similarly-named-but-not-identical privilege concepts side by side — itself a latent defect (a role could be gate-privileged but not lockout-protected, or vice versa) | **Medium** | Single source of truth: reuse the identical predicate/expression `assign()`/`revoke()` already use, not an independent re-derivation (Assumption 2/FR-7). |
| R5 | A tenant's "last admin-equivalent access" can be split across two different roles held by two different users. No mechanism today serializes revocations across `role_id`s — two concurrent `revoke()` calls, each individually passing a naive per-role lockout check, could jointly zero the tenant even after FR-1 ships, if FR-1 is implemented as a per-role rather than a true cross-role union check | **Medium** (overlaps R1; called out separately because it is a test-coverage risk, not just a design risk) | Mandatory adversarial IT coverage for the multi-role, multi-holder concurrent-revocation scenario (Edge Case 3) at Gate 2/Gate 3, not left as an afterthought. |
| R6 | Widening the health indicator's query surface from two tables (`roles`, `user_roles`) to four (adding `role_permissions`, `permissions`) broadens the read footprint of a component explicitly designed to stay cheap and detection-only; if this runs on every actuator health-check cycle across every tenant, it could itself become a load/availability concern | **Medium** | Tie to R2's mitigation — Architect to decide check frequency, caching, and whether the extended query needs its own health-check cadence separate from the aggregate `/actuator/health` poll interval. |
| R7 | Both halves of this story touch the same subsystem hardened twice already (US-012 AC5, US-016) with dedicated ADRs and threat models. Treating this as a routine extension rather than affording it the same rigor risks reproducing a closed class of bug in a new shape | **Medium** | Story should get its own `03b-threat-model.md`, and Gate 1/2 should explicitly decide whether a new ADR is warranted (following US-016's own precedent of requiring one for exactly this class of change to this same code) — see Open Question 6. |
| R8 | If Gate 1 leaves RES-9 unresolved and out of scope, the asymmetric state in Edge Case 8 (lockout-protected but caller-incapable admin-equivalent holder) ships as a known, silent limitation with no operator-facing signal distinguishing it from "working as intended" | **Low-Medium** | If RES-9 is descoped, explicitly record this asymmetry as a documented, accepted residual risk (mirroring how RES-1(b) and RES-9 itself were recorded in US-016), not silently left implicit. |

---

## 7. Open Questions

The three the story itself frames as open (per its AC table), plus questions surfaced independently during this analysis, marked **[new]**.

1. **(Security / Architect)** Is "admin-equivalent" for FR-1/FR-2 defined identically to `assign()`/`revoke()`'s existing `nameMatch || carriesDangerousPermission` test (literal `TENANT_ADMIN`, or **any** — not all — of `RbacDangerousPermissions.NAMES`)? The story's own Notes column suggests reuse but does not confirm it as settled. A "yes" answer settles Assumption 2 and FR-7.
2. **(Architect)** Does the lockout guard's protected invariant need to become a true tenant-wide **union** across potentially multiple admin-equivalent `role_id`s (Edge Cases 1-3), or is there a materially simpler framing the story's own background didn't consider — e.g., a single materialized per-tenant "has at least one active admin-equivalent holder" flag maintained transactionally on every relevant write, rather than a locking read fanned out across N role ids at revoke-time? This decision drives R1's severity and the entire locking design.
3. **(Architect / SRE)** For the health indicator (FR-2): resolve the role→privilege mapping live on every health check (cost scales with tenant × role count, unproven), or invest in a new cached/materialized signal distinct from D13 (which is event-time only, not a live per-tenant count — see R2)? What staleness, if any, is acceptable for a control whose whole purpose is catching a *bypass* of the preventive guard?
4. **(PM / Security)** RES-9 disposition: does the caller-side fix to `requireActiveTenantAdmin` ship as part of US-017, or does this Gate 1 analysis support splitting it into its own successor story? This document's own read: RES-3 (a tenant-wide *count/lockout* invariant) and RES-9 (a single caller's *authorization* test) are related in that both hinge on "who counts as admin equivalent," but are structurally separable and independently implementable — suggesting the coupling assumed by the story's Background may be looser than stated. Recommend PM/Security explicitly decide rather than defaulting to "bundled."
5. **(Security)** If RES-9 is *not* resolved in this story, is the resulting asymmetric state (Edge Case 8 — lockout-protected but caller-incapable admin-equivalent holder) acceptable as a documented interim limitation, or does it need to be surfaced/communicated (e.g., to Tenant Admins, or as an explicit follow-on risk with an expiry, mirroring RES-1(b)'s treatment in US-016)?
6. **[new] (Architect)** Does widening the lockout guard's locking protocol (Open Question 2) warrant a new ADR, following the precedent US-016 set (ADR-0017) for "expanding this exact code path's shipped contract"? This story changes a locking/detection mechanism rather than the authorization contract itself, but touches the identical security-critical method twice-hardened already.
7. **[new] (PM)** The story stub leaves Priority and Story Points blank ("PM to prioritize," "unestimated"), unlike US-016 which carried an explicit "hard expiry at Epic 3 kickoff." Given R1-R3's severity and this being the formally filed successor to a Med-severity, accepted-out-of-scope risk (RES-3) from a story that itself had a hard deadline, should this story inherit similar urgency/scheduling treatment ahead of Epic 3, or remain genuinely unscheduled as currently stated?
8. **[new] (Security / SRE)** Should the lockout guard's own denial signal (`RBAC_LAST_ADMIN_REVOCATION_BLOCKED` WARN / `nexus.domain.conflict{code="RBAC_002"}`) gain a `matchedOn`-style tag (mirroring the target-side gate's existing `ROLE_NAME` vs. `DANGEROUS_PERMISSION` distinction) once it can fire on the admin-equivalent-custom-role path, so operators can distinguish the two triggering conditions in monitoring?
9. **[new] (Security / Compliance)** Should a lockout block (today: `LastAdminRoleException`, a business-rule conflict, not currently routed through the durable `ROLE_ASSIGNMENT_DENIED` audit path) start producing a durable audit row once it can also fire for a custom admin-equivalent role, or does the existing WARN-log-only treatment remain sufficient? Not addressed anywhere in the source material for either the current or the extended behavior.

---

## 8. Gaps

Material the story and its linked EPIC section leave entirely unaddressed:

1. **No explicit performance/latency/RPS target** for either the widened lockout guard or the widened health indicator, before or after this change (mirrors the identical, still-unresolved gap flagged in US-016's own Gate 1 document).
2. **No remediation/detection plan for tenants that may already be in a silently-zeroed-out state today.** RES-3 has existed as a live gap since US-016 merged; the story stub is framed entirely as a forward-looking code fix, with no mention of whether a one-time audit of currently-existing tenants (to check whether any has already been revoked down to zero admin-equivalent holders) is in scope.
3. **No stated relationship to RES-10** (US-016 §12.3's already-accepted lock-cycling/deadlock risk on this exact `revoke()` code path). If FR-1 adds more locking to the same method, RES-10's risk acceptance may need to be revisited — the story stub doesn't mention RES-10 at all.
4. **No test scenarios provided** — the story stub explicitly states "not yet scoped... needs its own requirements/impact analysis pass."
5. **No mention of whether this story gets its own `03b-threat-model.md`**, despite touching the exact subsystem that has required one on both prior occasions (US-012, US-016). Flagged for completeness, likely just reflects that Gate 1 precedes that phase, per the identical observation made in US-016's own Gate 1 document.
6. **No mention of Priority or Story Points** — both explicitly deferred to "PM to prioritize" / "unestimated" in the stub's header table, unlike US-016 which had an assigned "High — hard expiry" priority from the outset.
7. **No stated interaction with AC8's self-assignment precedence question**, which US-016's own Gate 1 doc deferred to design (its Open Question 5) — if RES-9 is resolved as in-scope here, this story would directly touch that same unresolved precedence question, and the stub does not acknowledge the dependency.
8. **No frontend/UI impact analysis** — consistent with the rest of this epic's backend-only framing to date, but not explicitly stated for this story either.

---

## 9. Stakeholder Map

| Stakeholder | Interest / what they need from this story |
|---|---|
| Platform Security Owner (story author) | Confirmation that RES-3 is actually closed end-to-end (both the preventive lockout guard and the detective health indicator), not just one half of it. |
| Product Manager | Priority/scheduling decision (currently blank in the stub — Open Question 7); explicit scope decision on RES-9 (Open Question 4), which materially changes story size. |
| Architect | Locking-protocol design for the (possibly cross-role) lockout guard (Open Question 2, Risk R1); health-indicator data-source/caching strategy (Open Question 3, Risk R2/R6); ADR necessity (Open Question 6). |
| Security / Threat-model reviewer | Owns the RES-3 and RES-9 risk-register entries this story is meant to close or narrow; needs this Gate 1 outcome to update their status; will drive whether a dedicated threat model is commissioned (Gap 5). |
| SRE / Observability owner | Owns `/actuator/health` and its polling cadence/cost; needs the health-indicator mechanism decision (Open Question 3) before committing to a monitoring/runbook change; owns any new `matchedOn`-style tagging (Open Question 8). |
| QA / Test Engineer | Needs concrete acceptance scenarios once Gate 1's open questions resolve — none exist yet (Gap 4); will need to author the multi-role, multi-holder concurrent-revocation IT coverage this story specifically motivates (Edge Case 3, Risk R5), analogous to `LastAdminLockoutIT`. |
| Compliance / Audit | Interested in whether a lockout-block event should gain durable audit-trail treatment (Open Question 9) and whether the health indicator's existing disclosure discipline (count-only, no cross-tenant id leakage) is preserved under the widened query (FR-6). |
| Tenant Admins (end users) | No workflow change expected for legitimate administration; a tenant that would previously have been silently zeroed out of admin-equivalent access now receives a 409 instead — a strictly safer outcome, assuming FR-1 is correctly scoped (Risk R1/R5). |

---

## 10. Success Metrics

Pending Gate 1 resolution of the open questions above; exact thresholds to be confirmed once the mechanism (locking protocol, health-indicator data source) is designed:

1. **Zero** instances, measured from deployment forward, of a tenant reaching zero active admin-equivalent role holders through any sequence of `revoke()` calls — including the concurrent multi-role scenario (Edge Case 3) — verified by dedicated adversarial IT coverage with **zero false positives** against legitimate revocations that correctly leave ≥1 admin-equivalent holder in the tenant.
2. `RbacZeroActiveAdminsHealthIndicator` correctly reports `DOWN` for a tenant with zero active holders of any admin-equivalent role (not only literal `TENANT_ADMIN`) in adversarial test scenarios, within whatever staleness bound Gate 2 design settles on (Open Question 3).
3. No regression in existing lockout/health-indicator test coverage for the pre-existing, literal-`TENANT_ADMIN`-only scenarios (FR-4/FR-6 non-regression) — e.g., `LastAdminLockoutIT` and any existing `RbacZeroActiveAdminsHealthIndicator` tests continue to pass unmodified in their original scenarios.
4. RES-3 in US-016's design/threat-model residual-risk table is updated from "Med, accepted, out of scope" to a closed/resolved status, citing this story.
5. If RES-9 ships as part of this story: zero instances, in staging soak testing, of a legitimate admin-equivalent custom-role holder being denied a caller-side action they should be entitled to perform, and zero instances of a non-admin caller passing the widened caller-side test.
6. No increase in `nexus.rbac.privileged_revoke_lock_hold` p95/p99 lock-hold duration beyond whatever threshold the Architect sets, attributable to any expanded locking scope introduced by FR-1 (this metric already exists per US-016 D2/D18 and should be the primary regression signal for R1's performance dimension).
7. If RES-9 is explicitly descoped: a follow-on risk/backlog entry for the resulting asymmetric state (Edge Case 8) exists and is visible in the epic's risk register, rather than the limitation being silently absorbed with no trace (mirroring how US-016 itself recorded RES-3 and RES-9 as named follow-ons rather than letting them lapse silently).

---

## Summary for Gate 1 Sign-Off

This document deliberately stops short of deciding the security-critical questions below — they require explicit stakeholder approval before Phase 2 (impact analysis) / Phase 3 (design) proceeds.

**High/Critical risks requiring attention before Gate 2:**
- **R1 (Critical):** Extending the lockout guard from "lock one role's holders" to "protect the tenant-wide union of admin-equivalent holders across potentially several roles" is a new concurrency mechanism, not a parameter tweak — it risks either reopening the exact race this story exists to close, or introducing new deadlock hazards on top of the already-accepted RES-10 finding on this same code path.
- **R2 (High):** The health indicator's extension cannot cheaply reuse D13 (US-016's holder-count signal is event-time only, not a live per-tenant state) — a live cross-table join or genuinely new cached signal is required, and its cost/staleness trade-off is undecided.
- **R3 (High):** RES-3 and RES-9 are framed as one coupled Epic-3 question by the story's own Background; resolving that coupling (bundle vs. split) materially changes this story's size and must be an explicit PM/Security call, not a default.

**Open questions needing your explicit approval:**
1. Is "admin-equivalent" identical to `assign()`/`revoke()`'s existing `nameMatch || carriesDangerousPermission` definition (ANY, not ALL, of the three dangerous permissions)?
2. Does the lockout guard need a true cross-role union check, or is a simpler per-tenant materialized flag acceptable — and who (Architect) owns that design call?
3. Health indicator: live join per health check, or a new cached signal — and what staleness is tolerable for a control whose purpose is catching a bypass?
4. RES-9: fixed in this story, or split into its own successor story?
5. If RES-9 is descoped, is the resulting lockout-protected-but-caller-incapable asymmetric state acceptable as a documented interim limitation?
6. Does this story need its own ADR (following the US-016/ADR-0017 precedent) and its own `03b-threat-model.md`?
7. Should this story get a priority/scheduling decision now, given it is RES-3's named successor with Critical/High findings above, rather than remaining fully unscheduled?

---

## Gate 1 Resolution (approved by Md Nisar Ahmed, 2026-09-17)

1. **Admin-equivalent definition (Open Question 1 / Assumption 2): RESOLVED.** Identical to `assign()`/`revoke()`'s existing `nameMatch || carriesDangerousPermission` test — literal `TENANT_ADMIN`, or **any** (not all) of `RbacDangerousPermissions.NAMES`. FR-1/FR-2/FR-7 are promoted from `[SPEC, mechanism OPEN]`/`[INFERENCE]` to settled on this point; Assumption 2 is confirmed, not merely proposed.
2. **RES-9 disposition (Open Question 4): RESOLVED — fixed inside US-017,** not split into a successor story, notwithstanding this document's own recommendation to consider splitting. FR-3 is promoted from `[OPEN]` to in-scope: `requireActiveTenantAdmin`'s caller-side test becomes privilege-based, symmetric with FR-1/FR-2's target/detection-side treatment. Consequences that follow directly from this call and must carry into Phase 2 impact analysis / Gate 2 design:
   - Edge Case 8's asymmetric state (lockout-protected target, caller-incapable) is being **closed**, not documented as an accepted residual risk — Open Question 5 is moot.
   - Edge Case 9 (403-before-409 ordering on `revoke()`) must be explicitly preserved by design.
   - Gap 7 (interaction with US-016's own deferred AC8 self-assignment precedence question) is now a live design input, not a footnote — Gate 2 must address it, not defer it again.
   - R3's size warning stands: this touches `requireActiveTenantAdmin`, shared identical code between `assign()` and `revoke()`, security-critically hardened twice already. Impact analysis must scope this explicitly rather than treat it as incidental to FR-1/FR-2.
3. **ADR + dedicated threat model (Open Question 6): RESOLVED — yes.** This story gets its own ADR (next free number in `docs/adr/`, following the ADR-0017/US-016 precedent for expanding this exact code path's contract) and its own `03b-threat-model.md`, produced at Gate 2 alongside `03-design.md`.

**Deferred to Gate 2 (Architect/Security, not decided here):**
- Open Question 2 — cross-role union locking protocol vs. a simpler materialized-flag alternative (Risk R1, Critical). The Architect must treat this as a new concurrency mechanism, not a mechanical extension of `lockActiveAssignmentIds`.
- Open Question 3 — health-indicator data source/caching strategy and acceptable staleness (Risk R2, High).
- Open Questions 8 and 9 — `matchedOn`-style observability tagging on the lockout guard's own denial signal, and whether a lockout block should gain durable audit-trail treatment. Proposed as part of design, confirmed at Gate 2.
- Open Question 7 — priority/scheduling remains a PM call, unscheduled for now; does not block impact analysis or design.

Proceeding to Phase 2 (impact analysis).
