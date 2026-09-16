# US-016 — Requirement Analysis Document (Gate 1)

**Story:** Gate role assignment/revocation by actual privileges, not role name
**Epic:** EPIC-002 — RBAC Foundation
**Source documents:** `docs/story/2-rbac/US-016.md`; `docs/story/2-rbac/EPIC-002.md` (§ "US-016"); `nexus-backend/.../RoleAssignmentService.java` (M-3, T-E9 Javadoc); `docs/features/US-015/03-design.md` §10; `docs/features/US-015/03b-threat-model.md` §4.5, §5, §7; `docs/features/US-012/03b-threat-model.md` (T-E7, T-E9)
**Status of story as received:** explicit DRAFT stub, "not yet through Gate 1" (its own AC table). This document is the Gate 1 analysis, not a rubber stamp of the stub.

---

## 1. Context

Nexus's role-assignment service (`RoleAssignmentService`) lets a caller holding `user:write` grant or revoke roles for other users in their own tenant. One role — `TENANT_ADMIN` — is treated as special: only an existing active `TENANT_ADMIN` may grant (and, per the story's framing, arguably revoke) it, because it carries every permission in the system. That special-casing is implemented today as a **string comparison against the role's name**, not as a check of what the role actually grants.

US-015 (already merged) introduced the ability for a `TENANT_ADMIN` to attach any permission — including `role:write`, `user:write`, `tenant:write` (the "dangerous" set defined in `RbacDangerousPermissions`) — to any custom role in the tenant, gated by an equivalent admin check on the *attach* side. This means a role that is **not** named `TENANT_ADMIN` can now legitimately hold admin-equivalent power. Because `RoleAssignmentService` still gates purely by name, any ordinary `user:write` holder can then assign that custom, admin-equivalent role to anyone — including themselves — without the admin check ever firing. This is the "propagate" half of a privilege-escalation chain that US-015's Gate 2 review explicitly declined to fix in-scope, accepted as a documented residual risk (RES-1 / R-3), and forward-tracked to this story as its named, required successor.

This story exists to decide, and then have implemented, whatever closes that propagate-side gap for both granting (`assign()`) and, pending this Gate 1's resolution of an open question the story itself raises, revoking (`revoke()`) a role — before Epic 3 makes attaching dangerous permissions to custom roles a routine action, which is the point at which this risk stops being theoretical.

---

## 2. Functional Requirements

Numbered items below are atomic and independently testable. Each is tagged:
- **[SPEC]** — directly stated by the story or EPIC-002's US-016 section.
- **[INFERENCE]** — not stated by the story; derived from the cited prior-art documents (US-015 design/threat model, existing code). Requires Gate 1 sign-off before being treated as settled.
- **[OPEN]** — the story itself flags this as unresolved; a functional requirement cannot yet be written with confidence. See §7.

### FR-1 [SPEC] — Privilege-based gate on `assign()`
`assign()` must deny granting a role to a target user when that role carries at least one permission from a defined "admin-equivalent" set, unless the caller holds an active `TENANT_ADMIN` assignment in the same tenant. (Story AC1.)
- Not yet defined by this FR: the exact contents of the "admin-equivalent" set (see Open Question 1) or the mechanism used to check it (design-phase decision).

### FR-2 [OPEN] — Symmetric gate on `revoke()`
The story's AC2 only commits to "`revoke()` is reviewed for the same gap" — it does not commit to a fix. No functional requirement can be written here until Gate 1 resolves whether revocation gets an identical, a narrower, or no privilege gate. See Open Question 2 for the scenario analysis this requires.

### FR-3 [SPEC] — Existing AC8 name-match behavior is preserved, not replaced
The existing name-match check (`RbacRoleNames.TENANT_ADMIN.equalsIgnoreCase(role.getName())`) must continue to gate assignment/revocation of the literally-named `TENANT_ADMIN` role exactly as it does today. FR-1 (and FR-2, if adopted) is additive: it must also catch admin-equivalent roles that are *not* named `TENANT_ADMIN`. (Directly stated: "is gated the same way the seeded `TENANT_ADMIN` role is" — the seeded role's existing gate is not being removed or weakened.)

### FR-4 [INFERENCE] — Self-assignment is not exempt
The privilege gate in FR-1 must apply regardless of whether `targetUserId` equals the actor's own user id. Basis: the story's own Background section names self-grant as the explicit exploitation scenario ("any holder of `user:write` may grant that role to anyone, including themselves"), and the existing AC8 name-match check already makes no such exemption. This is flagged [INFERENCE] rather than [SPEC] because the story's Open Question 5 asks specifically whether the *interaction* with AC8's self-assignment handling changes — the "does the gate apply to self-assignment" question is answered here; the "how does it interact with AC8's existing self-grant check" mechanics are not (see Open Question 5).

### FR-5 [SPEC] — Denial must be recorded through the existing audit path
Any assignment or revocation denied under the new gate must produce a `ROLE_ASSIGNMENT_DENIED` audit row via the existing `recordDenial`/`recordRoleAssignmentDenied` mechanism (US-014 AC4), consistent with how every other denial in `RoleAssignmentService` is already handled. This FR is agnostic to *which* `DenialReason` value is used — that choice is Open Question 4.

### FR-6 [OPEN] — Exploitation-side counter (`nexus.rbac.self_role_assignment`) continued relevance
The story's AC3 requires this counter to be "reviewed for continued relevance" once the gap closes. No functional requirement can be written (keep as-is / retarget / retire) until Gate 1 resolves this — see Open Question 3.

---

## 3. Non-Functional Requirements

| Category | Requirement / finding |
|---|---|
| **Performance** | No documented p95 latency or RPS target exists for `assign()`/`revoke()` in any source document inspected (story, EPIC-002, US-012/US-015 design docs). The privilege check will add at least one additional read (permission-set lookup for the target role) to an already-authenticated, admin-scoped, low-volume path (US-012's threat model records this endpoint family as intentionally *not* rate-limited because it is "reachable solely by the tenant's most privileged principal"). **[CONFIRM]** an explicit latency budget with the Architect before design. |
| **Scalability** | The role-permission set being checked is bounded at 7 (`RoleManagementPort#findPermissionsForRole`'s own Javadoc: "Bounded at `|permissions| = 7`"), so scale risk from this specific lookup is low if that method or an equivalent is reused. Not yet confirmed as the mechanism (design-phase decision). |
| **Availability** | No SLO stated for the RBAC role-assignment API anywhere in the inspected source. **[CONFIRM]** whether this story inherits US-012's/US-015's (unstated) availability posture or needs its own. |
| **Security** | This entire story *is* a security requirement — see §6/§7. One explicit posture requirement: consistent with the precedent set by US-015's AC11 (T-E18, "fail-closed on Q3 empty"), any new lookup this gate depends on (e.g., resolving the role's permission set, or the tenant's `TENANT_ADMIN` role id) must fail **closed** (deny) rather than open if the lookup is empty, unresolvable, or errors. |
| **Observability** | Must integrate with, not duplicate, the existing RBAC observability set: `nexus.rbac.dangerous_permission_granted` (mint-side, US-015), `nexus.rbac.self_role_assignment` (exploitation-side, US-015 RC-7), and the composed PromQL alert in `docs/features/US-015/monitoring.md` that pages when both fire for the same `tenantId`. This story's fix directly affects that composed alert's meaning (see Open Question 3) and must not be shipped without an explicit decision on what happens to it. |
| **i18n** | Not applicable — this is backend authorization logic with no new user-facing strings identified in the source material. **[CONFIRM]** if any frontend denial message needs updated copy (see Gap in §8). |
| **Audit / compliance** | Must preserve the existing `ROLE_ASSIGNMENT_DENIED` durable-audit guarantee (US-014 AC4) for any new denial path (FR-5). |

---

## 4. Edge Cases

1. **Role with an empty permission set** — must not be treated as "admin-equivalent" by default; the gate must only trigger on an actual match against the admin-equivalent set.
2. **Role carrying exactly one vs. all three dangerous permissions** — the story's AC1 wording ("carries any of…") implies any single match is sufficient; confirm this is intended rather than requiring all three.
3. **Role is both literally named `TENANT_ADMIN` *and* independently carries a dangerous permission** — both the existing name-match (FR-3) and the new privilege-match (FR-1) would trigger; the outcome (a single denial, not two, and no double-counted audit/metric) must be defined.
4. **TOCTOU: the target role's permission set changes between the check and the write.** Direct precedent: US-015's threat model T-E14 rated a non-locking read on the equivalent mint-side check as **High**. Whatever mechanism FR-1 uses must be evaluated against the same locking-vs-non-locking distinction (design-phase decision, but the *requirement* that this be treated with the same rigor as T-E14 is a Gate 1 concern, not something to leave implicit).
5. **Caller's own active-`TENANT_ADMIN` assignment is revoked concurrently with their own `assign()`/`revoke()` call.** Existing AC8 precedent already requires this to be a live, non-JWT-derived read (T-E7); FR-1's admin-status check must inherit the same freshness guarantee, not a JWT-derived shortcut.
6. **Tenant has no seeded `TENANT_ADMIN` role at all.** US-015's AC11 handles this by failing closed (T-E18). FR-1's equivalent must specify the same fail-closed behavior explicitly rather than leaving it to be discovered.
7. **Role's permission set changes *after* an assignment already exists** (e.g., a role gains `user:write` via `attachPermission` after users already hold it, non-admin-assigned, from before it became dangerous). This gate only evaluates at the moment of `assign()`/`revoke()` — it does not retroactively re-validate existing assignments. This mirrors the already-accepted AC10 staleness model but is a distinct, unaddressed question: **does an already-existing non-admin-granted assignment of a role that later becomes dangerous need to be surfaced/remediated**, or is forward-only enforcement acceptable? Not addressed by the story. See Gap in §8 and Open Question 7.
8. **Last-admin lockout (AC5) does not extend to custom dangerous roles.** Today's `revoke()` lockout guard (`lockActiveAssignmentIds` / "last active TENANT_ADMIN") only fires when `role.getName()` matches `TENANT_ADMIN` literally — it does not protect against revoking the last holder of a *custom* role that happens to carry `role:write`/`user:write`/`tenant:write`. This is a materially different mechanism from the admin-authorization gate this story is otherwise scoped around, and the story's AC2 wording ("the same gate") does not disambiguate which of the two mechanisms (AC8-style authorization gate, or AC5-style lockout protection) it means. See Open Question 8 (new, not in the story's own list).
9. **Self-assignment of an admin-equivalent, non-`TENANT_ADMIN`-named role** — see FR-4; must be tested as a distinct scenario from self-assignment of a non-dangerous role (which remains legitimate and should still only trip the existing `nexus.rbac.self_role_assignment` counter, not a denial).
10. **Permission denial vs. resource-not-found ordering** — existing code resolves tenant/role existence (404/403) before any admin check runs; the new gate must slot into that same ordering without changing existing 404-before-403 behavior for unrelated paths.
11. **Network/partial failures** — audit-write failure on a denial (already handled today as best-effort/non-blocking per `RbacAuditPort`'s contract) must behave identically for the new denial path; no new failure mode should be introduced.

---

## 5. Assumptions

1. US-015 has merged and its `hasActiveAdminAssignment` mechanism and `RbacDangerousPermissions` set exist as described — **settled fact**, verified directly in code (not an assumption requiring confirmation).
2. **[CONFIRM]** The "admin-equivalent" permission set for this story's gate is `RbacDangerousPermissions.NAMES` (`role:write`, `user:write`, `tenant:write`) unchanged from US-015's mint-side set. The story itself flags this as open (Open Question 1).
3. **[CONFIRM]** No new REST endpoint, request/response DTO, or public API contract change is in scope — the story describes only a change to `RoleAssignmentService`'s internal authorization logic. Neither the story nor EPIC-002's US-016 section states this explicitly; it is inferred from the story's exclusive focus on `assign()`/`revoke()` internals.
4. **[CONFIRM]** No frontend (Angular) change is in scope. Not addressed anywhere in the source material — see Gap in §8.
5. **[CONFIRM]** This story does not require a database migration. Inferred from the fact that all cited reusable mechanisms (`hasActiveAdminAssignment`, `findPermissionsForRole`, `RbacDangerousPermissions`) already exist; no new schema element is described anywhere in the story.
6. **[CONFIRM]** The existing bounded `DenialReason` enum (5 values today) either gets reused (`NOT_TENANT_ADMIN`) or gains exactly one new value — not an open-ended set. US-012's threat model recorded the enum's cardinality as a deliberately bounded, reviewed property ("Bounded cardinality (5 reasons)"); adding a value is a decision that should be made consciously, not incidentally.

---

## 6. Risks

| # | Risk | Severity | Mitigation |
|---|---|---|---|
| R1 | Story not prioritized/shipped before Epic 3 kickoff, allowing the accepted residual risk (RES-1/R-3) to become live at routine scale | **Critical** | Already tracked in the story/EPIC as a standing risk with an owner and a 2026-11-27 (or Epic-3-kickoff, whichever first) review deadline. Carried forward here, not newly identified. |
| R2 | AC2's "review" language is interpreted as satisfied by documentation alone, leaving `revoke()` ungated — reproducing the exact administrator-stripping hole (T-E17) the cited threat model already rated **High** and explicitly warned reads worse than fixing neither `assign()` nor `revoke()` | **High** | Gate 1 must produce an explicit accept/reject decision on symmetric `revoke()` gating (Open Question 2), not leave it to design-phase default. |
| R3 | Exposure window is **already live in production right now**: US-015 (custom roles + dangerous-permission attachment) has already merged (confirmed via repo history), so any tenant could already hold a non-admin-granted, admin-equivalent custom role today, before this story ships | **High** | Confirm with Security whether `nexus.rbac.dangerous_permission_granted` has fired in any environment since US-015 shipped (Open Question 1 in EPIC-002's own risk-acceptance record makes this the trigger that makes this story P0) and whether a one-time remediation/audit pass is needed for assignments made during the exposure window (Open Question 7). |
| R4 | AC5's last-admin lockout mechanism does not extend to custom admin-equivalent roles, creating an inconsistent protection model (name-matched `TENANT_ADMIN` is lockout-protected; a functionally identical custom role is not) | **Medium** | Explicit scope decision needed — Open Question 8. |
| R5 | Ambiguity over whether a new `DenialReason` is needed makes the new denial indistinguishable from a plain permission-absent denial in audit/alerting, undermining detectability that the story's own security rationale depends on | **Medium** | Resolve at Gate 1 or explicitly defer to design with a stated default (Open Question 4). |
| R6 | Widening `RoleAssignmentService`'s dependency graph to include `RoleManagementPort` (needed for a Q7-shaped permission lookup) is, per the story's own prior-art notes, not currently used by that service and may be a first-of-its-kind cross-dependency between these two `rbac` application-layer services in this direction | **Medium** | Architect must confirm whether this is an accepted pattern or needs an ADR (also see R7). |
| R7 | Per US-015's own design document (§0), expanding `assign()`/`revoke()`'s authorization contract — which is exactly what this story does — was explicitly called out as requiring "an ADR *and* a Gate 1 reopen on US-012" if done as part of Gate 2 improvisation. That conditional trigger did not fire during US-015 (Gate 2 accepted deferral instead), but this story is precisely the deferred work | **Medium** | Confirm with Architect whether this story requires a new ADR before/alongside design (Open Question 6). |
| R8 | `nexus.rbac.self_role_assignment`'s composed "page" alert (with `nexus.rbac.dangerous_permission_granted`) is the operational signal currently standing in for the fix this story delivers. If this story ships without an explicit decision on that counter/alert's fate, operators may continue treating a now-blocked scenario as a live paging concern (alert fatigue), or worse, silently lose the signal if someone removes it without replacement | **Medium** | Explicit decision required — Open Question 3. |

---

## 7. Open Questions

Consolidated: the five the story itself flags, plus three surfaced independently during this analysis (marked **[new]**).

1. **(PM / Security)** Is `RbacDangerousPermissions.NAMES` (`role:write`, `user:write`, `tenant:write`) the correct "admin-equivalent" set for gating role *assignment*, or does propagating an already-dangerous role warrant a broader/different set than gating permission-*attachment* did (US-015 AC11)? Has `nexus.rbac.dangerous_permission_granted` fired in any environment since US-015 shipped — per EPIC-002's own risk-acceptance record, that event alone is stated to make this story P0 immediately.
2. **(Security / Architect)** Does `revoke()` need the identical privilege gate as `assign()`? The cited threat model (`03b-threat-model.md` T-E17, §10.2) already argues that fixing only `assign()` "would leave an admin-strippable-by-non-admin hole and would be worse than fixing neither." Gate 1 needs either (a) explicit agreement with that conclusion and a symmetric requirement written into FR-2, or (b) a documented, reasoned rebuttal — not silence.
3. **(Security / SRE)** Is `nexus.rbac.self_role_assignment` (and its composed page-alert with `nexus.rbac.dangerous_permission_granted`) still needed once this story ships? Options include: retained as-is (still catches self-assignment of *non*-dangerous roles, a separate signal), narrowed/retargeted, or retired. This decision has an operational blast radius (alert routing) beyond this story's code.
4. **(Security / Architect)** Does this story need a new `DenialReason` value distinguishing "denied: target role is dangerous-permission-carrying" from the existing `NOT_TENANT_ADMIN` (used today for the name-match case)? Note the existing enum's cardinality was previously recorded as a deliberately bounded, reviewed property (5 values) in US-012's threat model — adding a 6th is a conscious decision, not a routine one.
5. **(Architect)** Self-assignment interaction: AC8's existing check already blocks a non-admin from granting `TENANT_ADMIN` to themselves via the name-match path. Once FR-1's privilege-match path also exists, do the two checks need a defined precedence/ordering (e.g., which one's `DenialReason` wins when both would independently deny), or is the new check purely additive for non-`TENANT_ADMIN`-named dangerous roles with no interaction to define?
6. **[new] (Architect)** US-015's own design document states that expanding `assign()`/`revoke()`'s authorization contract "requires an ADR *and* a Gate 1 reopen on US-012" if done as an extension of that story. That trigger did not fire during US-015 (Gate 2 accepted deferral instead of expanding scope) — but this story is exactly that deferred expansion. Does US-016 require a new ADR before design proceeds?
7. **[new] (Security / PM)** Given US-015 has already merged, tenants could already hold non-admin-granted, admin-equivalent custom-role assignments made during the exposure window between US-015's merge and this story's ship date. Does this story's scope include a one-time detection/remediation pass over existing assignments, or is the fix intentionally forward-only (new assignments/revocations only, no retroactive audit)?
8. **[new] (PM / Security)** AC2's phrase "the same gate" is ambiguous between two distinct existing mechanisms: (a) the AC8-style admin-authorization gate (this story's primary focus), and (b) the AC5-style last-admin-lockout protection, which today only fires for the literally-named `TENANT_ADMIN` role, not for a functionally-equivalent custom role. Does this story's scope include extending AC5's lockout protection to any admin-equivalent role, or is that explicitly out of scope (and if so, should a follow-on risk be recorded for it)?

---

## 8. Gaps

Material the story and its linked EPIC section leave entirely unaddressed:

1. **No explicit performance/latency/RPS target** for `assign()`/`revoke()` anywhere in the source material, before or after this change.
2. **No frontend/UI impact analysis.** The story is scoped entirely to `RoleAssignmentService`; nothing states whether any Angular-side role-assignment UI (e.g., a role picker that currently distinguishes `TENANT_ADMIN` by name) needs updated behavior once non-`TENANT_ADMIN`-named roles can also be gated.
3. **No remediation/backfill plan for the current exposure window** (see Open Question 7) — the story is framed entirely as a forward-looking code fix, with no mention of whether existing, already-created assignments need review.
4. **No success/acceptance test scenarios provided** beyond the three draft AC rows — no example request/response pairs, no explicit list of scenarios QA should cover (contrast with more mature stories like US-012/US-015, which had dedicated threat-model-driven test lists).
5. **No mention of whether this story gets its own `03b-threat-model.md`.** Given the extent to which this story exists specifically because of prior threat-modeling findings (T-E16/T-E17), and given the numbered-artifact convention in `docs/README.md` calls for a threat model on security-relevant designs, its absence from the story text is notable but likely just reflects that Gate 1 (this document) precedes that phase — flagged for completeness, not as a defect.
6. **No stated relationship to Epic 3's own entry criteria** beyond the "must land before Epic 3 kickoff" deadline — no detail on what Epic 3 specifically requires from this story's outcome (e.g., does Epic 3 have its own AC that depends on a specific `DenialReason` or metric shape from this story?).
7. **No explicit statement on backward compatibility** — whether existing integration tests (e.g., `RoleAssignmentEscalationIT`) are expected to continue passing unmodified, or whether this story is expected to extend that specific test class.

---

## Gate 1 Decisions (recorded 2026-09-09)

Resolved by the story owner (Md Nisar Ahmed, RBAC bounded-context tech lead / platform security owner) in response to this document's Open Questions §7. These are now **settled requirements**, not open questions, for Phase 2 (impact analysis) and Phase 3 (design) to build against.

| # | Open Question | Decision | Rationale |
|---|---|---|---|
| 1 | Permission set for the gate | **Reuse `RbacDangerousPermissions.NAMES` unchanged** (`role:write`, `user:write`, `tenant:write`) | Same set as US-015's mint-side gate; one source of truth, no new maintenance surface. FR-1 is now settled: gate on membership in this exact set. |
| — | Has `nexus.rbac.dangerous_permission_granted` fired in any environment since US-015 shipped? | **Not yet checked — action item, not a Gate 1 blocker.** Track as a pre-Phase-3 action for the story owner/SRE; does not block impact analysis. | Firing would make this P0 per the epic's own risk-acceptance record, but checking it is an operational lookup, not a requirements decision. |
| 2 | `revoke()` symmetric gate | **Yes — `revoke()` gets the identical privilege-based gate as `assign()`.** FR-2 is now settled and no longer [OPEN]: revocation of an admin-equivalent role requires the caller to hold an active `TENANT_ADMIN` assignment, exactly mirroring FR-1. | Accepts the threat model's (`03b-threat-model.md` T-E17, §10.2) explicit conclusion that fixing only `assign()` creates a worse, asymmetric admin-stripping hole. |
| 3 | `nexus.rbac.self_role_assignment` counter fate | **Retained, meaning narrows.** The counter and its composed page-alert (with `nexus.rbac.dangerous_permission_granted`) no longer indicate a live exploit once this story ships — the gate blocks the underlying escalation at the source. Recommended default (confirm at design/Gate 2): reinterpret the composed alert as a **canary on the fix itself** — in normal operation it should never fire for a dangerous-role self-assignment post-release; any occurrence signals a bug in this story's gate, not a successful attack. The counter's non-composed, non-dangerous-role signal (legitimate self-assignment) is unaffected and keeps its original meaning. | Defense-in-depth: keep the detection surface rather than delete it, but its operational meaning changes and must be documented, not left stale. FR-6 is now settled: retained, reinterpreted, not retired. |
| 6 | New ADR required? | **Yes.** An ADR must be drafted alongside Phase 3 design, per the explicit precedent set in US-015's own design document (§0) for exactly this class of change — expanding `assign()`/`revoke()`'s shipped authorization contract. | Follows established precedent rather than treating this as a routine bug fix; the design phase's `/design` step must produce this ADR before/alongside `03-design.md`. |
| 7 | Remediation/backfill for the exposure window | **Forward-only fix — out of scope for this story's code.** No backfill/remediation task is part of US-016. | Keeps story scope tight, matches the story's own framing as a code-level authorization fix. **Recommended follow-up action (not story scope):** the story owner should run a one-off audit query for any tenant already holding a non-admin-granted assignment of a role carrying `role:write`/`user:write`/`tenant:write`, to establish current exposure. This is an operational action, not a development task. |
| 4 | New `DenialReason` value | **Deferred to Phase 3 design**, not a Gate 1 blocker — does not change scope size. Recommended default for the Architect to confirm or override: add exactly one new value (e.g. distinguishing "denied: target role carries a dangerous permission" from the existing `NOT_TENANT_ADMIN` name-match reason), consistent with US-012's threat model treating the enum's cardinality as a deliberate, reviewed property. | A conscious one-value addition preserves detectability (FR-5/Compliance stakeholder need) without reopening the enum's bounded-cardinality discipline. |
| 5 | Self-assignment / AC8 precedence | **Deferred to Phase 3 design**, not a Gate 1 blocker. Recommended default: unify into a single condition — deny if the target role is literally named `TENANT_ADMIN` **or** carries any `RbacDangerousPermissions` member — producing one denial, not two independently-triggered checks. Exact `DenialReason` selection when both conditions hold is a design detail (see #4). | Avoids double-counted audit rows/metrics (Edge Case 3) and keeps the authorization logic as one gate, not two overlapping ones. |
| 8 | AC2 "the same gate" ambiguity — does scope include extending AC5's last-admin-lockout to custom admin-equivalent roles? | **Out of scope for US-016.** This story is scoped to the *authorization* gate (who may assign/revoke), per its own title ("gate role assignment/revocation by actual privileges") — not the *lockout* mechanism (preventing a tenant from reaching zero admins). Extending AC5-style lockout protection to custom dangerous roles is a materially different mechanism and a distinct risk. | **Action item:** record a follow-on risk/backlog entry for "last-admin-style lockout protection does not extend to custom admin-equivalent roles" so it isn't silently lost — to be filed by the story owner, not built here. |

**Net effect on FRs:** FR-2 and FR-6 move from [OPEN] to [SPEC] (settled by decisions #2 and #3 above). FR-1 remains [SPEC] with its permission-set ambiguity now resolved (decision #1). No new functional requirement is added for Open Questions #4, #5, #8 — they are explicitly deferred to Phase 3 with stated recommended defaults the Architect may confirm or override without returning to Gate 1, since none of them change this story's scope or point estimate.

---

## 9. Stakeholder Map

| Stakeholder | Interest / what they need from this story |
|---|---|
| Platform Security Owner (story author) | Confirmation that the propagate-side escalation chain (RES-1/R-3) is actually closed, not just documented as closed. |
| Product Manager | Prioritization decision (story is currently unestimated, unscheduled) against the hard Epic 3 deadline; sign-off on scope questions that affect story points (esp. Open Questions 2 and 7, which materially change scope size). |
| Architect | Design decisions flagged throughout: new port dependency (R6), possible ADR requirement (Open Question 6), mechanism for the permission-set check, locking-read discipline (Edge Case 4). |
| Security / Threat-model reviewer | Owns the underlying risk register entries (RES-1, T-E16, T-E17) this story is meant to close; needs the Gate 1 outcome to update those entries' status. |
| QA / Test Engineer | Needs concrete acceptance scenarios once Gate 1 resolves the open questions (currently absent — Gap 4); will extend or newly author IT-level tests analogous to `RoleAssignmentEscalationIT`. |
| SRE / Observability owner | Owns the composed `nexus.rbac.self_role_assignment` / `nexus.rbac.dangerous_permission_granted` page alert whose meaning changes once this story ships (Open Question 3, R8). |
| Tenant Admins (end users) | No workflow change expected for legitimate admin actions; may see a new denial reason/message if they attempt an action a non-admin was previously (incorrectly) able to perform on their behalf. |
| Compliance / Audit | Interested in whether the new denial path is durably audited (FR-5) and whether a `DenialReason` distinguishes this failure mode for audit review purposes (Open Question 4). |

---

## 10. Success Metrics

Pending Gate 1 resolution of the open questions above, the following would indicate the fix is working in production (exact targets/thresholds to be confirmed once mechanism is designed):

1. **Zero** successful `assign()` calls that grant an admin-equivalent (non-`TENANT_ADMIN`-named) role to a caller who does not hold an active `TENANT_ADMIN` assignment, measured from the point of deployment forward.
2. If `revoke()` is symmetrically gated (Open Question 2 resolved as "yes"): **zero** successful `revoke()` calls that strip an admin-equivalent role from a user, performed by a caller who is not an active `TENANT_ADMIN`.
3. The new gate's denial path fires correctly in adversarial test scenarios (unit/IT coverage) with **zero false positives** against legitimate admin flows in staging/pre-prod soak testing.
4. The composed `nexus.rbac.self_role_assignment` / `nexus.rbac.dangerous_permission_granted` "page" alert (`docs/features/US-015/monitoring.md`) either stops firing for this specific chain post-release, or is explicitly retargeted with a documented new meaning — not left firing on a scenario the fix has already blocked.
5. RES-1 (and its component findings T-E16/T-E17) in US-015's threat-model residual-risk table are updated from "High, accepted, forward-tracked" to a closed/resolved status, with this story cited as the closure reference — mirroring the pattern the code's own Javadoc already anticipates ("Do not delete this note when that story ships — replace it with the closure reference").
6. No regression in existing `RoleAssignmentEscalationIT` / `RoleAssignmentServiceTest` coverage for the pre-existing name-match behavior (FR-3).
