# US-014 — Requirement Analysis Document

**Feature:** Audit role assignment and revocation events
**Epic:** EPIC-002 (RBAC Foundation) | **Story points:** 3 | **Priority:** P0
**Analyst:** Business Analyst (requirements-only; no design/code in this document)
**Sources reviewed:** `docs/story/2-rbac/US-014.md`, `docs/story/2-rbac/EPIC-002.md` (full, incl. US-009–US-015 sections, Recommended Sprint Order, Open Decisions), `docs/features/US-012/01-requirements.md`, `02-impact.md`, `03-design.md`, `03b-threat-model.md`, `docs/features/US-013/01-requirements.md` (template precedent), plus direct inspection of: `AuthEventType.java`, `RbacAuthEventAdapter.java`, `RoleAssignmentService.java`, `RbacAuditPort.java`, `RbacAuditEvent.java`, `DenialReason.java`, `LastAdminRoleException.java`, `DuplicateRoleAssignmentException.java`, `GlobalExceptionHandler.java`, `JpaAuthEventRepository.java`, `V2__identity_schema.sql`, `RoleAssignmentAuditIT.java`, `AuthEventsAppendOnlyIT.java`.

---

## 1. Context

EPIC-002's RBAC foundation needs an immutable record of who granted or removed access to whom, so Security & Compliance can reconstruct an access history for any user in any tenant before Epic 3 ships any admin surface. US-014 is nominally the story that delivers this, but **the majority of it was already built as forward work inside US-012** (role assignment/revocation API): `RoleAssignmentService` already emits `ROLE_ASSIGNED`/`ROLE_REVOKED` events with the full field set via `RbacAuthEventAdapter`, on the existing append-only `auth_events` table, with no schema change. What genuinely remains open for this story is (a) a real, non-foregone decision on whether to build the story's own P1/optional AC4 (`ROLE_ASSIGNMENT_DENIED`), and if so, exactly which of four possible denial paths it covers and where the emission point lives, and (b) confirming AC5's query requirement and AC3's security-test evidence are satisfied by existing generic infrastructure rather than requiring new code. This document treats US-014 as an **extend/verify** story, consistent with `docs/features/US-012/02-impact.md`'s own framing ("US-014 becomes an extend/verify story... its AC4 (`ROLE_ASSIGNMENT_DENIED`) remains US-014 scope"), and focuses its analysis on the genuinely open decision, not on re-litigating settled US-012 work.

---

## 2. Functional Requirements

Numbered from the story's 5 ACs. Each states current status against verified code/test evidence, not assumption.

- **FR1** — Every successful role assignment writes a `ROLE_ASSIGNED` event containing `user_id` (the target), `role_id`, `role_name`, `assigned_by`, `tenant_id`, and `correlation_id`, within 1 second of the write. *(AC1)* — **Status: DONE.** `RoleAssignmentService.assign()` registers a post-commit side effect calling `RbacAuditPort.recordRoleAssigned`; `RbacAuthEventAdapter` writes `user_id`=target, `tenant_id`, and a `metadata` JSON with `roleId`, `roleName`, `assignedBy`, `traceId` (satisfying `correlation_id`). Proven by `RoleAssignmentAuditIT.should_writeValidRoleAssignedEventWithCorrectFields_when_assignSucceeds`. The "within 1s" latency bound is not itself asserted by any test (see Gaps).
- **FR2** — Every successful role revocation writes a `ROLE_REVOKED` event with the same field set plus `revoked_by`, within 1 second. *(AC2)* — **Status: DONE.** `RoleAssignmentService.revoke()` → `recordRoleRevoked` → metadata carries `revokedBy` in place of `assignedBy`. Proven by `RoleAssignmentAuditIT.should_writeValidRoleRevokedEventWithRevokedByField_when_revokeSucceeds`, which also asserts a `ROLE_REVOKED` row never carries an `assignedBy` key. Same "within 1s" caveat as FR1.
- **FR3** — `ROLE_ASSIGNED`/`ROLE_REVOKED` rows in `auth_events` are append-only: UPDATE/DELETE are blocked by an existing trigger with no new mechanism required. *(AC3)* — **Status: DONE, generically.** `trg_auth_events_no_update`/`trg_auth_events_no_delete` (`V2__identity_schema.sql`) block any `event_type`, proven event-type-agnostically by `AuthEventsAppendOnlyIT` (which uses literal event types like `"LOGIN_ATTEMPT"`, not RBAC-specific ones). No RBAC-specific test currently exercises this against a real `ROLE_ASSIGNED` row — see Open Question 4.
- **FR4** — A 403 or 409 response from role assignment/revocation MUST NOT write a `ROLE_ASSIGNED`/`ROLE_REVOKED` event as if it succeeded; a `ROLE_ASSIGNMENT_DENIED` event MAY be written instead. *(AC4, P1, DoD text itself says "may")* — **Negative half: DONE.** `RoleAssignmentService`'s failure paths throw before any post-commit side effect is registered (transaction rolls back, nothing runs) — confirmed by `RoleAssignmentAuditIT` for cross-tenant 403 (`should_writeNoAuditRow_when_assignFailsWithCrossTenantTarget`), duplicate 409 (`should_writeExactlyOneAuditRow_notTwo_when_secondAssignFailsWithDuplicate`), and already-revoked 404 (`should_writeNoSecondRevokedRow_when_revokingAlreadyRevokedAssignment`). **Positive half (the `ROLE_ASSIGNMENT_DENIED` event itself): NOT BUILT, and its own DoD marks it optional.** This is the one genuinely open decision in this story — see Open Question 1.
- **FR5** — `SELECT * FROM auth_events WHERE tenant_id = ? AND user_id = ? AND event_type IN ('ROLE_ASSIGNED','ROLE_REVOKED')` returns correct ordered history. *(AC5)* — **Status: satisfiable by existing schema/data with no new code**, but **not currently proven by any test** written against that literal query shape (`RoleAssignmentAuditIT` queries by `user_id` + single `event_type`, not the AC5 `IN (...)` two-type form, and orders implicitly by `created_at DESC LIMIT 1` for its own assertion purposes, not the AC's "ordered history" of *all* matching rows). See Open Question 3.

**Explicitly not covered by any AC, and not built:** no repository method, service method, or API endpoint exposes AC5's query to any caller — `JpaAuthEventRepository` remains `extends JpaRepository<AuthEvent, UUID> {}` with zero custom methods, and no controller in EPIC-002's endpoint table queries `auth_events`. This is consistent with the story's own "Out of Scope: Audit log UI (Epic 7)" and EPIC-002's Sprint Order (Epic 7 owns the UI); AC5 as written is a data-availability guarantee, not a shipped query surface.

---

## 3. Non-Functional Requirements

**Performance**
- AC1/AC2's "within 1s" is the only quantified NFR in the story. It is not contradicted by anything observed, but it is also not independently tested — the existing audit pipeline (US-008) is asynchronous/best-effort by design (`RbacAuditPort`'s own Javadoc: "implementations MUST NEVER throw and MUST NOT block"), and no test in `RoleAssignmentAuditIT` measures elapsed time between the triggering write and the audit row's `created_at`. [GAP]
- No RPS/p95 figure is stated for this story specifically; EPIC-002's general 200 RPS/p95<300ms figure is for permission-guarded endpoints, not for the audit side-channel itself. [GAP]

**Scalability**
- Not addressed. `auth_events` is a shared, ever-growing table across all event types (RBAC and non-RBAC); no retention/partitioning/archival policy is stated anywhere in this story or the epic. [GAP]

**Availability / SLO**
- `RbacAuditPort`'s contract is "never throw, never block" — a Redis-outage-style graceful-degradation posture already inherited from US-012/US-008, not newly introduced here. The T-R3 audit-write-loss path (ERROR log + `nexus.rbac.audit_write_failed` counter, in `RbacAuthEventAdapter`) is US-012 work, not US-014's, but US-014's AC1-AC3 rely on it for their "eventually written, never silently lost without a signal" guarantee.

**Security**
- Append-only enforcement (AC3) is DB-trigger-level, already generically proven (FR3 above).
- If AC4's `ROLE_ASSIGNMENT_DENIED` is built, its own security value (a denial trail for Security & Compliance) is the entire reason AC4 exists — but the AC's own wording makes it optional, creating a direct tension between "audit denial attempts" (compliance value) and "don't build non-essential paths" (the epic's demonstrated risk-acceptance pattern elsewhere, e.g. the 15-minute cache lag). See Open Question 1.
- Metadata JSON escaping (`role_name` adversarial-input round-trip) is already covered by US-012's `RbacAuthEventAdapter`/`RoleAssignmentAuditIT` work and applies unchanged to any denial-event payload that reuses the same adapter shape.

**Observability**
- No new metric or log requirement is stated in the story for AC4's denial event specifically. If built, it would need to avoid double-counting against `nexus.rbac.permission_denied` (403s) and `nexus.domain.conflict{code}` (409s), which `GlobalExceptionHandler` already emits for the same underlying denials (`handleInsufficientPermission`, `handleConflict`) — a `ROLE_ASSIGNMENT_DENIED` audit event and these existing operational metrics would be two independent signals for the same event, which is not itself a problem but is undocumented anywhere. [GAP]

**i18n**
- Not applicable — no user-facing text is introduced by this story (audit records are internal/compliance-consumed only).

**Accessibility**
- Not applicable — no UI surface (explicitly Out of Scope, Epic 7).

---

## 4. Edge Cases

- **Concurrent assign/revoke on the same (user, role) pair** — already covered by US-012's own concurrency-safety work (`active_key` unique constraint, `LastAdminLockoutIT`-class tests); US-014 has no additional concurrency surface of its own beyond auditing whatever US-012 already serializes.
- **Partial failure: DB write succeeds, audit write fails** — covered by the existing T-R3 mechanism (ERROR log + counter); not this story's gap to close, but its AC1/AC2 "every successful ... writes an event" wording is technically violated in that narrow failure window (the write succeeds, the event does not land) — the mitigation is "loud failure with a signal," not "guaranteed delivery." Not called out anywhere in the story text as an accepted exception to AC1/AC2's absolute wording. [GAP]
- **A 409 from something other than the four known denial types** — no other 403/409 currently exists on the role-assignment path per the code reviewed; if a future story (e.g. US-015) introduces a fifth denial type on an adjacent-but-different endpoint, whether it should also emit `ROLE_ASSIGNMENT_DENIED` is unaddressed.
- **Empty result set for AC5's query** — a user with no role-assignment history: not explicitly stated, but trivially correct by construction (`SELECT` returns zero rows, no special-casing needed).
- **Denial event volume if AC4 is built and mis-scoped** — if `ROLE_ASSIGNMENT_DENIED` were to cover the 409 duplicate-assignment case (a "benign client bug," per `RoleAssignmentService`'s own DEBUG-level, non-WARN treatment of that path), a noisy/retrying client could generate a disproportionate volume of audit rows for a non-security event, polluting the audit stream Security & Compliance is meant to trust. This is a direct argument for scoping AC4 narrowly if built at all — see Open Question 2.
- **Query without a composite `(tenant_id, user_id, event_type)` index** — AC5's literal query is served by the per-column `(tenant_id, created_at)` / `(user_id, created_at)` / `(event_type, created_at)` indexes individually, not a single composite covering all three predicates; at low-to-moderate `auth_events` volume this is very unlikely to cause a real performance issue, and the story's Technical Notes explicitly state "no schema changes." This is a documented-but-accepted tradeoff, not a blocker — but it is a real gap if `auth_events` volume grows into a regime where MySQL's optimizer no longer picks an efficient plan across three separate single-column indexes.

---

## 5. Assumptions

Each flagged `[CONFIRM]` requires explicit stakeholder sign-off.

1. AC1/AC2's "within 1s" is a soft, best-effort target consistent with the existing asynchronous audit pipeline's design, not a hard SLA requiring new latency instrumentation or a test assertion. **[CONFIRM — PM/Architect]**
2. AC5 is satisfied by proving the literal query returns correct results against the existing table/data — no new repository method, service method, or API endpoint is required, because no consumer (Epic 7's Audit Log UI) exists yet to call one. **[CONFIRM — Architect/PM]**
3. AC3's existing generic append-only proof (`AuthEventsAppendOnlyIT`, which uses non-RBAC event-type literals) is accepted as sufficient evidence for AC3 without a dedicated `ROLE_ASSIGNED`-specific security test, on the basis that the DB trigger is event-type-agnostic by construction. **[CONFIRM — QA/Security]**
4. **[RESOLVED — see §7 Decisions]** AC4 (`ROLE_ASSIGNMENT_DENIED`) will be built, scoped to the two 403 authorization-denial paths only (`CROSS_TENANT_TARGET`, `NOT_TENANT_ADMIN`) — excluding the two 409 conflict paths (duplicate assignment, last-admin lockout), which are benign conflicts/races, not security-relevant denial attempts.

---

## 6. Risks

| # | Risk | Severity | Mitigation |
|---|---|---|---|
| R-1 | AC4 is explicitly optional ("may write") with no default stated either way. If left unresolved past Gate 1, the story could ship with a silent scope gap that Security & Compliance later discovers by absence (no denial trail exists) rather than by an explicit accepted-risk decision. | **Medium** | **RESOLVED (§7 Decisions):** build AC4, explicitly decided rather than defaulted. |
| R-2 | If `ROLE_ASSIGNMENT_DENIED` is built and scoped to all four denial types (two 403s + two 409s) rather than the narrower authorization-only set, the audit stream could be polluted with high-volume, low-security-value duplicate-assignment "denials" from ordinary client retries — undermining the audit trail's trustworthiness for the very use case (reconstructing who had access to what) the story exists to serve. | **Medium** | **RESOLVED (§7 Decisions):** scoped to the two 403 authorization denials only; the two 409 conflicts excluded. |
| R-3 | The natural emission point for a denial event is `GlobalExceptionHandler`'s existing `InsufficientPermissionException`/`ConflictException` handlers — both shared, generic, RBAC-agnostic infrastructure used by every feature in the codebase, not just role assignment. Adding RBAC-specific audit-emission logic there risks coupling a generic cross-cutting handler to one bounded context's concerns, or (if done carelessly) firing a `ROLE_ASSIGNMENT_DENIED` event for an unrelated 403/409 that happens to share the same exception type. | **Medium–High** (correctness/coupling risk, not security) | **RESOLVED (§7 Decisions):** emit from `RoleAssignmentService` itself, at the exact throw site — `GlobalExceptionHandler` stays untouched and RBAC-agnostic, eliminating the coupling/misattribution risk by construction rather than mitigating it after the fact. |
| R-4 | AC1/AC2's "within 1s" wording is technically violated in the narrow window where the DB write succeeds but the post-commit audit write fails (T-R3's own accepted failure mode) — the event is not written "within 1s," it is never written until/unless retried. This gap pre-dates US-014 (it is inherited from US-012's design) but US-014's ACs are the ones making the absolute claim. | **Low** | Already mitigated operationally by the ERROR log + `nexus.rbac.audit_write_failed` counter (US-012 T-R3); recommend the AC's wording be read as "unless the write itself fails, in which case an operator alert fires" rather than a hard guarantee — a documentation clarification, not new code. |
| R-5 | No composite index exists on `(tenant_id, user_id, event_type)` for AC5's query; at scale, MySQL may not efficiently serve a three-predicate query across three independent single-column-paired indexes. | **Low** (accepted per story's own "no schema changes" Technical Note) | Documented as an accepted tradeoff, consistent with the story's own text; revisit only if `auth_events` volume or query frequency materially increases (e.g., once Epic 7's Audit Log UI ships and issues this query interactively). |

---

## 7. Decisions (Gate 1 — resolved by product owner delegation, 2026-08-22)

The five open questions below were raised for stakeholder confirmation; the product owner delegated the call back to the assistant ("It's upon you, choose the best"). Decisions recorded here are final for this story's scope — Gate 2 (design) proceeds on this basis, not as open questions.

1. **Build AC4's `ROLE_ASSIGNMENT_DENIED` — YES.** The story's persona is Security & Compliance; an immutable, tenant/user-queryable record of *attempted* privilege escalation has forensic value the existing WARN log + `nexus.rbac.permission_denied` counter cannot provide (those are operational signals — mutable in effect, not permanent audit records, and not queryable by the AC5 shape). This is materially reinforced by EPIC-002's own T-E1 finding: self-registered bootstrap-tenant users sit one denied check away from `TENANT_ADMIN` — a denied escalation attempt is exactly the event a compliance audit trail exists to capture. Cost is low given the emission-point decision below, so the "don't build non-essential paths" counter-argument doesn't hold once the cost is priced correctly.
2. **Scope — 403s only (`CROSS_TENANT_TARGET`, `NOT_TENANT_ADMIN`).** The two 409 conflicts (duplicate assignment, last-admin lockout) are excluded — they are benign conflicts/races (the codebase's own DEBUG-vs-WARN log-level distinction already reflects this informally), and including them risks polluting the audit trail with retry noise, undermining the exact trustworthiness property the story exists to deliver (per Risk R-2).
3. **AC5 — test-only, confirmed.** Satisfied by a JDBC-based integration test proving the literal `SELECT ... WHERE tenant_id = ? AND user_id = ? AND event_type IN (...)` query returns correct, `created_at`-ordered results (ascending, oldest-first, matching "history" semantics), mirroring `RoleAssignmentAuditIT`'s existing pattern. No new `JpaAuthEventRepository` method, no new API endpoint — no consumer exists pre-Epic 7.
4. **AC3/Test Scenario 4 — add a lightweight dedicated test.** Two additional test methods (not a new IT class) extending the existing `RoleAssignmentAuditIT`/`AuthEventsAppendOnlyIT` pattern: insert a literal `ROLE_ASSIGNED` row, assert the existing trigger blocks UPDATE with `SQLSTATE '45000'`. The underlying mechanism is already proven generically, but the marginal cost of a compliance-traceable, AC-literal test is trivial, and it is precisely the artifact a compliance auditor or pen tester will ask to see mapped 1:1 to the story's own Test Scenario 4.
5. **Emission point — inside `RoleAssignmentService`, not `GlobalExceptionHandler`.** `RoleAssignmentService` already owns every authorization semantic `@RequiresPermission` cannot express (per US-012's `03-design.md`) and is the single place that already knows exactly which of the two denial reasons occurred, at the exact moment it occurs. Call `RbacAuditPort.recordRoleAssignmentDenied(...)` (new port method, same `REQUIRES_NEW`/T-R3-safe adapter pattern as the success path) immediately before throwing `InsufficientPermissionException`. This resolves Risk R-3 by construction — `GlobalExceptionHandler` remains untouched and stays RBAC-agnostic, with no risk of misattributing an unrelated feature's 403 to a role-assignment denial.

---

## 8. Gaps

- The story states "within 1s" for AC1/AC2 but no test in the existing suite measures or asserts this latency bound; it is unclear whether this figure was intended as an informal descriptor of "the existing async pipeline is fast enough" or a genuine SLA requiring instrumentation.
- No retention, archival, or partitioning policy exists anywhere for `auth_events` as it grows to include high-frequency RBAC events indefinitely — not addressed by this story, the epic, or (per available sources) any other story reviewed.
- No stated behavior for what "correct ordered history" in AC5 means precisely (ascending vs. descending by `created_at`; tie-breaking on identical timestamps) — the AC's own SQL has no `ORDER BY` clause, so "ordered" is asserted by the AC's prose but not encoded in its own literal query.
- No consumer of AC5's query is specified anywhere in this repo's visible endpoint table — the story's own Dependencies section confirms this ("Blocks: none — consumed by Epic 7"), but that leaves AC5 as a data-shape guarantee with no code surface to attach a requirement-traceable test to beyond a standalone integration test.
- If AC4 is built, no source document specifies the exact field set for a `ROLE_ASSIGNMENT_DENIED` event's metadata (e.g., should it carry the attempted `role_id`/`role_name` even though the assignment never happened? Should it carry the specific denial reason/error code?) — entirely undefined by the story.

---

## 9. Stakeholder Map

| Stakeholder | Interest / need |
|---|---|
| Security & Compliance | Direct beneficiary — the story's own "As a" role. Needs the audit trail to be trustworthy (accurate, not noisy, not silently incomplete) more than needs it to be exhaustive; owns the AC4 build/no-build call jointly with PM (Open Question 1). |
| PM | Owns the AC4 scope decision and whether it's worth the marginal effort against the epic's demonstrated risk-acceptance pattern; owns sign-off on treating AC5 as a data-guarantee with no shipped query surface. |
| Architect | Owns where a denial-emission point would live if built (Open Question 5) and confirms AC5's test-only satisfaction approach (Open Question 3). |
| QA | Owns whether AC3's existing generic test is sufficient evidence or a dedicated RBAC-specific test is needed for compliance traceability (Open Question 4); owns writing the AC5 JDBC-based IT if not already sufficiently covered by `RoleAssignmentAuditIT`'s existing per-event-type queries. |
| Epic 7 (Audit Log UI) team | Future consumer of AC5's query shape; not gating this story, but the eventual reason AC5 exists at all. |
| Tenant Administrators | Indirect — their assign/revoke actions are what gets audited; no direct interaction with this story's output. |
| Dev teams (future features) | Indirect — the append-only, queryable `auth_events` pattern this story confirms/extends is the same one any future audited event type will reuse. |

---

## 10. Success Metrics

The story states no success metrics of its own; the following are **[INFERENCE]**, proposed for stakeholder confirmation:

- 100% of successful role assignments/revocations have a corresponding `auth_events` row within the epic's stated business goal #3 ("100% of role assignment/revocation events emitted to the audit stream") — already effectively met by US-012's shipped work; this story's job is to confirm it, not newly achieve it.
- Zero `ROLE_ASSIGNED`/`ROLE_REVOKED` rows are ever successfully modified or deleted in production (continuously true by DB-trigger construction; monitorable only via absence of any successful UPDATE/DELETE attempt reaching the trigger, which is not itself instrumented as a metric anywhere).
- If AC4 ships: `nexus.rbac.audit_write_failed` and any new denial-specific counter remain at zero unexplained increments in steady-state production (i.e., failures are rare and always explained by a real incident, not a systemic bug).
- Epic 7's Audit Log UI (when built) can answer "who had access to what, and when" using AC5's query shape with no schema or query-contract changes required from this story.
