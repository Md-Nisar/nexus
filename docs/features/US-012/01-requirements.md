# US-012 — Requirement Analysis Document

**Feature:** Enable role assignment and revocation API
**Epic:** EPIC-002 (RBAC Foundation)
**Status:** **Gate 1 approved** — all Gate-1-blocking open questions resolved; see §11 Gate 1 Resolutions
**Analyst:** Business Analyst (requirements-only; no design/code in this document)

---

## 1. Context

EPIC-001 established *who* a caller is; US-009 built the tenant-scoped roles/permissions schema; US-010 populated the JWT and `/users/me` with resolved roles/permissions; US-011 built the reusable `@RequiresPermission` enforcement mechanism with no endpoint of its own to protect. US-012 is the first story to actually exercise all three: it is the **first controller in the `rbac` bounded context**, giving a Tenant Administrator an API to assign and revoke roles for users within their own tenant. It is also, per the story's own background note (forward-tracked from US-009's Gate-2 threat model), the *only* control standing between an ordinary self-registered user and the all-permissions `TENANT_ADMIN` role, because the bootstrap tenant design (pre-existing, EPIC-001) places self-registered members and the seeded admin role in the same tenant with no other backstop. This story is also the hard gate for Epic 3 (Tenant Management) kickoff, alongside US-009.

---

## 2. Functional Requirements

Numbered from the story's 8 ACs and Technical Notes, made atomic/testable. Each cites its source AC.

- **FR1** — `POST /api/v1/users/{userId}/roles` with a valid `{ "roleId": "..." }` body, where both the target user and the target role belong to the caller's own tenant, creates a new active (`revoked_at IS NULL`) `user_roles` row and returns `201`. *(AC1)*
- **FR2** — The `assigned_by` value on the created row is sourced exclusively from the authenticated caller's own principal (JWT subject) — never from the request body or any other request-supplied field. *(AC1; threat model T-S2)*
- **FR3** — `POST` requires the caller to hold `user:write` permission (enforced via `@RequiresPermission`, US-011); absence yields the existing `403 + RBAC_001` contract with no new shape. *(AC1, Technical Notes)*
- **FR4** — `DELETE /api/v1/users/{userId}/roles/{roleId}` sets `revoked_at` on the matching active row (never a hard delete) and returns `204`. *(AC2)*
- **FR5** — `DELETE` requires `user:write` permission. *(AC2)*
- **FR6** — `GET /api/v1/users/{userId}/roles` returns only the active (non-revoked) role assignments for the specified user. *(AC3)*
- **FR7** — `GET` requires `user:read` permission. *(AC3)*
- **FR8** — An assignment attempt (`POST`) where the target `userId` or the target `roleId` does not belong to the caller's own tenant — with the caller's tenant sourced exclusively from their own JWT/`AuthenticatedRequestDetails`, never request input — is rejected with `403`, regardless of whether the caller holds `user:write` in their own tenant. *(AC4)*
- **FR9** — When the target user's `TENANT_ADMIN` assignment is the only active `TENANT_ADMIN` assignment remaining in that tenant, an attempt to revoke it (`DELETE`) returns `409` with error code `RBAC_002`, and the row is not revoked. *(AC5 — see Assumption/Open Question on self-vs-any-actor scope, below)*
- **FR10** — The Redis cache key `permissions:{tenant_id}:{user_id}` is deleted for the affected user after every successful assignment. *(AC6)*
- **FR11** — The same cache key is deleted after every successful revocation. *(AC6)*
- **FR12** — Every successful role assignment writes an audit event `ROLE_ASSIGNED` containing at minimum `user_id`, `role_id`, `assigned_by`, `tenant_id`. *(AC7 — see Open Question 2 on the US-014 sequencing conflict and Open Question 11 on field-set discrepancy)*
- **FR13** — Every successful role revocation writes an audit event `ROLE_REVOKED` containing at minimum `user_id`, `role_id`, the revoking principal, `tenant_id`. *(AC7)*
- **FR14** — Assigning specifically the `TENANT_ADMIN` role requires the caller to hold an *active* `TENANT_ADMIN` assignment in the target tenant — generic `user:write` is insufficient. A caller who holds `user:write` by some other means but not an active `TENANT_ADMIN` assignment is rejected with `403`. *(AC8 — the story's own stated control for threat T-E1)*

**Explicitly not covered by any stated FR** (see §8 Gaps): behavior when `userId`/`roleId` in the path don't exist at all; behavior on a duplicate-active-assignment attempt; idempotency of `DELETE` on an already-revoked row; response DTO shape for `GET`; pagination for `GET`.

---

## 3. Non-Functional Requirements

**Performance**
- No endpoint-specific figure is stated in the story itself. `[INFERENCE]` the epic QA section's only endpoint-level figure — "200 RPS on a permission-guarded endpoint, p95 < 300ms" (EPIC-002 QA section) — is presumably meant to apply here too, since these are the epic's first real permission-guarded endpoints, but the story text does not say so explicitly.
- No figure is given for the cost of the lockout-guard `COUNT` query (AC5/Technical Notes) under load, nor for the combined cost of DB write + cache delete + audit write on a single request.

**Scalability**
- No stated ceiling on the number of role assignments per user or per tenant, and no pagination requirement for `GET /api/v1/users/{userId}/roles` — plausible to be small today (at most 2 system roles per user pre-US-015) but unstated as a constraint.

**Availability / SLO**
- No SLO number is stated for this story specifically. The story introduces two new external-dependency touchpoints on the write path (Redis delete, audit-event write) with no stated behavior for either failing independently of the primary DB write — see Edge Cases §4 and Risk R9/R11.
- The epic's broader "cache invalidation lag" risk (15-min TTL / 7-day refresh) is documented as accepted elsewhere in the epic for *normal* expiry, not for an *infra failure* at invalidation time — a distinct, unaddressed scenario here.

**Security**
- `assigned_by`/revoking-principal sourcing from the authenticated principal only (FR2, FR13) is explicit and threat-model-driven (T-S2, T-R1).
- Tenant isolation (AC4) is explicit for `POST` — see Open Question 4 on whether it is equally required for `GET`/`DELETE`, since the AC's own DoD text and Technical Notes ("validates user and role both belong to caller's `tenant_id` before **write**") name only the write path.
- The `TENANT_ADMIN`-grants-`TENANT_ADMIN` control (AC8) is the story's own named mitigation for a Critical self-escalation risk (T-E1) inherited from US-009's schema design — this is confirmed by the story's own risk register, not an inference.
- **Confirmed architectural fact (not an open question):** `TenantAwarePermissionEvaluator.hasPermission(Authentication, String)` (US-011) takes no tenant/resource parameter and performs zero cross-tenant or resource-ownership comparison — it only checks JWT `permissions[]` membership. Consequently, **AC4's tenant-isolation guarantee is not enforced by `@RequiresPermission` at all** and must be explicit logic in the new `RoleAssignmentService`, comparing the caller's own JWT-sourced `tenantId` against the target user's and target role's `tenant_id` loaded fresh from the DB.
- No rate-limiting requirement is stated for these endpoints (the story's own "Out of Scope: Bulk role assignment" only excludes a dedicated bulk endpoint, not scripted repeated single calls).

**Observability**
- AC7's audit-event requirement is explicit, but no separate observability requirement (structured logs, metrics, `traceId` correlation on 403/409 denials, dashboards/alerts on repeated AC8 self-escalation attempts) is stated anywhere — this mirrors a gap already identified in US-011's own requirements document for permission-check denials generally.

**i18n**
- No message text is specified for the `409 + RBAC_002` response beyond the code itself (unlike US-011's AC3, which gives verbatim message text for `RBAC_001`). No i18n statement one way or the other.

**Accessibility**
- Not applicable — backend-only story; the story's own "Out of Scope" explicitly excludes the Angular UI (Epic 3), and US-013 (frontend guard/directive) was already built prior to this story with no dependency on it.

---

## 4. Edge Cases

| # | Case | Expected per source material | Status |
|---|---|---|---|
| 1 | `userId` or `roleId` in the path does not exist at all | Not addressed by any AC | **Open — Question 6** |
| 2 | Attempt to assign a role the target user already actively holds (duplicate active assignment) | DB `active_key` unique constraint would raise a conflict at the persistence layer (US-009), but no AC/error code names the resulting HTTP status | **Open — Question 6** |
| 3 | `DELETE` on an assignment that is already revoked (not currently active) | Not addressed — idempotent 204 vs 404 unstated | **Open — Question 6** |
| 4 | Re-assigning a role after prior revocation (find-existing-row vs blind insert) | US-009 Test Scenario 8 covers the DB-level behavior (new active row inserts successfully); this story's service-layer logic for distinguishing "assign new" vs "reassign" is not yet built — no repository method exists for it today | **Gap — see §8** |
| 5 | Concurrent revocation of two different admins' `TENANT_ADMIN` assignments in the same tenant, each passing the lockout-guard `COUNT` check before either commits (TOCTOU race) | Not addressed — Technical Notes name a `SELECT COUNT(*)` guard with no stated locking mechanism | **Open — Question 7** |
| 6 | Caller in Tenant A issues `GET`/`DELETE` against a `userId` that exists but belongs to Tenant B | AC4's DoD text and Test Scenario 3 name only the assignment (`POST`) path; Technical Notes say the tenant check happens "before write" | **Open — Question 4 (potential tenant-data-leakage risk via `GET`)** |
| 7 | Redis unavailable at the moment cache invalidation runs (post-DB-write) | Not addressed — AC6 states the delete must happen but not what happens if it fails | **Open — Question 8** |
| 8 | Audit-event write fails after the DB write for assignment/revocation succeeds | Not addressed — no stated transactional relationship between the two | **Open — Question 2, 8 (also Risk R1)** |
| 9 | `DELETE` directly against the `user_roles` row (bypassing the API) | Blocked by the pre-existing US-009 DB trigger, `SQLSTATE '45000'` | Verified — pre-existing behavior, this story's Test Scenario 7 is a regression check, not new scope (see Assumption 1) |
| 10 | An existing `TENANT_ADMIN` assigns `TENANT_ADMIN` to themselves a second time, or assigns it to another user while already holding it | Implicitly allowed per AC8's wording (the check is "does the caller hold an active `TENANT_ADMIN` assignment," not "is this the caller's first grant") | `[INFERENCE]` not explicitly stated |
| 11 | Malformed/missing `roleId` in the `POST` request body | Not addressed — presumably a `400`, but no AC states validation behavior | **Gap — see §8** |
| 12 | Non-admin caller (holds `user:write` some other way) attempts to assign `TENANT_ADMIN` | 403, per AC8/Test Scenario 8 | Verified |

---

## 5. Assumptions

All flagged `[CONFIRM]` for Gate 1 stakeholder sign-off. None are treated as settled defaults.

- `[CONFIRM]` Test Scenario 7 (direct `DELETE` on `user_roles` blocked by trigger) verifies pre-existing US-009 DB behavior and requires zero new implementation in this story — included as a regression check, not new scope.
- `[CONFIRM]` AC5's title ("Self-revocation of last admin role blocked") implies the guard fires only when the *caller* is revoking their own last admin role, but the DoD text ("If user is the only active `TENANT_ADMIN`... revoking their admin role returns 409") and the Technical Notes' `COUNT(*) ... WHERE role_id = TENANT_ADMIN AND tenant_id = ?` query are both actor-agnostic — they describe a tenant-wide count, triggered by *any* caller (including a different admin) revoking the tenant's last active `TENANT_ADMIN` row. Assumed the broader, actor-agnostic reading is correct (matching the SQL), pending explicit confirmation given the AC's own title says otherwise.
- `[CONFIRM]` Tenant isolation (AC4) applies to all three endpoints (`POST`/`DELETE`/`GET`), not only `POST` as literally named in the AC's DoD text and Test Scenario 3, and not only to writes as Technical Notes' "before write" phrasing could imply.
- `[CONFIRM]` HTTP status for a `userId`/`roleId` that does not exist at all (as opposed to existing in the wrong tenant) — assumed `404`, not stated anywhere.
- `[CONFIRM]` HTTP status/error code for a duplicate-active-assignment attempt — assumed `409` (given the DB `active_key` constraint would raise a conflict), but no error code is named for this case distinct from `RBAC_002`.
- `[CONFIRM]` Idempotency behavior of `DELETE` on an already-revoked assignment — assumed either `204` (idempotent no-op) or `404`; not stated.
- `[CONFIRM]` `RoleAssignmentService`'s need to read the target user's `tenant_id`/existence from `identity.domain.User` implies a new cross-context read dependency from `rbac` into `identity` — mechanism (new port, shared query, direct repository dependency) is not specified anywhere and is design/impact-analysis work, not resolved here.
- `[CONFIRM]` Whether an audit-event write failure (AC7) should roll back the already-committed role-assignment/revocation DB write, or whether the two are intentionally decoupled (per CLAUDE.md's `REQUIRES_NEW`-audit-write convention) such that the assignment/revocation succeeds regardless of audit-write outcome.
- `[CONFIRM]` Whether a cache-invalidation failure (AC6, Redis unavailable) should fail the whole request (5xx) or be logged/retried asynchronously while the underlying DB write still succeeds.
- `[CONFIRM]` The `409 + RBAC_002` response body shape is unspecified beyond the code — assumed to follow the RFC 7807 problem-document convention (`code` + `traceId`, per CLAUDE.md), consistent with existing `GlobalExceptionHandler` behavior, but no message text or field list is given in the source material.
- `[CONFIRM]` Response DTO shape for `GET /api/v1/users/{userId}/roles` (which fields per role — `roleId`, `roleName`, `assignedAt`, `assignedBy`?) is not specified in the story.

---

## 6. Risks

| # | Risk | Severity | Mitigation |
|---|---|---|---|
| R1 | **Cross-context coupling for the audit write path is architecturally unresolved.** The only existing `REQUIRES_NEW`-transaction audit mechanism (`identity.application.service.SecureEventService`, per CLAUDE.md's stated convention) is `identity`-owned; `rbac` is a distinct bounded context. Having `rbac.application.RoleAssignmentService` call directly into `identity`'s `SecureEventService`/`AuthEventPort` is a cross-context dependency the project's own conventions generally discourage (and a class of coupling already flagged MEDIUM in `docs/features/US-010/06-code-review.md`, deferred at the time). Blocks AC6/AC7 design. | **Critical** | Explicit Gate 1/Gate 2 decision required (Open Question 1): new `rbac`-owned audit port + adapter into the same `auth_events` table, direct accepted cross-context dependency on `identity`'s `SecureEventService`, or move the abstraction to `common` so both contexts depend inward. |
| R2 | **AC7 vs. US-014 sequencing contradiction.** US-012's own AC7/Test Scenario 6 require `ROLE_ASSIGNED`/`ROLE_REVOKED` audit emission as part of *this* story's Definition of Done, and require it be integration-tested here. But `identity.domain.AuthEventType` has no such constants today, and EPIC-002's own dependency graph lists US-014 as "Blocked by: US-008, **US-012**" — i.e., US-014 is meant to come *after* US-012, contradicting AC7's requirement that the emission exist *within* US-012. This is a genuine contradiction between two source documents, not a matter of interpretation. | **Critical** | Gate 1 must resolve explicitly (Open Question 2): either (a) US-012 itself adds the `AuthEventType` constants and performs emission, making US-014 an extend/verify story, or (b) AC7 is descoped/deferred out of US-012 and the story text is corrected before implementation. |
| R3 | **TOCTOU race on the last-admin lockout guard.** The Technical Notes name a `SELECT COUNT(*) ... WHERE revoked_at IS NULL` check performed before revocation, with no stated locking strategy. Two concurrent revocation requests targeting two *different* admins in the same tenant could each pass the count check (count = 2, both see "not the last one") before either commits, resulting in a tenant left with zero active `TENANT_ADMIN`s — the exact lockout the guard exists to prevent. | **High** | Explicit Gate 2 design decision needed (Open Question 7) — e.g., `SELECT ... FOR UPDATE`/serializable check, or a DB-level constraint equivalent to the `active_key` technique. Not addressed anywhere in the story. |
| R4 | **Self-escalation to `TENANT_ADMIN` (T-E1).** Already named Critical in the story's own risk register: the schema (US-009) places no backstop between a self-registered member and the all-permissions admin role other than AC8's check. | **Critical** *(story's own rating)* | AC8's check + dedicated security test suite (Test Scenario 8) + mandatory code-review gate, per the story's own stated mitigation. |
| R5 | **Tenant isolation may not be enforced on `GET`.** AC4's DoD text and Test Scenario 3 name only the assignment (`POST`) path; Technical Notes' "validates ... before write" phrasing arguably excludes reads. If `GET /api/v1/users/{userId}/roles` performs no tenant check, a Tenant-A admin could enumerate Tenant-B users' role assignments by `userId` alone — a tenant-data-leakage vulnerability, not merely a UX gap. | **High** | Explicit Gate 1 confirmation required (Open Question 4) that tenant isolation applies uniformly to all three endpoints, with `GET`/`DELETE` cross-tenant test scenarios added alongside the existing `POST`-only Test Scenario 3. |
| R6 | Repository layer is missing two methods this story clearly needs: (a) counting active `TENANT_ADMIN` assignments per tenant for the lockout guard, (b) finding an existing `UserRole` row for `(userId, roleId)` regardless of active/revoked state, to distinguish "assign new" from "reassign after revocation" (per US-009 Test Scenario 8) and correctly hit the `active_key` constraint path rather than blindly inserting. | **Medium** | Flagged for impact-analysis/design; exact method shape is not this document's job to specify. |
| R7 | Ambiguity between AC5's title ("self-revocation") and its actor-agnostic DoD/SQL wording could lead to the wrong scope being implemented — either too narrow (only blocks self-revocation, leaving a gap where Admin B revokes Admin A's last-admin role) or the intended broader guard. | **Medium** | Resolve explicitly at Gate 1 (Assumption 2 / Open Question 3) before design. |
| R8 | No HTTP status/error code is defined for: nonexistent `userId`/`roleId`, duplicate-active-assignment attempts, or idempotent re-`DELETE` of an already-revoked row — risk of an inconsistent error contract being invented ad hoc during implementation. | **Medium** | Resolve at Gate 1 (Open Question 6) before design/API contract work. |
| R9 | Cross-context *read* dependency (rbac needing `identity.domain.User`'s `tenant_id`/existence) is architecturally unaddressed, the same class of issue as R1 but on the read side. | **Medium** | Fold into the same Gate 2 architecture discussion as R1 (Open Question 5). |
| R10 | No stated ordering/atomicity guarantee across the three side effects of a single request (DB write, cache invalidation, audit write) — a crash between steps could leave a stale cache entry or an unaudited assignment with no documented recovery path. | **Medium** | Resolve at Gate 2 alongside R1 (Open Question 8). |
| R11 | No rate-limiting requirement stated; "Out of Scope: bulk role assignment" excludes a dedicated bulk endpoint but not scripted repeated single-assignment calls achieving a similar effect. | **Low** | Confirm with PM whether this is an accepted gap for MVP (Open Question 9). |

---

## 7. Open Questions

1. **Architect (Critical, Gate 1/Gate 2-blocking)** — Does `rbac` get its own audit-event port/adapter writing into `auth_events`, does `rbac.application.RoleAssignmentService` depend directly on `identity`'s `SecureEventService`/`AuthEventPort` (an explicit, accepted cross-context call), or does the audit-event abstraction move to `common` so both contexts depend inward on a shared port? See Risk R1.
2. **PM / Architect (Critical, Gate 1-blocking)** — AC7 requires `ROLE_ASSIGNED`/`ROLE_REVOKED` audit emission as part of *this* story's DoD, verified by this story's own integration test (Test Scenario 6) — but `AuthEventType` has no such constants yet, and the epic's dependency graph lists US-014 as blocked *by* US-012. Does US-012 itself add the `AuthEventType` constants and perform emission (making US-014 a verify/extend story), or is AC7 descoped from US-012's DoD and the story text corrected? See Risk R2.
3. **Architect / QA** — Does the last-admin lockout guard (AC5) apply only when the caller revokes their *own* last active `TENANT_ADMIN` role (per the AC's title), or does it block *any* actor from revoking the tenant's last active `TENANT_ADMIN` assignment regardless of who holds it (per the AC's DoD text and the Technical Notes' actor-agnostic `COUNT` query)? Test Scenario 4's wording does not disambiguate either.
4. **Security / Architect** — Is tenant isolation (AC4) required uniformly on `GET` and `DELETE`, or only on `POST` as the AC's own DoD text and Test Scenario 3 literally name (with Technical Notes' "before write" phrasing arguably excluding reads)? If `GET` has no tenant check, this is a tenant-data-leakage vulnerability, not a UX gap — see Risk R5.
5. **Architect** — How does `rbac.application.RoleAssignmentService` obtain the target user's `tenant_id`/existence, given `rbac` and `identity` are separate bounded contexts and `identity.domain.User.tenantId` is the only source of truth for it? Is a new read-only port/adapter needed, and where does it live?
6. **PM / QA** — What HTTP status/error code applies to: (a) a `userId` or `roleId` that doesn't exist at all, (b) an attempt to assign a role the user already actively holds, (c) a `DELETE` on an already-revoked assignment? None of these are named in any AC.
7. **Architect** — Should the lockout-guard `COUNT` query and the subsequent revocation `UPDATE` be wrapped in a locking strategy to prevent a TOCTOU race where two concurrent revocations of two different admins both pass the count check before either commits, leaving zero active `TENANT_ADMIN`s in the tenant? See Risk R3.
8. **Security / Architect** — Should the audit-event write (AC7) and cache-invalidation (AC6) be transactionally coupled to the primary role-assignment/revocation write, or may each fail independently? What is the acceptable degraded behavior (retry, alert, silent gap) if the DB write succeeds but Redis or the audit write fails?
9. **PM** — Given "Out of Scope: bulk role assignment," is there any expectation of rate-limiting on the single-assignment/revocation endpoints to prevent scripted repeated calls from achieving a similar effect?
10. **Architect** — Per US-011's own established precedent (`InsufficientPermissionException` in `common.security`), should the new `RBAC_002` lockout exception (e.g. `LastAdminRoleException extends ConflictException`) live in `common.domain` or `rbac.domain`, given `GlobalExceptionHandler` (in `common.web`) needs to import whichever type it handles? Minor/Low-severity placement question, not blocking.
11. **PM / QA** — US-012's own AC7 names the audit payload as `user_id, role_id, assigned_by (assignment) or revoking principal (revocation), tenant_id`. US-014's AC1/AC2 (for the identical `ROLE_ASSIGNED`/`ROLE_REVOKED` event types) name a *different* field list: `user_id, role_id, role_name, assigned_by, tenant_id, correlation_id` (AC1) and adds `revoked_by` (AC2) — including `role_name` and `correlation_id`, both absent from US-012's own AC7. If US-012 is the story that actually performs the emission (per Open Question 2), which field list is authoritative?

---

## 8. Gaps

Missing from the source material entirely — not inferable, not addressed by any AC, Technical Note, or ADR:

1. No repository method exists yet for counting active `TENANT_ADMIN` assignments per tenant (needed for AC5), nor for finding an existing `UserRole` row for a given `(userId, roleId)` pair regardless of active/revoked state (needed to distinguish "assign new" from "reassign after revocation," per US-009 Test Scenario 8, and to hit the `active_key` constraint path correctly rather than blindly inserting). New methods will clearly be needed; exact shape is impact-analysis/design work.
2. No response DTO shape is specified for `GET /api/v1/users/{userId}/roles` (which fields per assignment).
3. No pagination requirement for the `GET` endpoint.
4. No validation-error behavior stated for a malformed/missing `roleId` in the `POST` body (presumably `400`, but unstated).
5. No observability requirement (structured logs, metrics, `traceId` correlation) distinct from the audit-event requirement itself — no requirement to alert on repeated AC8 self-escalation attempts, which is otherwise framed as the story's most security-critical control.
6. No i18n statement — or explicit "out of scope" — for any new error message text (`RBAC_002` has no message text given anywhere, unlike US-011's `RBAC_001`).
7. No rate-limiting requirement for the assignment/revocation endpoints.
8. No stated atomicity/ordering guarantee across DB write, cache invalidation, and audit write for a single request — no documented recovery path if one step fails after another has already committed.
9. No cross-context read mechanism named for `rbac` obtaining `identity.domain.User`'s `tenant_id`/existence.
10. No SLO/error-rate figure specific to this story (only the epic's generic 200 RPS / p95 < 300ms figure, which the story doesn't explicitly claim as its own).

---

## 9. Stakeholder Map

| Stakeholder | Interest |
|---|---|
| Tenant Administrators | Primary API consumer — first admin capability on the platform; needs to assign/revoke roles for users in their own tenant with clear, predictable error responses |
| Business Users (subject of assignment/revocation) | Indirect — access changes take effect within the documented refresh window (AC6); no direct interaction with this API |
| Security & Compliance | High stake — the story is this epic's primary control against the Critical self-escalation risk (T-E1) and the source of the audit trail requirement (AC7); also owns the cross-context audit-architecture decision (Open Question 1) and the field-set authority question (Open Question 11) |
| Architect | Owns nearly every open question here — cross-context audit-write coupling (Open Question 1), cross-context read dependency (Open Question 5), lockout-guard concurrency (Open Question 7), tenant-isolation scope (Open Question 4), exception package placement (Open Question 10) |
| PM | Owns the AC7/US-014 sequencing decision (Open Question 2, Gate 1-blocking), the self-revocation scope clarification (Open Question 3), and the rate-limiting/error-contract decisions (Open Questions 6, 9) |
| QA | Owns the ambiguity between AC5's title and its actual (actor-agnostic) scope (Open Question 3), and whether tenant-isolation test coverage extends beyond `POST` to `GET`/`DELETE` (Open Question 4) |
| US-013 (frontend) authors | Downstream consumer of `GET /api/v1/users/{userId}/roles` once a future admin UI exists (out of scope for US-013 itself, which reads via `AuthStore`/`/users/me`, not this endpoint) |
| Epic 3 (Tenant Management) authors | Hard dependency — this API is one of the two Epic 3 kickoff-gate stories (alongside US-009); inherits whatever tenant-isolation and error-contract decisions this story settles |
| US-015 authors | Will build `RoleManagementService` in the same `rbac` bounded context alongside `RoleAssignmentService` — inherits this story's tenant-scoping and cross-context patterns |

---

## 10. Success Metrics

No story-specific numeric metrics are stated in US-012 itself beyond its ACs' pass/fail contracts. Inherited from EPIC-002's stated success criteria, to the extent they apply to this story:

- Zero privilege-escalation findings involving role assignment in the pre-GA penetration test (epic-level; directly tied to AC8's control for T-E1).
- Role assignment/revocation reflected in JWT/`/users/me` within one token refresh cycle (epic business goal #2) — validated operationally via AC6's cache invalidation.
- 100% of role assignment/revocation events emitted to the audit stream (epic business goal #3) — contingent on Open Question 2's sequencing resolution; not yet achievable as stated if AC7 is descoped.
- Zero tenant-lockout incidents in production (no tenant left with zero active `TENANT_ADMIN`s) — tied to AC5 and contingent on Open Question 7's race-condition resolution.
- Zero cross-tenant role-assignment or role-visibility incidents — tied to AC4 and contingent on Open Question 4's scope resolution across all three endpoints.
- At least one Epic 3 admin surface built on this API with no contract changes required (epic's stated release-readiness bar, inherited).

No metric in any source document addresses ongoing monitoring/alerting on attempted AC8 self-escalation events, despite AC8 being framed as the story's most security-critical control — consistent with Gap 5 above.

---

## 11. Gate 1 Resolutions

Decisions below settle every Open Question from §7 and supersede the corresponding `[CONFIRM]` items in §5. Recorded here (not silently implied) so `/impact-analysis` and `/design` can cite fixed decisions rather than re-litigating them. Rationale for each is intentionally kept brief — the reasoning lives in the discussion that produced it; this section states the outcome.

| OQ | Decision | Rationale (short) |
|----|----------|--------------------|
| 1 (R1, Critical) | `rbac` defines its own outbound port, `rbac.application.port.out.RbacAuditPort`; `identity.infrastructure.audit` provides the adapter, delegating to `identity`'s existing `AuthEventPort`/`SecureEventService` (reusing the retry-buffer/`REQUIRES_NEW` machinery as-is). | Verified the only existing cross-context edge is `identity → rbac` (`JwtRs256Service` imports `RoleResolutionService`); `rbac` imports nothing from `identity` today. This resolution keeps that same direction — no new cycle, no duplicated audit infrastructure. |
| 2 (R2, Critical) | US-012 adds the `ROLE_ASSIGNED`/`ROLE_REVOKED` constants to `AuthEventType` and performs the emission itself (via the OQ1 port). US-014 becomes an extend/verify story (e.g. `ROLE_ASSIGNMENT_DENIED`, audit-query tooling), not a from-scratch build. | Only reading under which AC7 is achievable as written; consistent with the epic's own "US-014 blocked by US-012" ordering. |
| 11 | Audit event payload uses the superset from US-014's AC1/AC2: `user_id, role_id, role_name, assigned_by`/`revoked_by, tenant_id, correlation_id`. | Now that US-012 owns emission (OQ2), no reason to ship a narrower field set that US-014 would have to widen later. `role_name` and `correlation_id` are both already available at the call site for free. |
| 5 (R9) | New port `rbac.application.port.out.UserDirectoryPort` (e.g. `Optional<UUID> findTenantId(UUID userId)`), implemented by an adapter in `identity.infrastructure.persistence`. | Same shape and direction as OQ1 — `rbac` never imports `identity` directly. |
| 3 (R7) | Lockout guard (AC5) is tenant-wide/actor-agnostic, not self-revocation-only — matches the DoD text and the Technical Notes' actor-agnostic `COUNT` query. AC5's title should be corrected in the story to drop the "self-revocation" framing. | The tenant-wide reading is what actually prevents tenant lockout regardless of which admin triggers the last revocation; the title was simply imprecise. |
| 4 (R5, High) | Tenant isolation applies uniformly to `POST`, `GET`, and `DELETE`, not `POST` only. | Scoping it to `POST` only leaves `GET` open to cross-tenant assignment enumeration by `userId` — a real leak. Marginal cost: the target user must be loaded for `GET`/`DELETE` anyway to resolve the role rows. |
| 6 (R8) | Nonexistent `userId`/`roleId` → `404` via the existing `ResourceNotFoundException` (no new code). Duplicate active assignment → `409` with **new code `RBAC_004`** (not `RBAC_003` — EPIC-002 reserves that for US-015's system-role-immutability check). `DELETE` on an already-revoked assignment → `404` (no active resource left to revoke), not a silently-idempotent `204`. | Keeps the error contract consistent with existing `ResourceNotFoundException`/`ConflictException` conventions; avoids colliding with US-015's already-planned `RBAC_003`; avoids a `204` masking a client bug (double-revoke). |
| 7 (R3, High) | Lock the counted rows within the revocation transaction (`SELECT ... FOR UPDATE` on the tenant's active `TENANT_ADMIN` assignments) before the revoking `UPDATE`, so a concurrent revocation blocks rather than racing past the count check. Exact query shape is a `/design` (Gate 2) detail. | Standard technique, no schema change, closes the TOCTOU window described in R3. |
| 8 (R10) | Only the `user_roles` write is transactional/must-succeed. Cache eviction and the audit write are best-effort side effects performed after commit, following the identical existing pattern in `AuthEventPort.record`'s own contract ("must never throw or block... enqueue for bounded, backed-off retry"). | Reuses an established pattern rather than inventing new failure-handling; cache staleness is already bounded by the epic's accepted 15-min TTL. |
| 9 (R11, Low) | Rate limiting is out of scope for this story. | Consistent with the epic's existing "no bulk assignment" boundary; no cross-cutting rate limiter exists today beyond the auth endpoints. Revisit only if abuse is observed. |
| 10 | New exception `rbac.domain.LastAdminRoleException extends ConflictException`, carrying `RBAC_002`. Stays inside the `rbac` bounded context — no `common.domain` promotion. | `GlobalExceptionHandler`'s generic `ConflictException` handler dispatches by base type only (`e.code()`/`e.getMessage()`) and needs no import of a concrete subtype — unlike `AccountLockedException`/`InsufficientPermissionException`, which need dedicated handlers because they expose extra fields. `common.domain` promotion is reserved for exceptions `GlobalExceptionHandler` must reference by name; `RBAC_002` doesn't need that. |

**New error code registered by this story:** `RBAC_002` (last-admin lockout, 409) and `RBAC_004` (duplicate active assignment, 409). `RBAC_003` remains reserved for US-015.

**New ports registered by this story (consumed by `RoleAssignmentService`, implemented in `identity.infrastructure`):** `RbacAuditPort`, `UserDirectoryPort` — both in `rbac.application.port.out`.

---

### Cross-references
- `docs/story/2-rbac/US-012.md` — source story
- `docs/story/2-rbac/EPIC-002.md` — parent epic (PM/BA/ARC/QA sections, API table, RBAC data model, US-009/US-010/US-011/US-014/US-015 inline story text, Open Decisions)
- `docs/features/US-011/01-requirements.md` — template followed for this document; also the source of the confirmed `TenantAwarePermissionEvaluator` single-parameter fact restated in §3 here
- `docs/features/US-009/03b-threat-model.md` — source of T-E1, T-S2, T-R1, forward-tracked into this story's Background and AC1/AC5/AC7/AC8
- `docs/features/US-010/06-code-review.md` — prior MEDIUM finding on `rbac`/`identity` cross-context coupling, directly relevant to Risk R1/R9 and Open Questions 1/5
- `nexus-backend/src/main/java/com/example/nexus/rbac/domain/` — `Permission`, `Role`, `RolePermission`(+`RolePermissionId`), `UserRole` entities (US-009)
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/port/out/` — `UserRoleQueryPort`, `PermissionCachePort` (`evict()` implemented, unused until this story)
- `nexus-backend/src/main/java/com/example/nexus/common/security/` — `@RequiresPermission`, `TenantAwarePermissionEvaluator`, `InsufficientPermissionException`, `DenialReason`, `AuthenticatedRequestDetails` (US-011)
- `nexus-backend/src/main/java/com/example/nexus/common/web/GlobalExceptionHandler.java` — existing generic `ConflictException` (409) and `DomainException` (422) handlers, reusable as-is for AC5's `RBAC_002`
- `nexus-backend/src/main/java/com/example/nexus/identity/interfaces/rest/UserProfileController.java` — established `Authentication.getDetails()`-as-untyped-`Map` pattern via `AuthenticationDetailKeys`
