# US-015 — Requirement Analysis Document

**Feature:** Enable role and role-permission management API
**Epic:** EPIC-002 (RBAC Foundation)
**Status:** **Gate 1 approved.** All open questions resolved — see §11, including OQ1/OQ2 (Critical/High), resolved by explicit stakeholder decision and folded into the story as new AC11/AC12 (`docs/story/2-rbac/US-015.md`).
**Analyst:** Business Analyst (requirements-only; no design/code in this document)

---

## 1. Context

US-009 seeded exactly two roles per tenant (`TENANT_ADMIN`, `MEMBER`) via migration with no way to create, list, or reconfigure roles afterward. US-010–US-014 built JWT population, permission enforcement, the first assignment API (`RoleAssignmentService`/`UserRoleController`, US-012), and its audit trail (US-014). US-015 is the last piece of the `rbac` bounded context's CRUD lifecycle: it lets the platform (and, later, an Epic 3 Tenant Admin UI) create custom tenant-scoped roles and attach/detach permissions to them, while keeping the two seeded system roles immutable through this API. It is explicitly **non-gating** for Epic 3 — the kickoff gate remains US-009 + US-012 only — and is scheduled in Sprint 5 alongside US-013.

---

## 2. Functional Requirements

Numbered from US-015.md's 10 ACs and Technical Notes, made atomic/testable. Each cites its source AC. Status-code resolutions below use US-015.md's text (already edited to resolve three ambiguities) as authoritative over EPIC-002.md's stale inline copy — see §11 OQ3/Gate 1 Resolution.

- **FR1** — `POST /api/v1/roles` with `{ "name": "...", "description": "..." }` creates a role scoped to the caller's own tenant with `is_system_role = FALSE`; returns `201`; requires `role:write`. *(AC1)*
- **FR2** — The role's `tenant_id` is sourced exclusively from the caller's own authenticated tenant context, never from the request body (no tenant field appears in AC1's example body). `[INFERENCE]`, by direct analogy to `RoleChangeActor`/`assigned_by` sourcing in US-012 (FR2 of that story). *(AC1, Technical Notes)*
- **FR3** — `GET /api/v1/roles` returns only roles belonging to the caller's own tenant; requires `role:read`. *(AC2)*
- **FR4** — `GET /api/v1/roles/{roleId}/permissions` returns the role's assigned permissions; `404` (`ROLE_NOT_FOUND`) if the role doesn't exist anywhere, `403` (`CROSS_TENANT_TARGET`) if it exists but belongs to another tenant; requires `role:read`. *(AC3, resolved in US-015.md to match `RoleAssignmentService.resolveRoleInTenant`)*
- **FR5** — `POST /api/v1/roles/{roleId}/permissions` with `{ "permissionId": "..." }` creates a `role_permissions` row; returns `201`; requires `role:write`. *(AC4)*
- **FR6** — `DELETE /api/v1/roles/{roleId}/permissions/{permissionId}` removes the row; returns `204`; requires `role:write`. *(AC5)*
- **FR7** — `GET /api/v1/permissions` returns the 7 code-seeded permissions; requires `role:read`. *(AC6)*
- **FR8** — Any write (`POST`/`DELETE`) on `/api/v1/roles/{roleId}/permissions` targeting a role with `is_system_role = TRUE` returns `409 + RBAC_003`, regardless of whether the caller otherwise holds `role:write` — scoped **only** to these two endpoints; no role-update endpoint exists in this story's scope (confirmed independently: `roles` carries no `UPDATE` DB grant per US-009 AC9/ADR-0014 D6, so an "editing the role itself" case is not just descoped but not even executable against this DB user). *(AC7, resolved in US-015.md — see §11 OQ3 on the epic's stale copy)*
- **FR9** — Tenant isolation applies to the role-scoped endpoints (`GET`/`POST`/`DELETE` under `/roles/{roleId}/permissions`): `404` if the target role doesn't exist anywhere, `403` (`CROSS_TENANT_TARGET`) if it exists but belongs to another tenant. `GET /api/v1/roles` itself satisfies tenant isolation by result-filtering (FR3), not by a 403/404 branch, since the collection is inherently scoped to the caller's tenant. *(AC8, resolved; mirrors US-012 AC4/Gate-1 Resolution 4)*
- **FR10** — Creating a role with a name already used (case-insensitively, per the `uq_roles_tenant_name` collation documented in `RbacRoleNames`) within the caller's own tenant returns `409`; the same name in a different tenant succeeds. *(AC9)*
- **FR11** — After a role's `role_permissions` change, no bulk cache invalidation is performed; affected users see the change within the existing 15-minute Redis TTL / 7-day token-refresh window — an accepted, already-ratified decision (ADR-0013 D4), not an open design question for this story. *(AC10)*
- **FR12** — All six endpoints are protected by `@RequiresPermission` (US-011); a missing permission yields the existing `403 + RBAC_001` contract with no new shape. *(Technical Notes)*
- **FR13** — All endpoints are gated behind `feature.nexus-us015-rbac-role-management.enabled`, defaulted `false` in `application.yml`, enabled per-environment — per the established per-story kill-switch convention (US-012's `feature.nexus-us012-rbac-role-assignment.enabled`), independent of the story's own "Feature flag required: No" field, which tracks business-facing flags only, not this technical convention. *(US-015.md's added note, confirmed against the live `feature:` block in `application.yml`)*

**Explicitly not covered by any stated FR** (see §8 Gaps): response DTO shapes for any of the six endpoints; pagination for `GET /api/v1/roles`/`GET /api/v1/permissions`; validation rules for `name`/`description` in the `POST /roles` body; behavior for a nonexistent `permissionId`; behavior for a duplicate role-permission attachment; idempotency of `DELETE` on an already-detached/never-attached permission; any audit-event requirement for role creation or role-permission changes.

---

## 3. Non-Functional Requirements

**Performance**
- No endpoint-specific figure is stated. `[INFERENCE]` the epic QA section's generic "200 RPS on a permission-guarded endpoint, p95 < 300ms" presumably applies, as it did for US-012, but the story text does not say so.
- No figure for the cost of the role-name-uniqueness check or the `is_system_role` guard under load — both are cheap (a unique-index insert-time check and a boolean read on an already-loaded row), so this is a low-severity gap, not flagged as a risk.

**Scalability**
- No ceiling is stated on the number of roles a tenant may create, and no pagination requirement for `GET /api/v1/roles`. Unlike US-012's identical gap (where the collection was bounded to ≤2 system roles per user pre-US-015), **this story is the one that removes that bound** — it is the first mechanism that lets a tenant's role count grow without limit. See Risk R4.

**Availability / SLO**
- No SLO number specific to this story. AC10/ADR-0013 D4 already settle the cache-lag question (accepted, not a new failure mode to design around).

**Security**
- Tenant isolation (AC8) and the 403-vs-404 resolution follow the already-proven `RoleAssignmentService.verifySameTenant`/`resolveRoleInTenant` precedent exactly — low implementation risk for that part specifically.
- **Confirmed architectural fact:** `role.isSystemRole()` (the `Role` entity's `systemRole` boolean field) is a directly-readable value on the same `Role` row already loaded by `resolveRoleInTenant`-style resolution — no extra query is needed for the AC7 guard, and there is no name-matching ambiguity (unlike AC8's `TENANT_ADMIN` name-based check in `RoleAssignmentService`, `is_system_role` is a plain boolean).
- **Not confirmed and not addressed anywhere in the source material:** whether this story reopens the exact self-escalation gap `RoleAssignmentService`'s own Javadoc (lines 79–91) forward-tracks as "a future custom-roles story must close." See Risk R1 / Open Question 1 — this is the single most significant finding of this analysis and is **not resolved** in §11.
- No rate-limiting requirement is stated, consistent with the epic's pattern elsewhere.

**Observability**
- The existing generic `ConflictException` handler in `GlobalExceptionHandler` already increments a `nexus.domain.conflict{code=...}` counter for any `ConflictException` subtype, so a new `SystemRoleImmutableException` (`RBAC_003`) or a new duplicate-role-permission exception get basic trend-line metrics "for free," with no new instrumentation required — a positive precedent, not a gap.
- No requirement is stated for structured logging/alerting on repeated `RBAC_003` attempts (a plausible probing signal, analogous to how US-012's AC8 denials are WARN-logged with a dedicated event name in `RoleAssignmentService`) — unaddressed here.
- **No audit-event requirement is stated at all** for role creation or role-permission attach/detach, in contrast to US-012's explicit AC7/US-014's dedicated audit story for role *assignment*. See Risk R2 / Open Question 2.

**i18n**
- No message text is specified for `RBAC_003` beyond the code itself (contrast: `RBAC_002`/`RBAC_004` already have committed literal text in `LastAdminRoleException`/`DuplicateRoleAssignmentException`). See §8 Gaps.

**Accessibility**
- Not applicable — backend-only story, consistent with the epic's Epic-3-UI exclusion.

---

## 4. Edge Cases

| # | Case | Expected per source material | Status |
|---|---|---|---|
| 1 | `roleId` in path doesn't exist at all (any of the three role-permissions endpoints) | `404 ROLE_NOT_FOUND`, per AC3/AC8's resolved text and the `resolveRoleInTenant` precedent | Resolved by story text + precedent |
| 2 | `roleId` exists but belongs to another tenant | `403 CROSS_TENANT_TARGET`, per AC3/AC8's resolved text | Resolved by story text + precedent |
| 3 | `permissionId` in the `POST` body doesn't exist at all | Not addressed by any AC. Permissions are **not** tenant-scoped (no `tenant_id` column on `permissions`), so there is no analogous "exists in wrong tenant" case for this field — only exists/doesn't. | **Open — Question 5; resolved at Gate 1 as 404** |
| 4 | Permission already attached to the target role (duplicate `role_permissions` row) | Not addressed by any AC or Test Scenario; the composite PK `(role_id, permission_id)` (US-009) would raise a DB conflict at insert time | **Open — Question 5; resolved at Gate 1 as 409 (new code)** |
| 5 | `DELETE` on a role-permission pairing that was never attached, or already removed | Not addressed — idempotent `204` vs `404` unstated | **Open — Question 5; resolved at Gate 1 as 404, matching US-012's identical Gate-1 resolution for `user_roles` revoke** |
| 6 | Role in another tenant **and** is a system role simultaneously (e.g., probing Tenant A's `TENANT_ADMIN` from Tenant B) | Not addressed — which check (tenant vs. `is_system_role`) takes precedence, and does the response leak system-role status of an inaccessible role? | **Open — Question 4; resolved at Gate 1 via `RoleAssignmentService` precedent (tenant check always first)** |
| 7 | `GET /roles/{roleId}/permissions` on a freshly created custom role with zero permissions attached | Not stated; standard REST convention is an empty array, `200` | `[INFERENCE]` — Assumption, flagged `[CONFIRM]` |
| 8 | `GET /roles/{roleId}/permissions` or a write against a **system role in the caller's own tenant** | AC7's guard is explicitly scoped to writes only; reads are unaffected — this is stated directly in the story text (Notes column), not inferred | Verified — no ambiguity |
| 9 | Concurrent creation of two roles with the same name in the same tenant | DB `UNIQUE (tenant_id, name)` (US-009) resolves this atomically at insert time, same technique as D2's rationale for `user_roles` | Resolvable via precedent — translate constraint violation to `409`, not application-level check-then-insert |
| 10 | Concurrent attach of the same permission to the same role by two requests | Composite PK on `role_permissions` resolves this atomically | Resolvable via precedent, same translation pattern as `DuplicateRoleAssignmentException` |
| 11 | Malformed/missing `name` in `POST /roles` body, or malformed `permissionId` in `POST /roles/{roleId}/permissions` body | Presumably `400` via Bean Validation (`@Valid @RequestBody`), matching `AssignRoleRequest`'s precedent, but exact constraints (`@NotBlank`, max length) are unstated | **Gap — see §8** |
| 12 | Creating a role in a tenant whose name collides (case-insensitively) with that tenant's own seeded `TENANT_ADMIN`/`MEMBER` name | Blocked by the same `UNIQUE (tenant_id, name)` constraint AC9 already covers — no distinct new behavior | Verified, no separate case |
| 13 | Caller creates a custom role, attaches `role:write`/`user:write`/`tenant:write` to it, then (via the already-live US-012 endpoint) assigns that role to another user, who now holds those permissions without ever being named-matched `TENANT_ADMIN` | Not addressed anywhere — this is the scenario `RoleAssignmentService`'s own Javadoc (lines 79–91) forward-tracks as needing closure by "a future custom-roles story" | **Open — Question 1 (Critical), not resolved — see §7/§11 note** |

---

## 5. Assumptions

All flagged `[CONFIRM]` for Gate 1 stakeholder sign-off unless noted as already settled by the task's own framing.

- `[CONFIRM]` US-015.md's resolved 403/404 wording (AC3, AC7, AC8) is authoritative over `EPIC-002.md`'s stale inline copy of the same ACs, which still contains the original ambiguous "403/404" and "editing the role itself" text. See §11.
- `[CONFIRM]` `description` in the `POST /roles` request body is optional, not required — inferred from `Role.description`'s nullable DB column (contrast `Permission.description`, which is `NOT NULL`), not stated explicitly in AC1.
- `[CONFIRM]` Tenant isolation (AC8) applies uniformly to `GET`, `POST`, and `DELETE` on `/roles/{roleId}/permissions`, mirroring US-012's own Gate-1 resolution extending AC4 to all three verbs rather than "before write" only.
- `[CONFIRM]` `GET /roles/{roleId}/permissions` on a role with zero attached permissions returns `200` with an empty array, not `404`.
- `[CONFIRM]` The response envelope for the three new list-returning endpoints (`GET /roles`, `GET /roles/{roleId}/permissions`, `GET /permissions`) follows the existing `{"data": [...]}` convention established for `GET /users/{userId}/roles` (`RoleAssignmentListResponse`, referenced in `UserRoleController`'s own Javadoc as "03-design.md §8.3/D7").
- `[CONFIRM]` New endpoints validate path/body UUID-shaped fields via the same canonical-UUID-string-then-parse pattern as `UserRoleController.parsePathUuid`, yielding `400 FieldValidationException` on malformed values, never a `UUID`-typed `@PathVariable`/body field.
- **Settled, not `[CONFIRM]`** (per the task's own framing): this story's controller(s) ship behind `feature.nexus-us015-rbac-role-management.enabled`, defaulted `false`, independent of the story's "Feature flag required: No" field.
- **Settled, not `[CONFIRM]`** (ADR-0013 D4, explicitly ratified): no bulk cache invalidation is implemented for role-permission edits in this story's initial implementation; the existing 15-min/7-day lag is accepted.

---

## 6. Risks

| # | Risk | Severity | Mitigation |
|---|---|---|---|
| R1 | **Self-escalation via a custom role carrying `role:write`/`user:write`/`tenant:write`.** `RoleAssignmentService`'s own Javadoc (M-3 note, lines 79–91) explicitly forward-tracks this exact gap: AC8's admin-grant guard matches on the role **name** `TENANT_ADMIN`, not on the privileges a role confers. US-015 is the story that first lets a caller create a role and attach *any* permission — including `role:write`, `user:write`, or `tenant:write` — to it. Combined with the already-live US-012 assignment endpoint, a `TENANT_ADMIN` (or, if the gap in R1 is itself exploited once, any holder of `role:write`/`user:write`) can mint a non-`TENANT_ADMIN`-named role with admin-equivalent power and grant it to any user, fully bypassing AC8's protection. No AC, Technical Note, or ADR in either source document addresses this. | **Critical** | Not resolvable via precedent — requires an explicit architecture/policy decision (e.g., gating attachment of "dangerous" permissions on the caller already holding active `TENANT_ADMIN`, or extending AC8-style checks to any role carrying such a permission) before design starts. See Open Question 1 — **unresolved**. |
| R2 | **No audit-event requirement for role creation or role-permission changes.** The epic's own compliance requirement states "Role assignment/revocation events must be immutable and auditable," and `RbacAuditPort`/`SecureEventService` infrastructure already exists in this exact bounded context — yet US-015 defines zero audit obligation for creating a role or attaching/detaching a permission, even though (per R1) these actions can be as security-consequential as a direct role assignment. | **High** | Not resolvable via precedent — `RbacAuditPort`'s three existing methods are scoped specifically to `user_roles` changes; extending it is new design work with no stated mandate. See Open Question 2 — **unresolved**. |
| R3 | **`EPIC-002.md`'s inline copy of US-015's AC3/AC7/AC8 contradicts the (deliberately edited) standalone `US-015.md`** on the 403-vs-404 resolution and the "editing the role itself" scope. An implementer reading the epic file instead of the story file would build the wrong behavior. Additionally, `US-015.md`'s own background section omits the epic's T-E5 forward-tracked threat-model note ("`is_system_role` is inert until this story's AC7 ships") that appears only in `EPIC-002.md`. | **Medium** | Resolved at Gate 1 (§11, OQ3) — `US-015.md` is authoritative; recommend a follow-up edit syncing `EPIC-002.md`'s embedded copy and pulling the T-E5 note into the story text. |
| R4 | **Unbounded per-tenant role growth with no pagination requirement on `GET /api/v1/roles`.** Unlike US-012's identical gap (bounded to ≤2 roles/user pre-US-015), this story is the mechanism that removes the bound. | **Medium** | Flag for `/design`/`/impact-analysis`; not resolved here (design territory). |
| R5 | No defined error contract for: nonexistent `permissionId`, duplicate role-permission attachment, idempotent-vs-404 `DELETE`. Risk of inconsistent, ad hoc behavior invented during implementation. | **Medium** | Resolved at Gate 1 (§11, OQ5). |
| R6 | `RBAC_003` message text and `name`/`description` field-validation rules (max length, allowed characters) are undefined anywhere in the source material. | **Low** | Flag for `/design`; not blocking — implementation-detail, not a business decision. |
| R7 | No port is specified for role/role-permission CRUD persistence. `UserRoleAssignmentPort` is explicitly documented as scoped to `user_roles` write/read operations, not `roles`/`role_permissions` CRUD — reusing it as-is for this story's needs would violate its own stated boundary. | **Low** | Flag for `/impact-analysis`; new port(s) are clearly needed, exact shape is design work. |
| R8 | Cache fan-out staleness on role-permission edits (story's own risk register) | **Low** (downgraded from the story's own "Med/Med") | Already resolved as an accepted trade-off by ADR-0013 D4 — residual risk is only ensuring the lag is documented in the security runbook, not a technical unknown. |
| R9 | System-role immutability check missed on one of the two write endpoints (story's own risk register) | **Low** (per story's own "Low/High" rating; the mitigation already named is a single shared guard, not per-controller) | Single shared guard in `RoleManagementService`, not per-controller, as the story's own Technical Notes already specify; covered by AC7's security test suite. |

---

## 7. Open Questions

1. **Security / Architect (Critical, blocking — not resolved below)** — Does this story reopen the self-escalation gap `RoleAssignmentService`'s own Javadoc forward-tracks (a custom role carrying `role:write`/`user:write`/`tenant:write`, assigned via the already-live US-012 endpoint, bypasses AC8's name-based `TENANT_ADMIN` check entirely)? If so, what control closes it — restricting which permissions a non-`TENANT_ADMIN` caller may attach to a role, extending AC8-style admin-gating to any role carrying a sensitive permission, or something else? See Risk R1.
2. **Security / PM (High, blocking — not resolved below)** — Is any audit-event requirement in scope for role creation and role-permission attach/detach, given the epic's own compliance requirement ("Role assignment/revocation events must be immutable and auditable") and the existing `RbacAuditPort` infrastructure in this same bounded context? See Risk R2.
3. **Architect / PM** — Which document is authoritative where `US-015.md` and `EPIC-002.md`'s inline copy of the same ACs disagree (AC3/AC7/AC8 status-code wording; the T-E5 forward-tracked note present only in the epic)? See Risk R3.
4. **Architect** — When a target role is simultaneously "in another tenant" and "a system role," does the tenant-ownership check (403/404) run before the `is_system_role` check (409), to avoid revealing system-role status of an inaccessible role?
5. **PM / QA** — What HTTP status/error code applies to: (a) a `permissionId` that doesn't exist at all, (b) an attempt to attach a permission already attached to the role, (c) a `DELETE` on a role-permission pairing that was never attached or already removed? None of these are named in any AC.
6. **PM** — Given `Role.description` is DB-nullable but AC1's example body shows both `name` and `description`, is `description` actually optional in the request, or should it be required despite the schema allowing `NULL`?

---

## 8. Gaps

Missing from the source material entirely — not inferable, not addressed by any AC, Technical Note, or ADR:

1. No port is named for role/role-permission CRUD persistence — `UserRoleAssignmentPort` is documented as scoped to `user_roles` only; `JpaRoleRepository`, `JpaRolePermissionRepository`, and `JpaPermissionRepository` are all currently empty marker interfaces with no custom query methods (no "find roles by tenant," no "find role_permissions by role," no name-uniqueness lookup beyond the DB constraint itself).
2. No response DTO shape is specified for any of the six endpoints (which fields per role/permission — `id`, `name`, `description`, `createdAt`, `isSystemRole`?).
3. No pagination requirement for `GET /api/v1/roles` or `GET /api/v1/permissions`.
4. No field-validation rules stated for `name`/`description` in the `POST /roles` body (max length, allowed characters, whether `description` is required).
5. No message text specified for `RBAC_003`, unlike `RBAC_002`/`RBAC_004`, which already carry committed literal text in the codebase.
6. No audit-event requirement stated one way or the other for role creation or role-permission changes (also listed as Risk R2/Open Question 2, since it is significant enough to also be a stakeholder-facing question, not merely an implementation gap).
7. The Dependencies section lists only US-009/US-011 as blockers, omitting US-012 despite the Technical Notes' explicit architectural reliance on `RoleAssignmentService` as a sibling/precedent and on already-live `PermissionCachePort`/audit infrastructure it built. Low-severity — Sprint ordering already sequences US-015 after US-012 in practice.
8. No SLO/error-rate figure specific to this story (only the epic's generic 200 RPS / p95 < 300ms figure, which the story doesn't explicitly claim as its own — same gap noted in US-012's own requirements document).
9. Because per-tenant system-role seeding is currently bootstrap-tenant-only (ADR-0014 D5/ADR-0015 D8 — Epic 3's per-tenant seeding hasn't shipped), real production data today has only one tenant with any roles at all; AC8's cross-tenant test scenarios can only be exercised against synthetic/seeded second-tenant data until Epic 3 ships, not a US-015-specific gap but worth noting for QA planning.

---

## 9. Stakeholder Map

| Stakeholder | Interest |
|---|---|
| Tenant Administrators | Primary API consumer — first capability to build roles beyond the two seeded ones; needs predictable error responses and confidence that system roles can't be broken |
| Business Users (subject of custom roles) | Indirect — see effective permission changes within the documented cache/refresh window; also the population potentially exposed by Risk R1 if it goes unresolved |
| Security & Compliance | High stake — owns Open Questions 1 and 2 (both currently unresolved, both touching the epic's core no-privilege-escalation and full-audit-trail business goals) |
| Architect | Owns Open Questions 1, 3, 4, and the port/design gaps in §8 |
| PM | Owns Open Questions 2, 3, 5, 6 |
| QA | Owns Open Question 3's test-coverage implications and Gap 9's cross-tenant test-data planning |
| Epic 3 (Tenant Management) authors | Downstream consumer — this API is the future Tenant Admin UI's backend; inherits whatever precedent this story sets, including any self-escalation exposure if Open Question 1 ships unresolved |
| US-012 authors' own forward-tracked note | The direct origin of Risk R1 — `RoleAssignmentService`'s own Javadoc names this exact story as the one that must close the gap it flags |

---

## 10. Success Metrics

No story-specific numeric metrics are stated in US-015 itself beyond its ACs' pass/fail contracts. Inherited from EPIC-002's stated success criteria, to the extent they apply:

- Zero privilege-escalation findings involving role/role-permission management in the pre-GA penetration test — now achievable per AC11's admin-gating on dangerous-permission attachment (§11, OQ1).
- 100% of role-related events emitted to the audit stream (epic business goal #3) — now achievable per AC12's audit events (§11, OQ2).
- At least one Epic 3 admin surface built on this API with no contract changes required (epic's stated release-readiness bar, inherited).
- Zero system-role-mutation incidents in production (`TENANT_ADMIN`/`MEMBER` never altered via this API) — tied to AC7.
- Zero cross-tenant role-visibility or role-write incidents — tied to AC8.

---

## 11. Gate 1 Resolutions

Decisions below settle every Open Question from §7 and supersede the corresponding `[CONFIRM]` items in §5.

| OQ | Decision | Rationale (short) |
|----|----------|--------------------|
| 1 (R1, Critical) | **Resolved by explicit stakeholder decision, folded into the story as new AC11.** Attaching `role:write`, `user:write`, or `tenant:write` to any role requires the caller to hold an *active* `TENANT_ADMIN` assignment in their own tenant, checked via a fresh, locking DB read (`UserRoleAssignmentPort#hasActiveAdminAssignment`) — never a JWT-claim check. Generic `role:write` alone is insufficient. | Reuses the exact mechanism `RoleAssignmentService.assign()` already implements for US-012 AC8, per that method's own Javadoc forward-tracking this precise fix ("gating any role carrying such a permission on an active TENANT_ADMIN check... not by extending the name match"). Rejected the blunter alternative (custom roles may never carry these permissions at all) as it defeats the story's purpose — Epic 3's Tenant Admin UI needs the ability to build near-admin custom roles. |
| 2 (R2, High) | **Resolved by explicit stakeholder decision, folded into the story as new AC12.** Role creation, permission grant, and permission revoke each emit an audit event (`ROLE_CREATED`, `ROLE_PERMISSION_GRANTED`, `ROLE_PERMISSION_REVOKED`) via an extended `RbacAuditPort`, following the identical post-commit, best-effort pattern already used for `ROLE_ASSIGNED`/`ROLE_REVOKED`. Denied attempts do not write a success event. | The audit pipeline already exists in this bounded context (US-012/US-014) — low marginal cost. Once OQ1 is understood, a `role_permissions` write is at least as security-consequential as a single user's role assignment (it affects every current/future holder of that role), so the epic's "100% of role events audited" compliance goal should cover it. |
| 3 (R3) | `US-015.md` (the standalone, deliberately-edited story file) is authoritative over `EPIC-002.md`'s inline copy for AC3/AC7/AC8 wording. Recommend a follow-up edit to sync `EPIC-002.md`'s embedded text and pull the T-E5 forward-tracked note into `US-015.md`'s own background section. | The task's own framing confirms `US-015.md` was deliberately edited during pre-analysis to resolve these three ambiguities; the epic's copy is simply stale, not a competing intentional decision. |
| 4 | Tenant-ownership resolution (`404`/`403`) always runs before the `is_system_role` (`409`) check, for any endpoint that could hit both. | Mirrors `RoleAssignmentService.assign()`'s existing ordering exactly: `verifySameTenant`/`resolveRoleInTenant` run first, and AC8's business-rule check (the closest analog to AC7's guard) runs strictly after. Also avoids leaking system-role status of an inaccessible resource through response-code choice. |
| 5 | (a) Nonexistent `permissionId` → `404` via `ResourceNotFoundException` (no cross-tenant dimension applies — permissions are not tenant-scoped). (b) Duplicate role-permission attachment → `409` via a new dedicated exception (next available code, `RBAC_005`, following `DuplicateRoleAssignmentException`'s exact pattern: fixed static message, never echo the DB constraint text). (c) `DELETE` on a never-attached or already-removed pairing → `404`, not an idempotent `204`. | (a)/(b) mirror the `findRole`/`DuplicateRoleAssignmentException` precedent directly. (c) mirrors US-012's own Gate-1 Resolution 6 for the identical "already-revoked" question on `user_roles`, for the identical reason: avoids masking a client double-remove bug behind a silent `204`. |
| 6 | `description` in the `POST /roles` body is optional. | `Role.description`'s DB column is nullable (contrast `Permission.description`, `NOT NULL`); AC1's example body is illustrative, not a required-fields declaration. |

**New error code registered by this story:** `RBAC_003` (system-role-immutable, 409, per the story's own Technical Notes) and `RBAC_005` (duplicate role-permission attachment, 409, resolved above). `RBAC_004` remains US-012's (duplicate active user-role assignment).

**New AC surface registered at Gate 1 (not in the story's original draft):** AC11 (dangerous-permission admin-gating) and AC12 (role/role-permission audit events) — both now in `docs/story/2-rbac/US-015.md`. The story's 9-point estimate is flagged for re-estimation at `/impact-analysis` given this added scope.

**New ports/methods this story will need (confirmed, not yet designed):** an extension to `RbacAuditPort` (or a sibling port) for `recordRoleCreated`/`recordRolePermissionGranted`/`recordRolePermissionRevoked`; reuse (not extension) of `UserRoleAssignmentPort#hasActiveAdminAssignment` for AC11. Exact shape is `/impact-analysis`/`/design` work.

---

### Cross-references
- `docs/story/2-rbac/US-015.md` — source story (authoritative per Gate 1 Resolution OQ3)
- `docs/story/2-rbac/EPIC-002.md` — parent epic (PM/BA/ARC/QA sections, API table, RBAC data model, US-009/US-011/US-012/US-014 inline story text; note its inline US-015 copy is stale — see §11)
- `docs/features/US-012/01-requirements.md` — structural/rigor template followed for this document; also the source of the `403`/`404` `resolveRoleInTenant` precedent and the Gate-1-resolution style for the identical "duplicate/idempotent-delete" question class
- `docs/adr/0013-rbac-data-model-and-enforcement-contract.md` — D4 (cache-fan-out default, ratified, not reopened here), D1-D3 (naming, uniqueness technique, exception-handler pattern reused for `RBAC_003`)
- `nexus-backend/src/main/java/com/example/nexus/rbac/domain/Role.java`, `Permission.java`, `RolePermission.java`, `RolePermissionId.java`, `RbacRoleNames.java` — existing entities this story's service must build on
- `nexus-backend/src/main/java/com/example/nexus/rbac/domain/LastAdminRoleException.java`, `DuplicateRoleAssignmentException.java` — exception pattern `SystemRoleImmutableException`/`RBAC_005`'s exception should follow
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/RoleAssignmentService.java` — source of the Critical Risk R1 finding (Javadoc lines 79–91), the `verifySameTenant`/`resolveRoleInTenant` precedent, and the post-commit side-effect pattern
- `nexus-backend/src/main/java/com/example/nexus/rbac/interfaces/rest/UserRoleController.java` — `@ConditionalOnProperty` gate pattern, `parsePathUuid` pattern, response-envelope precedent
- `nexus-backend/src/main/java/com/example/nexus/rbac/application/port/out/PermissionCachePort.java`, `UserRoleAssignmentPort.java`, `UserDirectoryPort.java`, `RbacAuditPort.java` — existing ports; none currently cover role/role-permission CRUD (Gap 1)
- `nexus-backend/src/main/java/com/example/nexus/rbac/infrastructure/persistence/JpaRoleRepository.java`, `JpaRolePermissionRepository.java`, `JpaPermissionRepository.java` — confirmed empty marker interfaces, no custom query methods exist yet
- `nexus-backend/src/main/java/com/example/nexus/common/web/GlobalExceptionHandler.java` — confirms `RBAC_003` unused/reserved; generic `ConflictException` handler reusable as-is for `RBAC_003`/`RBAC_005`
- `nexus-backend/src/main/resources/application.yml` (line ~205) — confirms the `feature:` kill-switch convention this story must follow
