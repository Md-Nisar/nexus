# EPIC-003: Tenant Management

```
EPIC ID:       EPIC-003
EPIC TITLE:    Tenant Management
STATUS:        APPROVED 2026-10-04 — all epic decisions closed; each story still passes Gate 1
PRIORITY:      P0 (MVP slice) — later phases prioritised per story
STORIES:       15 stories (10 in MVP) between US-021 and US-046 — merged and moved IDs in §5.2
BLOCKED BY:    EPIC-002 entry criteria (Open Decision #4 build checks — owner committed to land
               them before Epic 3 starts; US-016/US-017 merged)
RELATED:       US-019 / US-020 (RBAC UI) — role-assignment screens live there, not here
BLOCKS:        Any customer-facing feature that stores tenant-owned data
```

> **Status of this document.** This is a full rewrite of the earlier draft of this file (see git
> history for the original). The earlier draft's intent — a first enterprise customer onboardable
> within one week of GA, with zero cross-tenant leakage — is kept. Its structure, numbering and
> several technical assumptions were changed because they did not match the codebase; every
> deliberate change is listed in [§0.3](#03-what-changed-from-the-previous-draft-and-why).
> Statements are **verified** against the code on branch state of 2026-09-30 unless marked
> _(inferred)_ or _(unverified)_.
>
> **Approved 2026-10-04.** All epic-level decisions (§8.1 D1–D13) and open questions (§8.2) are
> closed, and ADRs 0019 and 0020 are accepted. Remaining items are tracked, not blocking: the
> §7 entry criteria, a load test of the ADR 0019 limits and legal review of the ADR 0020
> retention periods before GA. Each story still goes through its own Gate 1.
>
> **Restructured 2026-10-04** from 26 to 15 stories with no acceptance criterion dropped: six
> pairs merged, five Later stories moved to the backlog, and oversized scope moved rather than
> split ([§5.2](#52-merged-and-moved-story-ids-2026-10-04)).

---

## Contents

0. [Summary of the previous draft and what changed](#0-summary-of-the-previous-draft-and-what-changed)
1. [Problem, goals, non-goals](#1-problem-goals-non-goals)
2. [Personas](#2-personas)
3. [Current state and recommended architecture](#3-current-state-and-recommended-architecture)
4. [Gap analysis](#4-gap-analysis)
5. [Feature areas and user stories](#5-feature-areas-and-user-stories)
6. [Non-functional requirements](#6-non-functional-requirements)
7. [Phased rollout](#7-phased-rollout)
8. [Decisions needed, open questions and risks](#8-decisions-needed-open-questions-and-risks)
9. [Appendix A — Industry research comparison](#appendix-a--industry-research-comparison)
10. [Appendix B — Sources](#appendix-b--sources)
11. [Appendix C — Verification log](#appendix-c--verification-log)

---

## 0. Summary of the previous draft and what changed

### 0.1 What the previous draft proposed

| Aspect | Previous draft |
|---|---|
| Intent | Two-tier model (Tenant → Organisation); Platform Admin creates tenants and controls lifecycle; Tenant Admin self-service profile and organisation CRUD; suspension filter; Angular `TenantContextService`; audit of tenant events |
| Stories | US-020 … US-025, 29 points, Sprints 5–7 |
| Schema | `V4__tenant_schema.sql` creating `tenants`, `organisations`, `tenant_status_history`; FK from `users.tenant_id`; seed `organisation:read/write` |
| Platform admin | `tenant:write` permission used as the platform-admin gate (OQ-004) |
| Storage | New `FileStorageService` with Local / S3 / SFTP implementations (wired but unused in the epic) |
| Success metrics | Zero cross-tenant findings in pre-GA pen test; tenant creation p95 < 2 s; suspension enforced ≤ 5 min |

### 0.2 Gaps and contradictions found in the previous draft (all verified)

| # | Finding | Evidence |
|---|---|---|
| G1 | **Story IDs collide** with the RBAC plan: US-018 is RBAC hardening; US-019 / US-020 are RBAC UI. | Product direction for this rewrite; `docs/story/2-rbac/` ends at US-017 |
| G2 | **Migration version collides**: `V4__` is already `V4__auth_events_add_user_agent.sql`; latest is `V5__rbac_schema.sql`. | `nexus-backend/src/main/resources/db/migration/` |
| G3 | **Privilege-escalation hole**: gating platform-admin actions on `tenant:write` would let *every* tenant admin create/suspend *any* tenant, because `V5` grants `TENANT_ADMIN` every permission including `tenant:write`. | `V5__rbac_schema.sql` (seed: "TENANT_ADMIN gets all 7") |
| G4 | **Tenant-creation flow cannot work**: it assigns `TENANT_ADMIN` to an existing `tenantAdminUserId`, but users belong to exactly one tenant (`users.tenant_id NOT NULL`), and `RoleAssignmentService.verifySameTenant` rejects cross-tenant targets. A brand-new tenant has no users and no roles. | `V2__identity_schema.sql`; `rbac/application/RoleAssignmentService.java` |
| G5 | **No way for a second tenant's users to sign in**: login, registration and password reset all use the single `nexus.identity.default-tenant-id`. The draft never addresses tenant resolution. | `identity/interfaces/rest/LoginController.java`, `RegistrationController.java`, `PasswordResetController.java` |
| G6 | **Organisations have no members**: the draft's organisation CRUD has no user↔organisation link and no consuming feature, so it delivers labels with no behaviour. | Draft US-023 |
| G7 | **Non-existent classes and names referenced**: `AuditEventPublisher`, `AuditEventType`, `UuidBinaryConverter`, `UuidUtils`, `jwtHelper.extractTenantId`, package `com.example.nexus.tenant`, `ToastService`, `DialogService`, `TableComponent`, `EmptyStateComponent`, `app-input`, `app-button`. | Real equivalents: `AuthEventType` + `SecureEventService`; `UuidV7Converter`; `AuthenticatedRequestDetails` / `RbacControllerSupport.resolveActor`; `NxToast`, `NxDialog`, `NxTable`, `NxEmptyState`, `nx-input`, `nx-button` |
| G8 | **Speculative infrastructure**: `FileStorageService` (3 implementations, S3/SFTP credentials) is built but never called. | Draft US-020 Task 5 |
| G9 | **Suspension lag**: draft accepts ≤ 5 min; research and our Redis design support near-immediate enforcement. Also, login/refresh are not blocked for suspended tenants in the draft (auth paths excluded from the filter). | Draft US-024 AC-6 / T-7 |
| G10 | **Lifecycle has no grace period / restore** and `DELETED` is terminal immediately; no link to ADR 0020 (data lifecycle). | Draft `TenantStatus` transition map |
| G11 | Draft ignores EPIC-002 Open Decision #4 (ArchUnit `@RequiresPermission`/`@PublicEndpoint` rule), which **blocks the first protected Epic 3 controller from merging**. | `docs/story/2-rbac/EPIC-002.md` → Open Decisions #4 |
| G12 | Draft puts implementation code (Java/TS bodies) in the epic; this repo's operating model produces that in Gate 2/3 artefacts (`docs/features/<ID>/03-design.md`, `04-tasks.md`). | `PROJECT.md` → Operating Model |

### 0.3 What changed from the previous draft and why

| Change | Why |
|---|---|
| Stories renumbered **US-021 … US-044** | G1 |
| Migration referred to as "next free Flyway version" (V6 at time of writing) | G2 — the exact number depends on what US-017/US-018 merge first |
| New **platform-scope permission namespace** and operator role, never attachable to tenant roles | G3 |
| Provisioning creates the tenant **plus its system roles** and **invites** the first admin by email | G4; Auth0 Organizations / Atlassian invitation pattern |
| New **tenant-aware sign-in** story (tenant resolved from a slug) | G5 — without it the epic cannot onboard a second customer |
| **Organisations deferred** to "Later" and redefined with membership | G6; research: keep one tenant level until a customer needs sub-units (§A.3) |
| Implementation code removed; stories carry testable Given/When/Then criteria and dependencies, and MVP stories carry code anchors | G7, G12 |
| `FileStorageService` **cut**; logo is a validated HTTPS URL in MVP, upload later | G8 (CLAUDE.md §2 — nothing speculative) |
| Suspension target tightened to **≤ 60 s**, and login/refresh also blocked | G9 |
| Lifecycle gains **PENDING_DELETION** with a restore window; purge tied to ADR 0020 | G10; Entra 30-day soft delete, Atlassian 14-day, GitHub/AWS 90-day patterns |
| EPIC-002 Open Decision #4 made an explicit **entry criterion** | G11 |
| Added isolation-hardening, invitations, member directory, audit viewer, quotas, export/erasure, SSO/SCIM areas | Phase 3 research — table-stakes coverage (§A.2) |

---

## 1. Problem, goals, non-goals

### 1.1 Problem statement

Nexus is described as multi-tenant — `tenant_id` columns exist on `users`, `roles`, `user_roles`
and `auth_events`, JWTs carry a `tenant_id` claim, and RBAC checks are tenant-aware — but there is
**no tenant as a first-class entity**. There is no `tenants` table, no foreign key behind any
`tenant_id`, no way to create a second tenant, and every unauthenticated flow (register, login,
forgot/reset password, resend verification) is pinned to one configured default tenant.
`docs/ARCHITECTURE.md` states it plainly: "Multi-tenancy | Not implemented".

As a result, Nexus cannot onboard a second B2B customer, cannot suspend a non-paying customer,
cannot let a customer administer its own users, and has isolation guarantees that rest partly on
convention rather than on database or framework enforcement.

### 1.2 Goals

1. **Onboard a new enterprise customer end-to-end without engineering involvement**: an operator
   provisions the tenant, its first admin is invited, and that admin invites their users —
   within one week of GA (kept from previous draft).
2. **Make the tenant boundary enforceable, not conventional**: registered tenants with FKs,
   mandatory tenant claim, automated checks for unscoped queries, cross-tenant tests as CI gates.
3. **Give operators safe lifecycle control**: suspend, reactivate, schedule deletion and restore,
   with every action recorded and effective within 60 s.
4. **Give tenant admins self-service** over their tenant profile and membership.
5. **Lay the groundwork** (without building it yet) for plans/quotas, data export and erasure,
   and enterprise SSO/SCIM.

### 1.3 Success metrics

| Metric | Target | Source |
|---|---|---|
| Cross-tenant data-access findings in pre-GA pen test | 0 (Critical/High) | Previous draft |
| Time from "contract signed" to first tenant user signed in | ≤ 1 business day of operator effort | Previous draft goal, made measurable |
| Tenant provisioning API p95 | < 2 s (excluding email delivery) | Previous draft |
| Suspension effective on all API calls | ≤ 60 s worst case after the operator action | Tightened from 5 min (G9) |
| Added p95 latency from tenant-status check | < 5 ms on cache hit | _(inferred target; validate with nexus-test k6 suite)_ |

### 1.4 Non-goals (this epic)

- **Silo or bridge isolation** (schema-per-tenant, DB-per-tenant, dedicated deployments). Nexus
  stays on the pool model (§3.2).
- **Multi-tenant user accounts** (one login that belongs to several tenants, tenant switcher).
  Users remain per-tenant (§3.2 C, decision D2).
- **Operator impersonation** of tenant users — conflicts with ADR 0013 D6's tenant-provenance
  invariant; would need its own ADR and threat model.
- **Billing / payments / invoicing.** Plan tier is a label that drives limits; no payment
  integration.
- **Role and permission management UI** — delivered by US-019 / US-020 (RBAC UI).
- **Custom domains per tenant, per-tenant sandboxes, BYOK / EKM, data residency.**
- **SCIM server, SSO, domain verification, organisations and branding** — moved to the backlog
  (§5.2); not committed in this epic.

---

## 2. Personas

| Persona | Who | Scope | Maps to (proposed) |
|---|---|---|---|
| **Platform Operator** | Nexus staff who onboard and manage customers | All tenants (cross-tenant) | `PLATFORM_OPERATOR` role in the operator tenant with `platform_tenant:read`, `platform_tenant:write` (US-023) |
| **Support Agent** | Nexus support staff | All tenants, read-only | `PLATFORM_SUPPORT` role with `platform_tenant:read` only (US-023) |
| **Tenant Admin** | Customer's administrator (the first one is the "owner" contact) | Own tenant only | Existing `TENANT_ADMIN` system role (V5 seed, re-seeded per tenant by US-024) |
| **End User** | Customer's employee | Own tenant only | Existing `MEMBER` system role |
| **Invitee** | Person who received an invitation but has no account yet | None until acceptance | No account; holds a single-use invitation token |
| **Compliance Officer** | Customer's security/privacy contact (often the Tenant Admin) | Own tenant's audit trail and data requests | `audit:read` (existing, currently unused by any endpoint) |

"Tenant Owner" as a distinct role (Slack Primary Owner / Atlassian org admin pattern) is **not**
introduced in MVP: the last-admin lockout protection from US-016 (shipped) and US-017 (in progress)
already prevents a tenant from losing its last admin. Revisit if a customer needs an undeletable owner (decision D7).

---

## 3. Current state and recommended architecture

### 3.1 How tenancy works today (verified)

All backend paths are relative to `nexus-backend/src/main/java/com/example/nexus/` unless they
start with `nexus-`, `docs/` or `src/`; bare `V*__*.sql` names are under
`nexus-backend/src/main/resources/db/migration/`.

| Concern | Current state | Code anchors |
|---|---|---|
| Bounded contexts | `identity`, `rbac`, `common`, `config`. **No tenant context.** | package tree |
| Tenant entity | **None.** No `tenants` table. The bootstrap tenant `00000000-0000-7000-8000-000000000001` exists only as a literal: on the seeded `roles` rows, in `application-dev.yml` / `application-test.yml`, and used by the dev-only `identity/infrastructure/seed/DevDataInitializer.java`. | `nexus-backend/src/main/resources/db/migration/V5__rbac_schema.sql` (seed section); ADR 0014 D5 |
| Isolation model | **Pool** — shared schema, `tenant_id BINARY(16)` column, no FK. On `users` (NOT NULL, `UNIQUE (tenant_id, email_hmac)`), `roles` (NOT NULL, `UNIQUE (tenant_id, name)`), `user_roles` (NOT NULL), `auth_events` (NULL). `user_roles.tenant_id` is not constrained to match the user's or role's tenant. | `V2__identity_schema.sql`, `V5__rbac_schema.sql` |
| Query scoping | Manual: tenant-scoped derived/JPQL queries plus service-level checks (`verifySameTenant`, `resolveRoleInTenant`). An ArchUnit rule requires tenant scoping on *declared* repository methods, with a 6-entry allowlist; **inherited `findById`/`findAll` and JPQL bodies are not checked** (stated in the test's own Javadoc). | `rbac/application/RoleAssignmentService.java`, `rbac/application/RoleManagementService.java`, `nexus-backend/src/test/java/com/example/nexus/architecture/TenantIsolationArchitectureTest.java` |
| Tenant resolution (unauthenticated) | Controllers inject `@Value("${nexus.identity.default-tenant-id}")` and pass it to use cases. **Every self-registered user lands in the default tenant**, with **no role**. | `identity/interfaces/rest/RegistrationController.java`, `LoginController.java`, `PasswordResetController.java`; `identity/application/RegisterUserUseCase.java` |
| Tenant resolution (authenticated) | JWT `tenant_id` claim → `Authentication` details (only `JwtAuthenticationFilter` may set them — ArchUnit) → `AuthenticatedRequestDetails` → `RbacControllerSupport.resolveActor`. | `identity/infrastructure/web/JwtAuthenticationFilter.java`, `common/security/AuthenticatedRequestDetails.java`, `rbac/interfaces/rest/RbacControllerSupport.java`, `nexus-backend/src/test/java/com/example/nexus/architecture/HexagonalArchitectureTest.java` |
| JWT | RS256; claims `sub`, `tenant_id`, `email_verified`, `roles`, `permissions`, `token_version`, `schema_version`, `jti`, `iat`, `exp`. **`verify()` does not require `tenant_id`** (null passes). Access-token TTL 900 s; no per-request user/tenant status check. | `identity/infrastructure/security/JwtRs256Service.java`; `nexus-backend/src/main/resources/application.yml` (`access-token-ttl-seconds: 900`) |
| Authorisation | `@RequiresPermission` → `TenantAwarePermissionEvaluator` checks the permission is in the JWT `permissions` claim; no DB lookup per request. Seeded permissions: `tenant:read`, `tenant:write`, `user:read`, `user:write`, `role:read`, `role:write`, `audit:read`. `TENANT_ADMIN` holds all seven; `MEMBER` holds `user:read`. **No platform/super-admin concept.** | `common/security/RequiresPermission.java`, `common/security/TenantAwarePermissionEvaluator.java`, `V5__rbac_schema.sql`, `rbac/domain/RbacDangerousPermissions.java` |
| Unused permissions | `tenant:read`, `tenant:write`, `audit:read` are seeded but no endpoint uses them. | every `@RequiresPermission` call site uses only `ROLE_READ`, `ROLE_WRITE`, `USER_READ` or `USER_WRITE` |
| Redis keys | Permission cache is tenant-scoped (`…:rbac:permset:{tenantId}:{userId}`). Login/forgot/reset rate-limit keys are **not** tenant-scoped (`USER:{emailHmac}`, `IP:…`), so the same email in two tenants shares one bucket. The rate-limit store defaults to in-memory per instance (`nexus.security.rate-limit.store-type: memory`); Redis is optional. | `rbac/infrastructure/cache/RedisPermissionCacheAdapter.java`, `identity/infrastructure/web/LoginRateLimitFilter.java`, `identity/infrastructure/security/RedisRateLimitStore.java`; ADR 0016 D3 |
| Quotas | Only `nexus.rbac.max-roles-per-tenant` (default 500). ADR 0019 (per-tenant fairness) was **Proposed** with all questions open; accepted 2026-10-02 (§8.1 D12). | `rbac/application/RoleManagementService.java`; `docs/adr/0019-tenant-fairness-and-quotas.md` |
| Audit | One append-only table `auth_events` (nullable `tenant_id`, triggers block UPDATE/DELETE), written via `SecureEventService` (REQUIRES_NEW, ADR 0009) with a retry buffer (ADR 0011). Event types in `AuthEventType` — **no TENANT_\* events; no read API**. | `identity/application/service/SecureEventService.java`, `identity/domain/AuthEventType.java`, `identity/infrastructure/audit/AuthEventRetryBuffer.java` |
| Users & invitations | Only `GET /api/v1/users/me` and `/api/v1/users/{userId}/roles`. No user list, no invitations, no SSO/SCIM. `UserStatus` = `PENDING, ACTIVE, LOCKED, DISABLED`; `DISABLED` is treated as terminal by self-service reset. | `identity/interfaces/rest/UserProfileController.java`, `rbac/interfaces/rest/UserRoleController.java`, `identity/domain/UserStatus.java`, `identity/domain/User.java` |
| Email | Global from-address and frontend base URL; mail events carry no tenant. | `identity/infrastructure/mail/MailEventListener.java`, `identity/infrastructure/mail/SmtpMailSenderAdapter.java` |
| Background jobs | Only the audit retry-buffer drain (`@Scheduled`) and async mail listeners; MDC (incl. `tenantId`) is propagated to async threads. No outbox, no tenant-aware jobs. | `identity/infrastructure/audit/AuthEventRetryBuffer.java`, `config/AsyncConfig.java`, `common/web/MdcTaskDecorator.java` |
| File storage | **None.** | — |
| Feature flags | Static properties + `@ConditionalOnProperty` per story (`feature.nexus-us0xx-…`); no per-tenant flags. | `nexus-backend/src/main/resources/application.yml` (`feature:` block) |
| Data lifecycle | No export, deletion, or retention jobs. ADR 0020 was **Proposed** with all questions open; accepted 2026-10-02 (§8.1 D13). `auth_events` is append-only (UPDATE and DELETE blocked by triggers); `user_roles` blocks DELETE only (revocation is an UPDATE of `revoked_at`). Both will block naïve hard deletes. | `docs/adr/0020-tenant-data-lifecycle.md`, `V2__identity_schema.sql`, `V5__rbac_schema.sql` |
| DB grants | Least-privilege `nexus_app` user, per-table grants in three places (ADR 0012/0014 follow-on rule: every new table adds its grants in the same story). | `nexus-database/mysql/init/02-grants-post-schema.sql`, `nexus-backend/src/test/resources/nexus-app-grants.sql`, prod runbook |
| Frontend | Token in memory (`AuthStore` signal); `tenantId` available only via `currentUser()?.tenantId` from `/users/me`; no tenant context service; header in `app.html` shows only a wordmark and theme toggle; `permissionGuard` exists but no route uses it; no admin UI. | `nexus-frontend/src/app/core/auth/auth.store.ts`, `nexus-frontend/src/app/features/auth/auth.service.ts`, `nexus-frontend/src/app/shared/types/auth.ts`, `nexus-frontend/src/app/app.html`, `nexus-frontend/src/app/core/guards/permission.guard.ts`, `nexus-frontend/src/app/app.routes.ts` |
| Config drift | ADR 0014 D5 specified a fallback for `default-tenant-id`; ADR 0015 D8 deliberately removed it for prod-safety, so `application.yml` has none and dev/test set it explicitly. Consistent with ADR 0015, not a bug. | `application.yml` (`default-tenant-id: ${NEXUS_IDENTITY_DEFAULT_TENANT_ID}`), `docs/adr/0015-us-009-threat-model-hardening.md` D8 |

### 3.2 Recommended architecture

**A. Isolation model — stay on _pool_ (shared schema + `tenant_id`), harden it.**
AWS SaaS Lens defines pool as tenants sharing resources and silo as dedicated resources per tenant,
with bridge as a mix. Pool matches our single-MySQL modular monolith and pre-enterprise stage;
silo adds per-tenant migration and operations cost we cannot justify yet. The pool model's known
weakness is that one missed `WHERE tenant_id` leaks data, so the epic invests in *automated*
enforcement:

1. A `tenants` table and FKs from every `tenant_id` column that has a NOT NULL tenant
   (`users`, `roles`, `user_roles`), plus a composite constraint so `user_roles` rows cannot
   mix tenants (US-021). `auth_events` keeps no FK (append-only, pre-auth events have no tenant).
2. `tenant_id` becomes a **required** JWT claim (US-021).
3. The ArchUnit rule is extended to cover inherited `findById`/`findAll` on tenant-owned
   entities (US-021). _Hibernate `@TenantId` / `@Filter` was considered and **not** recommended
   now_: it would change query semantics under the existing RBAC lock queries and cross-tenant
   health readers (`rbac/infrastructure/persistence/ZeroAdminTenantReader.java`) and needs its own
   spike. Listed as risk R6.
4. Tenant-scoped rate-limit keys (US-021), following ADR 0016 D3's keyspace convention.
5. `CrossTenantPermissionIT`-style merge-blocking tests for every new endpoint (NFR-ISO-3).

Silo is left open as a future **bridge** option for a premium tier (e.g. a dedicated database for
one customer) — no design work in this epic.

**B. Tenant hierarchy — single level now (Tenant), sub-units later.**
Every researched product has one top-level customer boundary (Salesforce org, Atlassian org,
Auth0/WorkOS organization, Entra tenant). Multi-level hierarchies (Slack Grid, GitHub Enterprise,
Shopify Plus, Entra administrative units) are enterprise-tier features. The previous draft's
Organisation level is deferred to US-044 (backlog) and redefined with membership (decision D4).

**C. Identity model — users stay per-tenant; tenant resolved by slug.**
Today a user row belongs to exactly one tenant and email is unique *per tenant*. We keep that
(Okta's "separate orgs" option in its multi-tenancy guidance) rather than introduce a global identity
with many memberships (Auth0 / WorkOS pattern), because: the schema, blind index and lockout code
already assume it; and no customer has asked for cross-tenant accounts. Unauthenticated flows need
to know the tenant, so each tenant gets an immutable, URL-safe **slug** used in the sign-in URL
(US-027). Decisions D1 (subdomain vs path) and D2 (per-tenant vs global identity) are flagged.

**D. Platform scope — a separate permission namespace and an operator tenant.**
Operator capabilities must never be reachable by a tenant admin (G3). Recommendation (US-023):

- New permissions `platform_tenant:read` and `platform_tenant:write`, following ADR 0013 D1's
  flat `resource:action` format. They are flagged as platform-scope in the `permissions` catalogue
  and **rejected** by `RoleManagementService` when a tenant tries to attach them to a role, and
  never granted to `TENANT_ADMIN`.
- A dedicated **operator tenant** (seeded, not the bootstrap tenant that self-registration uses)
  holds `PLATFORM_OPERATOR` and `PLATFORM_SUPPORT` roles.
- Operator endpoints live under `/api/v1/platform/**`. They take the *target* tenant id from the
  path; the *caller's* tenant still comes from the token. This is an explicit, documented exception
  to the `docs/ARCHITECTURE.md` rule "tenant id comes from the auth token, never from request
  body/path" and needs an ADR recording that exception plus a threat model. ADR 0013 D6's
  tenant-provenance invariant must additionally be re-reviewed **if** the design introduces any new
  producer of `Authentication` details (e.g. a "target tenant" context); the recommended design does
  not, keeping the target tenant as an ordinary path parameter.

This mirrors GitHub Enterprise (enterprise owners are separate from org owners and get no org
content by default) and AWS Organizations (management account separate from member accounts).

**E. RBAC model — keep EPIC-002's roles-of-permissions; add platform roles; no custom-role UI here.**
Per-tenant system roles (`TENANT_ADMIN`, `MEMBER`) are seeded at provisioning time (ADR 0014 D5
already anticipates this). Custom roles already exist via US-015; their UI is US-019/US-020. This matches the direction
Salesforce still recommends (a permission-set-led model, even after cancelling the planned
retirement of permissions on profiles) and WorkOS/Auth0's roles-per-membership model.

**F. Tenant status enforcement — request filter backed by a Redis status cache.**
A filter after `JwtAuthenticationFilter` resolves the caller's tenant status from
`nexus:tenant:status:{tenant_id}` (ADR 0016 keyspace), falling back to the DB, and rejects
non-active tenants. Login and refresh also check tenant status, because suspending must stop new
sessions too (G9). Cache entries are deleted on every status change and have a short TTL.

**G. Lifecycle — PENDING → ACTIVE (on first admin acceptance) ⇄ SUSPENDED; PENDING / ACTIVE /
SUSPENDED → PENDING_DELETION → (restore | DELETED).**
`PENDING_DELETION` blocks access like `SUSPENDED` but is restorable for a grace period
(30 days proposed — Entra's 30-day user restore; Atlassian uses 14 days for managed accounts,
GitHub 90 for repos/members, AWS 90 for closed accounts). Restore returns the tenant to `SUSPENDED`
(or `PENDING` if it was never activated) so an operator re-activates it deliberately. The purge
into `DELETED` is gated on ADR 0020 decisions (US-039).

**H. Audit — reuse `auth_events` via `SecureEventService`, add TENANT\_\* / MEMBER\_\* / INVITATION\_\* event types.**
One audit stream keeps ADR 0009/0011 guarantees (survives rollback, bounded retry). Operator
actions carry an `actor_scope=PLATFORM` marker in `metadata` so tenant-facing views can show them.
_Renaming `auth_events` to a general audit table is out of scope (risk R7)._

---

## 4. Gap analysis

Legend: **Exists** — implemented and fit for purpose · **Partial** — some pieces exist ·
**Missing** — nothing exists · **Risky** — exists but creates a security/correctness risk.

| # | Capability | Status | Evidence (§3.1) | Addressed by |
|---|---|---|---|---|
| 1 | Tenant entity / registry | Missing | no `tenants` table | US-021 |
| 2 | DB-level tenant referential integrity | Risky | `tenant_id` without FK; `user_roles` tenant not tied to user/role tenant | US-021 |
| 3 | Row scoping in repositories | Partial | declared methods checked by ArchUnit; inherited `findById`/`findAll` unchecked | US-021 |
| 4 | Tenant claim integrity in JWT | Risky | `verify()` accepts a token without `tenant_id` | US-021 |
| 5 | Tenant-scoped rate limiting / lockout | Risky | `USER:{emailHmac}` shared across tenants | US-021 |
| 6 | Tenant-scoped caches | Exists | permission cache keyed by tenant+user | — (NFR-ISO-4 keeps it so) |
| 7 | Permission enforcement (tenant) | Exists | `@RequiresPermission`, `CrossTenantPermissionIT` | — |
| 8 | Controller annotation coverage gate | Missing | EPIC-002 Open Decision #4 open | Entry criterion (owner committed 2026-10-01) |
| 9 | Platform operator authority | Missing | no platform role/permission | US-023 |
| 10 | Tenant provisioning | Missing | — | US-024 |
| 11 | Per-tenant system-role seeding | Partial | seeded for bootstrap tenant only | US-024 |
| 12 | Lifecycle (suspend / delete / restore) | Missing | — | US-025 |
| 13 | Tenant resolution for sign-in | Risky | single `default-tenant-id` for all unauthenticated flows | US-027 |
| 14 | Self-registration into a tenant | Risky | every self-registrant joins the default tenant with no role | US-027 (decision D3) |
| 15 | Invitations | Missing | — | US-028 |
| 16 | Tenant member directory / deactivation | Missing | only `/users/me` | US-030 |
| 17 | Role assignment UI | Missing | API exists (US-012/US-015) | US-019 / US-020 (out of this epic) |
| 18 | Tenant profile / settings | Missing | `tenant:read/write` unused | US-031 |
| 19 | Frontend tenant context | Partial | `tenantId` on `AuthUser` only | US-031 |
| 20 | Branding | Missing | ADR 0004 tokens make it feasible | Backlog (US-033) |
| 21 | Plans, seats, quotas | Partial | only max-roles-per-tenant; ADR 0019 accepted 2026-10-02 | US-034 |
| 22 | Audit write path | Exists | `SecureEventService`, append-only `auth_events` | extended in each story |
| 23 | Tenant lifecycle audit events | Missing | no TENANT\_\* types | US-024–US-031 |
| 24 | Audit read / export for tenants | Missing | `audit:read` unused, no query API | US-036 |
| 25 | Operator back-office UI | Missing | — | US-037 |
| 26 | Tenant data export | Missing | ADR 0020 D2 decides the format | US-038 |
| 27 | Tenant purge / retention | Missing | ADR 0020 D1/D2/D5; append-only triggers | US-039, US-046 |
| 28 | Data-subject erasure | Missing | ADR 0020 D3 | US-039 |
| 29 | Tenant-aware email | Risky | global from-address / base URL; links cannot carry tenant | US-027, US-028 |
| 30 | Domain verification | Missing | — | Backlog (US-041) |
| 31 | Enterprise SSO (OIDC/SAML) | Missing | — | Backlog (US-042) |
| 32 | SCIM provisioning | Missing | — | Backlog (US-043) |
| 33 | Sub-tenant hierarchy (organisations) | Missing | — | Backlog (US-044) |
| 34 | Background jobs tenant-aware | Partial | MDC carries `tenantId`; no tenant-iterating jobs yet | NFR-ISO-5 |
| 35 | File storage | Missing | none | Not needed in this epic (G8) |

---

## 5. Feature areas and user stories

**Conventions for every story below**

- Priority is MoSCoW **within this epic**; phase is MVP / Next / Later (§7).
- Size: S ≈ ≤ 3 pts, M ≈ 5 pts, L ≈ 8 pts _(inferred calibration from EPIC-002 point sizes)_.
- Every story that adds an endpoint must: carry `@RequiresPermission` (or `@PublicEndpoint`);
  add a merge-blocking cross-tenant IT; publish its audit events through `SecureEventService`; add
  `nexus_app` grants for any new table in all three grant artefacts (ADR 0014 follow-on rule);
  name its retention class in ADR 0020 D1's table; and name the ADR 0019 D1 limit that bounds any
  new expensive or unbounded per-tenant operation. These are not repeated per story.
- UI stories use the `shared/ui` wrappers (`nx-table`, `nx-dialog-shell`/`NxDialog`, `NxToast`,
  `nx-empty-state`, `nx-input`, `nx-button`) per ADR 0004, compose `permissionGuard` after
  `authGuard`, and meet WCAG 2.1 AA with zero critical Axe findings.
- Error responses use the existing RFC 7807 `ProblemDetail` shape from
  `common/web/GlobalExceptionHandler.java`; new codes use a `TENANT_` prefix (ADR 0019 D4) (exact codes at Gate 2).

### Area A — Isolation foundation & platform authority

#### US-021 — Register tenants and close known isolation gaps before tenant data exists

| Priority | Size | Phase | Pattern |
|---|---|---|---|
| Must | L | MVP | AWS SaaS Lens pool isolation and "SaaS identity" (tenant context in the token, enforced across layers); every researched product has a tenant/org entity |

**As a** Platform Operator, **I want** every tenant to exist as a registered record that all
tenant-owned rows must reference, and every request and query to be bound to one tenant, **so
that** fabricated or orphaned tenant ids are rejected by the database and no customer's data can
leak through a missing filter or a malformed token.

_Merged 2026-10-04: AC1–AC6 were US-021; AC7 was US-046 AC1; AC8–AC12 were US-022 AC1–AC5._

**Acceptance criteria**
1. **Given** the next free Flyway migration has run, **when** the schema is inspected, **then** a
   `tenants` table exists with at least: `id BINARY(16)` (UUIDv7), `slug` (unique, immutable),
   `display_name`, `status`, `plan_tier`, `created_at`, `updated_at`, `version`; and an append-only
   `tenant_status_history` table (UPDATE/DELETE blocked by triggers, as for `auth_events`).
   `plan_tier` is one of `FREE`, `TEAMS`, `ENTERPRISE` (D10); the bootstrap and operator tenant
   rows are seeded as `ENTERPRISE`.
2. **Given** the migration runs on a database that already has rows, **when** it completes,
   **then** the bootstrap tenant `00000000-0000-7000-8000-000000000001` exists as an `ACTIVE` row
   and an operator-tenant row exists (its roles are added by US-023), and the migration fails with a clear error if any
   `users`/`roles`/`user_roles` row references a tenant id that is neither.
3. **Given** the migration has run, **when** a row is inserted into `users`, `roles` or `user_roles`
   with a `tenant_id` not in `tenants`, **then** the insert fails with an FK violation.
4. **Given** a user in tenant A and a role in tenant B, **when** a `user_roles` row linking them is
   inserted directly in SQL, **then** it is rejected by a DB constraint (composite FK or trigger —
   chosen at Gate 2).
5. **Given** the `nexus_app` user, **when** grants are inspected in `02-grants-post-schema.sql`,
   `nexus-app-grants.sql` and the prod runbook, **then** all three list the same grants — proposed
   `SELECT, INSERT, UPDATE` on `tenants` and `SELECT, INSERT` on `tenant_status_history`, with no
   `DELETE` on either (final set confirmed at Gate 2).
6. **Given** Testcontainers ITs, **when** the migration chain V1→latest runs, **then** it is green and
   Hibernate `ddl-auto=validate` passes.
7. **Given** a new migration, **when** it runs, **then** `auth_events` is `RANGE`-partitioned by month
   on `created_at` with primary key `(id, created_at)`, and its `UPDATE`/`DELETE` triggers still
   reject changes (existing append-only tests stay green).
   Moved here from US-046 (2026-10-04) so it lands before production holds any audit data:
   changing this primary key later means rebuilding a large append-only table.
8. **Given** a correctly signed access token without a `tenant_id` claim (or with a malformed one),
   **when** it is presented to any authenticated endpoint including `/api/v1/users/me`, **then** the
   request is rejected with 401 `AUTH_003`.
9. **Given** a repository whose entity has a `tenantId` field, **when** production code calls an
   inherited `findById`, `findAll`, `existsById` or `deleteById` on it outside an allowlisted
   adapter, **then** `TenantIsolationArchitectureTest` fails the build.
10. **Given** the login/forgot/reset rate-limit and lockout key builders, **when** unit-tested, **then**
   every per-user key includes the tenant id (per-IP keys stay global). The end-to-end behaviour —
   the same email in tenants A and B, 5 failed logins against A from one IP and a login to B from
   a second IP, B unaffected — is asserted in US-027, the first story where two tenants can sign in.
11. **Given** the existing 6-entry `UNSCOPED_ALLOWLIST`, **when** this story completes, **then** each
   entry either gains a tenant predicate and is removed, or carries an inline reason comment in the
   test and is listed in the story's `07-security-review.md` as reviewed.
12. **Given** every Redis key written by the application, **when** it holds tenant-owned data,
   **then** it contains the tenant id per ADR 0016 D3 (verified by a test enumerating key builders).

**Dependencies:** the §7 entry criteria (EPIC-002 Open Decision #4, US-016/US-017). **Blocks:** every other story.
**Code anchors:** `V2__identity_schema.sql` (`auth_events` and its triggers), `V5__rbac_schema.sql`,
`nexus-database/mysql/init/02-grants-post-schema.sql`, `identity/infrastructure/security/JwtRs256Service.java`,
`nexus-backend/src/test/java/com/example/nexus/architecture/TenantIsolationArchitectureTest.java`,
`identity/infrastructure/web/LoginRateLimitFilter.java`.

#### US-023 — Establish a platform-operator authority that tenant roles can never hold

| Priority | Size | Phase | Pattern |
|---|---|---|---|
| Must | M | MVP | GitHub Enterprise owners vs org owners; AWS Organizations management account vs member accounts |

**As a** Platform Operator, **I want** a platform-scope role whose permissions cannot be granted
inside a customer tenant, **so that** only Nexus staff can create, suspend or delete tenants and
no tenant admin can escalate into cross-tenant control.

**Acceptance criteria**
1. **Given** the migration, **when** the permission catalogue is read, **then** `platform_tenant:read`
   and `platform_tenant:write` exist, are marked platform-scope, and are **not** held by any
   `TENANT_ADMIN` or `MEMBER` role in any tenant.
2. **Given** a tenant admin with `role:write`, **when** they call
   `POST /api/v1/roles/{roleId}/permissions` with a platform-scope permission, **then** the request
   is rejected with 403 and an audit event is recorded; platform permissions are attached only by
   migration seed, never through the API (`RoleManagementService` attach path rejects them).
3. **Given** the seeded operator tenant, **when** it is inspected, **then** it holds
   `PLATFORM_OPERATOR` (both platform permissions) and `PLATFORM_SUPPORT` (`platform_tenant:read`)
   system roles plus its own `TENANT_ADMIN`, so further operators and support agents are invited and
   deactivated with the ordinary US-028 / US-030 flows inside the operator tenant; self-registration
   can never create users in it. Because `PLATFORM_*` roles carry no permission in
   `RbacDangerousPermissions`, the ADR 0017 assignment gate would not protect them: assigning or
   revoking a `PLATFORM_*` role must additionally require the caller to hold `TENANT_ADMIN` in the
   operator tenant (merge-blocking test: a `user:write`-only operator-tenant user gets 403).
4. **Given** a user holding `TENANT_ADMIN` in any customer tenant, **when** they call any
   `/api/v1/platform/**` endpoint, **then** they receive 403 `RBAC_001` (merge-blocking IT).
5. **Given** the design, **when** Gate 2 completes, **then** an ADR records the `/api/v1/platform/**`
   path-tenant exception to the `docs/ARCHITECTURE.md` rule, and the platform permissions live in
   their own platform-scope set — **not** in `RbacDangerousPermissions.NAMES`, whose "carries all"
   semantics drive the admin-equivalence check (ADR 0018) and the zero-admin health indicator and
   would change for every tenant if extended.

**Dependencies:** US-021. Decision D5 (how the first operator account is bootstrapped).
**Code anchors:** `rbac/domain/RbacDangerousPermissions.java`, `rbac/domain/RbacAdminEquivalence.java`, `rbac/application/RoleManagementService.java`,
`common/security/TenantAwarePermissionEvaluator.java`, `docs/adr/0013-rbac-data-model-and-enforcement-contract.md`.

### Area B — Provisioning & lifecycle

#### US-024 — Provision a new tenant with its system roles and an invited first admin

| Priority | Size | Phase | Pattern |
|---|---|---|---|
| Must | L | MVP | Auth0 Organizations create-org + invite-member-with-role; AWS SaaS Lens orchestrated onboarding |

**As a** Platform Operator, **I want** to create a tenant by entering its name, slug, plan tier
and the first admin's email, **so that** a new customer is ready to use Nexus without any
database work or engineering help.

**Acceptance criteria**
1. **Given** an operator with `platform_tenant:write`, **when** they `POST /api/v1/platform/tenants`
   with a valid display name, slug, plan tier and admin email, **then** within one transaction the
   tenant is created with status `PENDING`, `TENANT_ADMIN` and `MEMBER` system roles are seeded for
   it with the same permission sets as the bootstrap tenant's, a **bootstrap invitation** for the
   admin email with role `TENANT_ADMIN` is created (US-028 storage, but issued by the platform, not
   by an in-tenant admin), and 201 is returned in p95 < 2 s.
2. **Given** a slug that already exists, is reserved (e.g. `www`, `api`, `admin`, `platform`) or
   is not URL-safe lowercase, **when** the operator submits it, **then** 409 (taken or reserved) or
   400 (malformed) is returned and nothing is created.
3. **Given** any step fails (role seeding, invitation creation), **when** the transaction ends,
   **then** no tenant, role or invitation row remains (rollback IT).
4. **Given** the invited admin accepts (US-028), **when** their account is created, **then** the
   tenant transitions `PENDING → ACTIVE` automatically and a `TENANT_ACTIVATED` event is recorded.
   This is the **only** way a tenant becomes `ACTIVE` for the first time, so an `ACTIVE` tenant
   always has at least one admin.
5. **Given** a support agent with only `platform_tenant:read`, **when** they call the create
   endpoint, **then** they receive 403.
6. **Given** a successful creation, **when** the audit trail is read, **then** a `TENANT_CREATED`
   event exists with actor, tenant id, slug and plan tier and **no** admin email in clear text.
7. **Given** a `PENDING` tenant whose bootstrap invitation expired or went to the wrong address,
   **when** an operator re-issues it (optionally to a corrected email), **then** the old invitation is
   revoked, a new one is sent, and `INVITATION_REISSUED` is audited.

**Dependencies:** US-021, US-023, US-028. **Code anchors:** `V5__rbac_schema.sql` (seed pattern),
`rbac/application/RoleAssignmentService.java`, `identity/application/service/SecureEventService.java`.

#### US-025 — Suspend, reactivate, schedule deletion of and restore a tenant, enforced on every request

| Priority | Size | Phase | Pattern |
|---|---|---|---|
| Must | L | MVP | Entra users-restore 30-day soft delete; Atlassian 14-day deactivation before delete; AWS 90-day post-closure; AWS SaaS Lens tenant context resolved per request |

**As a** Platform Operator, **I want** to change a tenant's status with a mandatory reason, see
its status history, and have a suspension take effect for all of the tenant's users within 60
seconds, **so that** I can respond to non-payment, abuse or offboarding with a recoverable,
auditable record that cannot be bypassed with an existing token.

_Merged 2026-10-04: AC1–AC6 were US-025; AC7–AC13 were US-026 AC1–AC7._

**Acceptance criteria**
1. **Given** a tenant, **when** an operator `PATCH`es `/api/v1/platform/tenants/{tenantId}/status`,
   **then** only these transitions succeed: `ACTIVE→SUSPENDED`, `SUSPENDED→ACTIVE`,
   `PENDING|ACTIVE|SUSPENDED→PENDING_DELETION`, and restore `PENDING_DELETION→SUSPENDED` (or
   `→PENDING` if the tenant was never activated); any other returns 409 with the current and
   requested status. `PENDING→ACTIVE` is not an operator action (US-024 AC4).
2. **Given** any accepted transition, **when** it commits, **then** a `tenant_status_history` row
   (previous, new, actor, reason, timestamp) and a `TENANT_STATUS_CHANGED` audit event are written,
   and the tenant's status cache entry is deleted.
3. **Given** a request with no reason or a reason over 512 characters, **when** submitted, **then**
   400 is returned.
4. **Given** a tenant in `PENDING_DELETION`, **when** it is read, **then** the response shows the
   scheduled purge date (transition time + grace period, config default 30 days).
5. **Given** the bootstrap or operator tenant, **when** an operator tries to suspend or delete it,
   **then** 409 is returned and nothing changes.
6. **Given** `GET /api/v1/platform/tenants/{tenantId}/status-history`, **when** called with
   `platform_tenant:read`, **then** the history is returned newest first, paginated.
7. **Given** a user of any tenant whose status is not `ACTIVE` (e.g. `SUSPENDED`,
   `PENDING_DELETION`) with a valid access token, **when** they call any authenticated endpoint, **then** they receive 403 with a tenant-status
   code and no controller runs.
8. **Given** such a user, **when** they call login or refresh, **then** no token is issued and the
   response does not reveal whether the password was correct (anti-enumeration, per the pattern in
   `ForgotPasswordUseCase`).
9. **Given** a user whose tenant is `ACTIVE`, **when** they log in or refresh, **then** the tenant check
   passes with no extra round-trip on a warm cache. (The `PENDING`→first sign-in path is tested in
   US-028 AC13.)
10. **Given** an operator suspends a tenant, **when** 60 s have elapsed, **then** 100 % of that
   tenant's requests on all application instances are rejected — proved by an IT that runs two
   application contexts against one Redis and one MySQL container.
11. **Given** Redis is unavailable, **when** the status is needed, **then** it is read from MySQL
   (fail-safe, not fail-open) and a fallback counter (e.g. `nexus.tenant.status.cache.fallback`)
   is incremented.
12. **Given** an `ACTIVE` tenant and a warm cache, **when** the k6 suite in `nexus-test/` runs,
   **then** the filter adds < 5 ms p95.
13. **Given** a request from a platform-operator user, **when** it targets a suspended tenant via
   `/api/v1/platform/**`, **then** it is **not** blocked (the operator's own tenant is checked, not
   the target's).

**Dependencies:** US-021, US-023. Decision D6 (grace period). **Blocks:** US-027, US-039.
**Code anchors:** new tenant context (per ADR 0002 hexagonal layout); `identity/application/service/SecureEventService.java`;
`rbac/infrastructure/cache/RedisPermissionCacheAdapter.java` (key-builder pattern for the status cache);
`config/SecurityConfig.java`, `identity/infrastructure/web/JwtAuthenticationFilter.java`,
`identity/application/service/LoginUseCase.java`, `identity/application/service/RefreshTokenUseCase.java`.

### Area C — Sign-in, membership & invitations

#### US-027 — Resolve the tenant for sign-in and account recovery from the tenant slug

| Priority | Size | Phase | Pattern |
|---|---|---|---|
| Must | L | MVP | Salesforce My Domain (per-org login URL); Auth0 `organization_name` in the login route |

**As an** End User, **I want** to sign in, reset my password and verify my email at my company's
Nexus address, **so that** I reach my own tenant's account even if the same email is used in
another tenant.

**Acceptance criteria**
1. **Given** a tenant with slug `acme`, **when** a user submits login, forgot-password or
   resend-verification through the tenant-scoped entry point (form chosen by decision D1), **then**
   the backend resolves tenant `acme` and uses it instead of `default-tenant-id`.
2. **Given** an unknown or non-`ACTIVE` slug, **when** any of these flows is called,
   **then** the response is indistinguishable from "wrong credentials / email not found" for that
   flow (no tenant enumeration), with equalised timing per the existing anti-enumeration pattern.
3. **Given** a verification, reset or invitation email, **when** it is sent, **then** its links
   carry the tenant slug and the email shows the tenant display name.
4. **Given** the bootstrap tenant, **when** no slug is supplied, **then** existing behaviour is
   unchanged (backwards compatibility until decision D3 retires it).
5. **Given** public self-registration, **when** decision D3 is implemented, **then** registration
   is either disabled for customer tenants (invite-only) or restricted by tenant setting — never
   possible into the operator tenant.
6. **Given** the Angular app, **when** it loads under a tenant slug, **then** the sign-in pages show
   the tenant display name, fetched from a public, rate-limited endpoint that returns only
   display name and logo URL.
7. **Given** the same email in tenants A and B, **when** 5 failed logins are made against A from one
   IP and a correct login to B from another IP, **then** B's login succeeds (completes US-021 AC10).

**Dependencies:** US-021, US-025. Decisions D1, D3. **Code anchors:**
`identity/interfaces/rest/LoginController.java`, `RegistrationController.java`,
`PasswordResetController.java`, `identity/infrastructure/mail/SmtpMailSenderAdapter.java`,
`nexus-frontend/src/app/features/auth/auth.routes.ts`.

#### US-030 — View and manage the members of my tenant

| Priority | Size | Phase | Pattern |
|---|---|---|---|
| Must | M | MVP | Atlassian/Slack admin user lists with suspend/deactivate; Okta "deprovision, don't delete" |

**As a** Tenant Admin, **I want** to see everyone in my tenant with their status and roles and
deactivate or reactivate a member, **so that** leavers lose access promptly and I can audit who
has access.

**Acceptance criteria**
1. **Given** `user:read`, **when** `GET /api/v1/tenants/me/members?status=&q=&page=` is called,
   **then** only this tenant's users are returned (id, email, status, role names, last sign-in if
   available), paginated (default 20, max 100); email search uses the blind index, not a scan.
2. **Given** `user:write`, **when** the admin deactivates a member, **then** the member's refresh
   tokens are revoked, their `token_version` is bumped, and they cannot sign in or refresh; an
   already-issued access token stays valid until its 900 s TTL expires (the same accepted residual
   documented on `User.java`'s password-reset path, since `token_version` is not checked per
   request) unless Gate 2 adds a per-request user-status check; **when** reactivated, **then** they
   can sign in again. Deactivation sets the existing `DISABLED` status (decided 2026-10-01, open
   question 3): login and refresh already refuse it, and self-service password reset already
   refuses to reactivate it. Reactivation is a new, explicit `User` transition `DISABLED → ACTIVE`
   that only this admin endpoint calls; `applyPasswordReset` keeps refusing `DISABLED`. No new
   status value is added.
3. **Given** the member is the last holder of an admin-equivalent role, **when** deactivation is
   requested, **then** it is refused, reusing the US-016/US-017 last-admin protection.
4. **Given** a member id from another tenant, **when** used, **then** 404 is returned (cross-tenant IT).
5. **Given** the Angular route `/settings/members` guarded by `authGuard` then `permissionGuard`
   (`user:read`), **when** opened, **then** an `nx-table` lists members with an empty state, and
   deactivate/reactivate actions are shown only with `user:write` (`*appHasPermission`).
6. **Given** each deactivate/reactivate, **when** it commits, **then** `MEMBER_DEACTIVATED` /
   `MEMBER_REACTIVATED` audit events are written.

**Dependencies:** US-021. **Code anchors:** `identity/domain/User.java`, `identity/domain/UserStatus.java`,
`identity/application/EmailBlindIndexService.java`, `rbac/domain/RbacAdminEquivalence.java`,
`nexus-frontend/src/app/shared/directives/has-permission.directive.ts`. **Coordination:** US-019/US-020 own role-assignment UI; this page
links to it rather than duplicating it (decision D8, approved 2026-10-01).

#### US-028 — Invite people to my tenant with a pre-assigned role, and let them accept

| Priority | Size | Phase | Pattern |
|---|---|---|---|
| Must | L | MVP | Auth0 Organizations invitations (role pre-assigned, default 7-day TTL) and acceptance; WorkOS/AuthKit invite flow |

**As a** Tenant Admin, **I want** to invite a colleague by email with a chosen role, resend or
revoke pending invitations, and have the invitee join my tenant with that role by setting a
password, **so that** I control who joins my tenant without asking Nexus staff and the invitee can
start working without a separate sign-up or approval step.

_Merged 2026-10-04: AC1–AC7 were US-028; AC8–AC13 were US-029 AC1–AC6; AC14 is new. The largest
story in the epic (estimated 6–8 tasks): if `/breakdown` exceeds 8 tasks, AC4–AC5 (resend, revoke,
list) move to a follow-on story._

**Acceptance criteria**
1. **Given** a tenant admin with `user:write`, **when** they `POST /api/v1/tenants/me/invitations`
   with an email and a role id from their own tenant, **then** a single-use invitation is created
   (token stored only as a hash), valid for 7 days by default, and an email is sent.
   The inviter must pass the same privilege gate as direct role assignment (US-016 / ADR 0017:
   granting `TENANT_ADMIN`, or any role carrying a permission in `RbacDangerousPermissions`, requires
   the caller to hold `TENANT_ADMIN` or a fully admin-equivalent role in the same tenant — ADR 0018),
   checked when the invitation is created, so an invitation cannot escalate privilege.
2. **Given** a role id from another tenant (including an operator-tenant platform role), **when** used
   in an invitation, **then** 404 is returned and nothing is created (cross-tenant IT).
3. **Given** an email that already belongs to an active user in this tenant, or has a pending
   invitation, **when** invited, **then** 409 is returned.
4. **Given** a pending invitation, **when** the admin resends it, **then** the old token is
   invalidated and a new one issued; **when** they revoke it, **then** it can no longer be accepted.
5. **Given** `GET /api/v1/tenants/me/invitations`, **when** called with `user:read`, **then** only this
   tenant's invitations are listed with status (pending / accepted / expired / revoked).
6. **Given** each create/resend/revoke, **when** it commits, **then** an `INVITATION_*` audit event is
   written with the email stored only as HMAC/cipher (ADR 0006), never in clear text.
7. **Given** the Angular members page (US-030), **when** a tenant admin uses "Invite member",
   **then** an `NxDialog` collects email and role and shows 409 inline.
8. **Given** a valid, unexpired invitation, **when** the invitee submits a password meeting the
   existing policy, **then** an `ACTIVE`, email-verified user is created in the invitation's tenant,
   the pre-assigned role is granted, and the invitation is consumed — all in one transaction.
   The grant **cannot** go through `RoleAssignmentService.assign(actor, …)` unchanged: the invitee
   holds no role yet and a platform operator fails its same-tenant check (the same trap as G4).
   Gate 2 must define a dedicated invitation-grant path that relies on the privilege check already
   made when the invitation was issued (US-028 AC1 / US-024), and must decide what is recorded in
   `user_roles.assigned_by` (NOT NULL, FK to `users`) — e.g. the inviter for in-tenant invitations
   and the new user themself for a platform bootstrap invitation — with the issuer kept in the audit
   event.
9. **Given** an expired, revoked, already-used or unknown token, **when** it is used, **then** the
   same generic 410 response is returned for all four cases.
10. **Given** the invitation is for tenant A, **when** accepted, **then** the created user's
   `tenant_id` is A regardless of any tenant hint in the request.
11. **Given** the tenant is `SUSPENDED` or `PENDING_DELETION`, **when** the invitee accepts, **then**
   acceptance is refused with the same generic response.
12. **Given** acceptance succeeds, **when** the audit trail is read, **then** `INVITATION_ACCEPTED` and
   `ROLE_ASSIGNED` events exist for the new user.
13. **Given** a bootstrap invitation for a `PENDING` tenant (US-024), **when** it is accepted, **then** the
   tenant becomes `ACTIVE` in the same transaction and the new admin can sign in immediately.
14. **Given** an invitation link, **when** the invitee opens it in the Angular app, **then** a public
   accept page shows the tenant display name and a password form with the existing password-policy
   feedback, submits to the AC8 acceptance endpoint, and shows the same generic message for every
   AC9 failure case (added 2026-10-04: the invitee had no screen to accept on).

**Dependencies:** US-021, US-027 (tenant-aware email links), US-030 (members page for AC7).
Mandatory security review (R12: the invitation-grant path).
**Code anchors:** `rbac/application/RoleAssignmentService.java` (privilege gate), `identity/application/EmailBlindIndexService.java`,
`identity/infrastructure/mail/MailEventListener.java`. Invitation state may extend
`auth_tokens` (new type) or be a new table — Gate 2 decides; note `auth_tokens.user_id` is
`NOT NULL`, so a pre-account invitation needs either a `PENDING` user row or a separate table. Also `identity/application/RegisterUserUseCase.java`, password policy from EPIC-001 US-006.

### Area D — Tenant profile

#### US-031 — View and update my tenant's profile, and show the tenant in the app header

| Priority | Size | Phase | Pattern |
|---|---|---|---|
| Must | L | MVP | Table stakes (§A.2): tenant-admin self-service settings; Auth0 Organizations per-org branding _(vendor screens not researched)_ |

**As a** Tenant Admin, **I want** to view and edit my tenant's display name, logo URL and
billing/technical contacts, **and as an** End User, **I want** to see my company's name and logo
in the Nexus header, **so that** our details are accurate without contacting Nexus staff and
everyone knows which tenant they are working in.

_Merged 2026-10-04: AC1–AC7 were US-031; AC8–AC11 were US-032 AC1–AC4._

**Acceptance criteria**
1. **Given** `tenant:read`, **when** `GET /api/v1/tenants/me` is called, **then** the caller's tenant
   (from the token only — no id in path or body) is returned, including slug, status and plan tier
   as read-only fields.
2. **Given** `tenant:write`, **when** `PATCH /api/v1/tenants/me` changes display name, logo URL or
   contacts, **then** they are saved; slug, status and plan tier in the body are rejected with 400
   (not silently ignored — the previous draft's AC-4 behaviour is reversed so clients learn early).
3. **Given** a logo URL that is not `https://` or exceeds 512 characters, **when** submitted, **then**
   400 is returned.
4. **Given** contact name/email/phone, **when** stored, **then** they are encrypted at rest with the
   same AES-256-GCM `TextEncryptor` used by ADR 0006. Note: the existing `AttributeEncryptor` is
   typed to `EmailCipher` only, so a converter for general PII strings is needed (the previous
   draft assumed it could be reused as-is).
5. **Given** a profile update, **when** audited, **then** `TENANT_PROFILE_UPDATED` lists changed field
   names only — no values.
6. **Given** the Angular route `/settings/tenant`, **when** a user with `tenant:read` opens it, **then**
   the form is pre-filled and editable only with `tenant:write`; save shows an `NxToast`.
7. **Given** a request for another tenant's profile by any means, **when** made, **then** it is
   impossible by construction (no id parameter) and the cross-tenant IT proves `GET /me` returns only
   the caller's tenant.
8. **Given** a signed-in user, **when** the session is established, **then** a signal-based tenant
   context in `core/` holds the tenant's display name, slug and logo URL from a `tenant` summary
   object added to `GET /api/v1/users/me` (`MeResponse`), which every signed-in user can already
   call (decided 2026-10-01, open question 2). `MEMBER` does **not** get `tenant:read`; the full
   profile at `GET /api/v1/tenants/me` (US-031), including contacts, stays admin-only.
9. **Given** the header in `app.html`, **when** a user is signed in, **then** it shows the tenant display
   name and logo (with non-empty `alt`), and nothing tenant-specific when signed out.
10. **Given** logout, **when** it completes, **then** the tenant context is cleared.
11. **Given** the logo fails to load, **when** rendered, **then** the display name is shown alone.

**Dependencies:** US-021. **Code anchors:** `identity/infrastructure/persistence/AttributeEncryptor.java`,
`common/web/GlobalExceptionHandler.java`, `identity/interfaces/rest/dto/MeResponse.java`,
`identity/interfaces/rest/UserProfileController.java`, `nexus-frontend/src/app/core/auth/auth.store.ts`,
`nexus-frontend/src/app/app.html`.

### Area E — Plans, quotas & limits

#### US-034 — Enforce plan limits: seats and per-tenant request rates

| Priority | Size | Phase | Pattern |
|---|---|---|---|
| Should | L | Next | Auth0 entity limits; Shopify Plus store limit; AWS SaaS Lens tiering and noisy-neighbour guidance |

**As a** Platform Operator, **I want** each plan tier to cap a tenant's active members and API
request rate, with an optional per-tenant override, **so that** tenants stay within what they have
bought and one tenant's heavy usage cannot slow down other customers.

_Merged 2026-10-04: AC1–AC6 were US-034; AC7–AC10 were US-035 AC1–AC4._

**Acceptance criteria**
1. **Given** plan-tier limits in configuration (defaults per D10: Free 5, Teams 50, Enterprise 500
   active members) and an optional override on the tenant, **when** a tenant is at its limit, **then** creating an invitation or reactivating a member returns 409 with
   a limit code, and pending invitations count toward the limit.
2. **Given** an operator with `platform_tenant:write`, **when** they change a tenant's plan tier or
   override, **then** it takes effect on the next check and a `TENANT_PLAN_CHANGED` event is written.
3. **Given** a tenant admin, **when** they view the members page, **then** used / allowed seats are
   shown.
4. **Given** the existing `nexus.rbac.max-roles-per-tenant`, **when** this story completes, **then** it
   remains a global safety cap (not a plan limit) and is documented as such.
5. **Given** a tenant moved to a tier whose limit is below its current member count, **when** the
   change is saved, **then** no existing member loses access; only new invitations and
   reactivations are refused until the count is under the limit, and the operator is warned
   before confirming.
6. **Given** the operator tenant, **when** seats are checked, **then** it has no seat limit.
7. **Given** a per-tier request budget (ADR 0019 D2: Free 300, Teams 1,200, Enterprise 6,000
   requests per minute), **when** a tenant exceeds it, **then** further requests get
   429 with `Retry-After` and an RFC 7807 body; other tenants are unaffected (load test).
8. **Given** Redis is unavailable, **when** the limiter runs, **then** it fails open (ADR 0019 D4,
   matching ADR 0016 D4), emits a metric and raises an alert; per-user and per-IP limits keep
   working.
9. **Given** metrics, **when** exported, **then** tenant id is not a raw label (bounded cardinality per
   `docs/observability-standards.md`).
10. **Given** the production profile, **when** the application starts, **then** the rate-limit store
   is Redis (`nexus.security.rate-limit.store-type: redis`); the in-memory store is refused outside
   dev/test, since it would multiply each tenant's limit by the number of instances.

**Dependencies:** US-024, US-028, US-030; decision D10; ADR 0019 (accepted: D2 limits, D3 seat check in the
use case under a tenant-row lock and the tenant rate-limit filter, D4 `409` / `429`).
**Code anchors:** `rbac/application/RoleManagementService.java` (existing `max-roles-per-tenant` check),
`identity/infrastructure/security/RedisRateLimitStore.java`, `identity/infrastructure/web/LoginRateLimitFilter.java`.

### Area F — Audit logging

Every MVP story writes its own audit events (see story ACs). This area adds the **read** side.

#### US-036 — Review and export my tenant's audit trail

| Priority | Size | Phase | Pattern |
|---|---|---|---|
| Should | M | Next | Atlassian org audit log (180 days, export); GitHub/Salesforce 180-day audit trails; Stripe security history CSV |

**As a** Compliance Officer, **I want** to search and export my tenant's security and
administration events, **so that** I can answer auditors and investigate incidents without asking
Nexus support.

**Acceptance criteria**
1. **Given** `audit:read`, **when** `GET /api/v1/tenants/me/audit-events?type=&from=&to=&page=` is
   called, **then** only events whose `tenant_id` equals the caller's tenant are returned, newest
   first, paginated, within the 13-month retention window (ADR 0020 D1); an erased member is shown
   as "erased user" (ADR 0020 D3).
2. **Given** a date range of up to 90 days, **when** CSV export is requested, **then** a CSV is
   produced with the same filtering; larger ranges are rejected (bounds the cost, per ADR 0019 follow-on rule 1).
3. **Given** events whose metadata contain personal data, **when** returned, **then** only metadata keys
   on an explicit allowlist (defined at Gate 2) are included, and email addresses are never returned.
4. **Given** operator actions on this tenant (US-025), **when** listed, **then** they appear, marked as
   performed by Nexus staff and shown only with a role label (`Nexus operator` / `Nexus support`)
   and the event id (decided 2026-10-01, open question 4). The operator's user id stays in the
   stored event for internal investigation and is never returned by the tenant API.
5. **Given** the Angular route `/settings/audit`, **when** opened with `audit:read`, **then** an
   `nx-table` with filters and an export button is shown.

**Dependencies:** US-021, US-025 (operator events and the `actor_scope` marker, §3.2 H); ADR 0020 D1
(retention: 13 months).
**Code anchors:** `identity/infrastructure/persistence/JpaAuthEventRepository.java` (currently no query methods).

### Area G — Operator back-office

#### US-037 — Manage tenants from an operator console

| Priority | Size | Phase | Pattern |
|---|---|---|---|
| Should | L | MVP | Slack Grid admin dashboard; Atlassian admin; AWS SaaS Lens operational tooling |

**As a** Platform Operator, **I want** a console to find a tenant, see its details and status
history, and perform lifecycle actions, **so that** onboarding and support do not require API
tools.

**Acceptance criteria**
1. **Given** `platform_tenant:read`, **when** `GET /api/v1/platform/tenants?status=&q=&page=` is
   called, **then** tenants are listed (slug, display name, status, plan tier, member count, created
   date), excluding `DELETED` by default.
2. **Given** the Angular route `/platform/tenants`, **when** opened by an operator, **then** the list,
   a detail page with status history, a "Create tenant" dialog (US-024) and status actions (US-025,
   with a reason field and confirmation) and "Re-issue admin invitation" for `PENDING` tenants
   (US-024 AC7) are available; support agents see no action buttons.
3. **Given** a tenant user (any tenant role), **when** they navigate to `/platform/**`, **then**
   `permissionGuard` redirects to `/access-denied` and the API returns 403 (backend is the boundary).
4. **Given** a destructive action (suspend, schedule deletion), **when** confirmed, **then** the
   operator must type the tenant slug.

**Dependencies:** US-023, US-024, US-025. **Code anchors:** `nexus-frontend/src/app/app.routes.ts`,
`nexus-frontend/src/app/core/guards/permission.guard.ts`.

#### US-045 — Require multi-factor sign-in for operator accounts

| Priority | Size | Phase | Pattern |
|---|---|---|---|
| Must | L | MVP | GitHub Enterprise and AWS root/management accounts require MFA for administrators; Okta/Entra admin-role MFA policies _(vendor MFA settings not researched in detail)_ |

**As a** Platform Operator, **I want** my account to require a second factor at sign-in, **so
that** a stolen password alone cannot be used to create, suspend or delete customer tenants.

**Acceptance criteria**
1. **Given** a user in the operator tenant, **when** they sign in for the first time after this
   story ships, **then** they must enrol a TOTP authenticator (RFC 6238) before any token is
   issued; enrolment shows a QR code once and asks for one valid code to confirm it.
2. **Given** an enrolled operator-tenant user, **when** the password step of `LoginUseCase`
   succeeds, **then** no access or refresh token is issued; the response is a short-lived (≤ 5 min),
   single-use MFA challenge, and tokens are issued only after a valid TOTP code is submitted
   against it.
3. **Given** a wrong TOTP code, **when** submitted, **then** the failure counts toward the existing
   account lockout (`SecureEventService`) and the challenge endpoint is rate-limited like login
   (`LoginRateLimitFilter`); a code already used within its time step is rejected (no replay).
4. **Given** enrolment, **when** it completes, **then** 10 single-use recovery codes are shown once
   and stored only as hashes; the TOTP secret is stored encrypted at rest with the AES-256-GCM `TextEncryptor` from ADR 0006
   (through the general-purpose converter US-031 AC4 adds),
   never logged and never returned again.
5. **Given** an access token for an operator-tenant user, **when** it is issued, **then** it records
   that MFA was completed (an `amr`-style claim), and `TenantAwarePermissionEvaluator` refuses
   `platform_tenant:*` permissions on any token without it (403 `RBAC_001`). Adding the claim bumps
   `JwtClaims.CURRENT_VERSION`, per the frozen-contract rule on `JwtClaims.java`.
6. **Given** a lost authenticator, **when** an operator-tenant `TENANT_ADMIN` resets that user's
   MFA, **then** the user must re-enrol at next sign-in, their refresh tokens are revoked, and the
   reset is audited; no user can reset their own MFA, and the last operator admin's reset follows
   the D5 runbook.
7. **Given** each enrolment, successful challenge, failed challenge, recovery-code use and MFA
   reset, **when** it happens, **then** an `auth_events` row is written (`MFA_ENROLLED`,
   `MFA_SUCCESS`, `MFA_FAILURE`, `MFA_RECOVERY_CODE_USED`, `MFA_RESET`) with no secret or code in
   metadata.
8. **Given** a user in a customer tenant, **when** they sign in, **then** the flow is unchanged (MFA
   for customer tenants is out of scope here; it can reuse this mechanism later).
9. **Given** the Angular sign-in flow, **when** an MFA challenge is returned, **then** a code entry
   step is shown with an accessible single input, a "use a recovery code" option and generic
   error text.

**Dependencies:** US-023 (operator tenant and platform permissions), US-027 (tenant-aware sign-in),
US-031 (encryption converter).
Mandatory security review (new authentication factor). Decision D11. **Blocks:** GA (NFR-SEC-4).
**Code anchors:** `identity/application/service/LoginUseCase.java`,
`identity/application/service/RefreshTokenUseCase.java`, `identity/application/service/SecureEventService.java`,
`identity/domain/JwtClaims.java`, `identity/infrastructure/web/LoginRateLimitFilter.java`,
`common/security/TenantAwarePermissionEvaluator.java`.
**Split line (agreed 2026-10-04):** if `/breakdown` produces more than 8 tasks, AC5 (MFA claim and
permission refusal) and AC6 (admin reset) move to a follow-on story; the rest ships as one.

### Area H — Data retention, export & deletion

#### US-046 — Enforce retention periods on tokens and audit events

| Priority | Size | Phase | Pattern |
|---|---|---|---|
| Should | M | Next | ISO 27001 A.8.10 scheduled deletion with verification; PCI DSS 10.5.1 12-month audit retention |

**As a** Compliance Officer, **I want** expired tokens and old audit events to be removed on a
fixed schedule with proof, **so that** we keep data only as long as ADR 0020 says and can show
auditors that deletion happens.

**Acceptance criteria**
1. **Given** the rotation job, **when** it runs, **then** it creates next month's partition ahead of
   time and drops partitions older than 13 months (ADR 0020 D1).
2. **Given** refresh, auth and invitation tokens expired, revoked or used more than 30 days ago,
   **when** the token job runs, **then** they are deleted in batches of at most 1,000 rows.
3. **Given** the `nexus_retention` database account, **when** grants are inspected, **then** it is
   added to all three grant artefacts and the DB-grant health check; `nexus_app` still has no DDL
   and no `DELETE` on protected tables (ADR 0012).
4. **Given** two application instances, **when** a job is due, **then** only one runs it (database
   lease, ADR 0020 D5), and a rerun after interruption is harmless.
   The job runner (schedule, lease, run record, metrics) is a reusable component: US-038's export
   and US-039's purge and erasure run on it rather than building their own.
5. **Given** each job run, **when** it finishes, **then** a `RETENTION_PURGE` audit event and the
   `nexus_retention_*{data_class}` metrics are written, and an alert fires if a job has not
   succeeded for 48 hours.
6. **Given** the `deletion_log` table, **when** it is created, **then** it is append-only and its
   rows expire after the backup window (ADR 0020 D4).

**Dependencies:** US-021 (its AC7 partitions `auth_events`; this story rotates the partitions); ADR 0020 (accepted).
**Code anchors:** `nexus-database/mysql/init/01-grants.sql`, `nexus-backend/src/test/resources/nexus-app-grants.sql`,
`identity/infrastructure/persistence/JpaAuthEventRepository.java`.

#### US-038 — Export all of my tenant's data

| Priority | Size | Phase | Pattern |
|---|---|---|---|
| Should | L | Later | Microsoft 365 / Atlassian export-before-deletion windows (ADR 0020 research) |

**As a** Tenant Admin, **I want** to request a machine-readable export of my tenant's data,
**so that** we can meet our own retention duties and leave Nexus without losing records.

**Acceptance criteria**
1. **Given** `tenant:write`, **when** an export is requested, **then** it runs asynchronously, is
   limited to one concurrent export per tenant, and the requesting admin is emailed when it is ready.
2. **Given** the export, **when** produced, **then** it contains every tenant-owned table's rows for
   that tenant only (proved by a test that seeds two tenants), as a ZIP of JSON Lines files (one per
   entity type) plus `manifest.json` (ADR 0020 D2.1); password hashes, token hashes, MFA secrets and
   blind-index values are never included.
3. **Given** a finished export, **when** downloaded, **then** the link is single-use and expires
   (duration decided at Gate 2).
4. **Given** each request and download, **when** they happen, **then** audit events are recorded.
5. **Given** a tenant in `PENDING_DELETION`, **when** its customer asks for an export, **then** an
   operator with `platform_tenant:write` can produce it (tenant users cannot sign in then).

**Dependencies:** US-046 (job runner); ADR 0020 D2 (format); ADR 0019 D1 (one concurrent export per tenant); storage mechanism decided at Gate 2 (no file storage exists today) (this is where a
`FileStorageService`-style abstraction may first be justified).

#### US-039 — Purge a tenant after its grace period, and erase one member on request

| Priority | Size | Phase | Pattern |
|---|---|---|---|
| Should | L | Later | Entra/Atlassian/AWS grace-then-purge; GDPR Art. 17; ADR 0020 D2–D5 |

**As a** Platform Operator, **I want** tenants in `PENDING_DELETION` to be purged automatically
when their grace period ends, **and as a** Tenant Admin acting on a data-subject request, **I
want** to erase one person's personal data from my tenant, **so that** we honour offboarding
commitments and GDPR erasure deadlines without manual SQL.

_Merged 2026-10-04: AC1–AC5 were US-039; AC6–AC10 were US-040 AC1–AC5. Both share the
`nexus_retention` account, the `deletion_log` and Redis key removal._

**Acceptance criteria**
1. **Given** a tenant whose grace period has ended, **when** the scheduled purge runs, **then** its
   tenant-owned rows are hard-deleted (ADR 0020 D2.3), its Redis keys are removed, and the
   tenant row moves to `DELETED` (kept as a tombstone, contact fields cleared, slug reserved
   permanently). Its `auth_events` stay until their 13-month partition is dropped (D2.4).
2. **Given** `auth_events` (append-only) and `user_roles` (DELETE blocked by trigger), **when** purge
   runs, **then** it runs under the separate `nexus_retention` database account (ADR 0020 D5);
   `nexus_app` gains no `DELETE` on protected tables, and a test proves `nexus_app` is still refused.
3. **Given** the purge job, **when** it runs, **then** it emits metrics and one audit event per tenant,
   and is idempotent if interrupted.
4. **Given** a tenant restored before the deadline (US-025), **when** the job runs, **then** it is
   untouched.
5. **Given** a completed purge, **when** it commits, **then** the tenant id is appended to
   `deletion_log` (ADR 0020 D4) and a `TENANT_PURGED` event records row counts per table.
6. **Given** `user:write` and a deactivated member, **when** erasure is requested, **then** within 7
   days (ADR 0020 D3.1) the `users` row is anonymised, not deleted (`user_roles.assigned_by`
   references it): `email_cipher` and `email_hmac` are overwritten with non-identifying values,
   `consent_accepted_at` is cleared and `erased_at` is set; tokens, pending invitations and Redis
   keys are deleted, and active role assignments are revoked.
7. **Given** audit events referencing the user, **when** erasure completes, **then** they remain
   until their 13-month expiry (ADR 0020 D3.4), shown in the audit view as "erased user".
8. **Given** the request, **when** completed, **then** a `MEMBER_ERASED` event records who requested it
   and when, without the erased data.
9. **Given** an erased user, **when** reactivation is attempted (US-030), **then** it is refused.
10. **Given** a completed erasure, **when** it commits, **then** the user id is appended to
   `deletion_log` (ADR 0020 D4).

**Dependencies:** US-025, US-030, US-046 (retention account and job runner); ADR 0020 D2–D5 (accepted); ADR 0006.
**Code anchors:** `identity/domain/User.java`, `identity/application/EmailBlindIndexService.java`,
`V2__identity_schema.sql` (`auth_events` triggers), `V5__rbac_schema.sql` (`user_roles` trigger).

### 5.1 Story index

| Story | Title | Area | MoSCoW | Size | Phase | Depends on |
|---|---|---|---|---|---|---|
| US-021 | Tenant records, referential integrity and isolation gaps (incl. `auth_events` partitioning) | A | Must | L | MVP | EPIC-002 entry criteria |
| US-023 | Platform-operator authority | A | Must | M | MVP | US-021 |
| US-025 | Tenant lifecycle with per-request enforcement | B | Must | L | MVP | US-021, US-023 |
| US-027 | Tenant-aware sign-in and recovery | C | Must | L | MVP | US-021, US-025 |
| US-030 | Member directory, deactivate/reactivate | C | Must | M | MVP | US-021 |
| US-028 | Invitations: send, manage and accept | C | Must | L | MVP | US-021, US-027, US-030 |
| US-024 | Provision tenant + roles + invited admin | B | Must | L | MVP | US-021, US-023, US-028 |
| US-031 | Tenant profile and tenant in app header | D | Must | L | MVP | US-021 |
| US-037 | Operator console | G | Should | L | MVP | US-023, US-024, US-025 |
| US-045 | Operator MFA | G | Must | L | MVP | US-023, US-027, US-031, D11 |
| US-034 | Plan limits: seats and per-tenant rate limits | E | Should | L | Next | US-024, US-028, US-030, D10, ADR 0019 |
| US-046 | Retention jobs and shared job runner | H | Should | M | Next | US-021, ADR 0020 |
| US-036 | Tenant audit viewer + export | F | Should | M | Next | US-021, US-025, ADR 0020 D1 |
| US-038 | Tenant data export | H | Should | L | Later | US-046, ADR 0020 D2, ADR 0019 D1 |
| US-039 | Tenant purge and member erasure | H | Should | L | Later | US-025, US-030, US-046, ADR 0020 |

### 5.2 Merged and moved story IDs (2026-10-04)

The epic was reduced from 26 to 15 stories without dropping any acceptance criterion. Old IDs
stay resolvable here because ADRs, commits and earlier reviews cite them.

| Old ID | Now |
|---|---|
| US-021 | Merged into **US-021** (AC8–AC12) |
| US-025 | Merged into **US-025** (AC7–AC13) |
| US-028 | Merged into **US-028** (AC8–AC13) |
| US-031 | Merged into **US-031** (AC8–AC11) |
| US-034 | Merged into **US-034** (AC7–AC10) |
| US-039 | Merged into **US-039** (AC6–AC10) |
| US-046 AC1 | Moved to **US-021 AC7** (partitioning must precede production data) |
| US-033, US-041, US-042, US-043, US-044 | Moved unchanged to [`docs/story/backlog/deferred-from-EPIC-003.md`](../backlog/deferred-from-EPIC-003.md); each returns through its own Gate 1 |

---

## 6. Non-functional requirements

### 6.1 Isolation guarantees

| ID | Requirement |
|---|---|
| NFR-ISO-1 | The caller's tenant is taken only from the verified token. Only `/api/v1/platform/**` may name a *target* tenant in the path, and only for callers holding a platform-scope permission. |
| NFR-ISO-2 | Every tenant-owned table has a NOT NULL `tenant_id` with an FK to `tenants` (except `auth_events`, documented). |
| NFR-ISO-3 | Every new endpoint has a merge-blocking IT proving another tenant's resources return 403/404, in the style of `nexus-backend/src/test/java/com/example/nexus/rbac/security/CrossTenantPermissionIT.java`. |
| NFR-ISO-4 | Every Redis key holding tenant data includes the tenant id (ADR 0016 D3). |
| NFR-ISO-5 | Background jobs that iterate tenants set the tenant explicitly per unit of work and never reuse a previous tenant's context. |
| NFR-ISO-6 | Platform-scope permissions can never be attached to a tenant role (US-023 AC2 is a regression test). |

### 6.2 Performance

| ID | Requirement |
|---|---|
| NFR-PERF-1 | Tenant-status check adds < 5 ms p95 on cache hit (US-025). |
| NFR-PERF-2 | Tenant provisioning p95 < 2 s excluding email delivery. |
| NFR-PERF-3 | Paginated list endpoints (members, tenants, audit) p95 < 500 ms at 10 k rows per tenant _(inferred target; add a k6 scenario in `nexus-test/`)_. |

### 6.3 Security

| ID | Requirement |
|---|---|
| NFR-SEC-1 | Each MVP story completes Gate 2 threat modelling (`03b-threat-model.md`); US-021, US-023, US-025, US-027, US-028 and US-045 are mandatory security-reviewer stories. |
| NFR-SEC-2 | Invitation and export tokens are random, single-use, stored hashed, and expire. |
| NFR-SEC-3 | Unauthenticated tenant-resolution endpoints are rate-limited and never reveal whether a tenant or email exists. |
| NFR-SEC-4 | Operator accounts must use MFA before GA (approved, D11; delivered by US-045) _(no MFA exists in the codebase today — flagged as risk R3)_. |
| NFR-SEC-5 | No PII (emails, names, contacts) in logs or audit metadata values, per existing no-PII rule. |

### 6.4 Compliance (GDPR)

| ID | Requirement |
|---|---|
| NFR-GDPR-1 | Each new table names its retention class in ADR 0020 D1's table. |
| NFR-GDPR-2 | Tenant offboarding and data-subject erasure follow ADR 0020 (accepted 2026-10-02) through US-038, US-039 and US-046 only. No other story hard-deletes tenant data. |
| NFR-GDPR-3 | Data residency is out of scope; if a customer requires it, it is a bridge/silo decision (§3.2 A), not a feature of this epic. |
| NFR-GDPR-4 | Contact PII on `tenants` is encrypted at rest (ADR 0006 approach). |

### 6.5 Observability

| ID | Requirement |
|---|---|
| NFR-OBS-1 | `tenantId` stays in MDC for every request and async task (already true via `MdcTaskDecorator`). |
| NFR-OBS-2 | Metrics: tenants by status, status-check cache hit ratio, invitations sent/accepted/expired, suspension enforcement latency — with bounded cardinality (no raw tenant id label). |
| NFR-OBS-3 | An alert fires if a request is served for a non-`ACTIVE` tenant (defence-in-depth counter in the status filter). |

---

## 7. Phased rollout

### Entry criteria (before the first MVP story merges)

- [ ] EPIC-002 Open Decision #4 closed: ArchUnit rule that every `@RestController` method carries
      `@RequiresPermission` or `@PublicEndpoint`, plus the self-invocation check. The epic owner
      committed on 2026-10-01 to land these before Epic 3 starts; which story carries them is
      their choice (it need not be US-018).
- [ ] US-016 and US-017 merged (EPIC-002 Open Decisions #6/#7).
- [x] Decisions D1, D2, D3, D5 and D6 recorded (see §8; approved 2026-10-01).
- [ ] ADR amendment for the platform path-tenant exception drafted (US-023 AC5).

### MVP — "second customer can be onboarded safely"

| Order | Stories | Why this order |
|---|---|---|
| 1 | US-021 | Schema, isolation gaps and `auth_events` partitioning first; everything builds on them |
| 2 | US-023 | Platform authority before any platform endpoint |
| 3 | US-025 | Lifecycle and its enforcement before tenants exist in production |
| 4 | US-027, US-030 | Tenant sign-in; members page (the invitation dialog lives on it) |
| 5 | US-028, US-031 | Invitations end to end; tenant profile and header |
| 6 | US-024 | Provisioning (needs US-028 for the bootstrap invitation) |
| 7 | US-037, US-045 | Operator console (needs US-024), operator MFA (US-045 must merge before any operator account exists in production) |

Exit: a second tenant is provisioned in staging by an operator who signed in with MFA, its admin accepts an invitation,
invites a member, and a pen-test-style cross-tenant suite shows zero findings.

### Next — "self-service and accountability"

US-034 (plan limits: seats and rate), US-036 (audit viewer), US-046 (retention jobs and the shared
job runner; partitioning itself already landed in US-021 AC7). ADR 0019 and ADR 0020 were accepted
on 2026-10-02.

### Later — "offboarding and retention"

US-038 (tenant data export) and US-039 (tenant purge and member erasure), both on US-046's job
runner. Enterprise identity, organisations and branding (US-033, US-041–US-044) are in the backlog
(§5.2) and return through their own Gate 1 when a customer or regulation requires them.

---

## 8. Decisions needed, open questions and risks

### 8.1 Decisions needing human input

| # | Decision | Options | Recommendation | Blocks |
|---|---|---|---|---|
| D1 | How the tenant is identified at sign-in | (a) subdomain `acme.nexus.app`; (b) path `/t/acme/login`; (c) email-domain discovery | **Approved 2026-10-01.** **(b) path** for MVP — no wildcard DNS/TLS or cookie-domain work; (a) can be added later. (c) needs verified domains (US-041). | US-027 |
| D2 | Identity model | (a) per-tenant users (today); (b) global identity + memberships | **Approved 2026-10-01.** **(a)** — matches the schema; revisit if cross-tenant users are requested | US-027–US-030 |
| D3 | Public self-registration | (a) keep for bootstrap tenant only; (b) invite-only everywhere; (c) per-tenant toggle | **Approved 2026-10-01.** **(a) now, (b) for customer tenants** — today every registrant joins the default tenant with no role | US-027 |
| D4 | Organisations (sub-tenant level) | (a) defer; (b) build as in previous draft | **Decided 2026-10-01.** **(a) defer** until a feature consumes them | US-044 |
| D5 | Bootstrapping the first operator account | (a) migration-seeded operator tenant + CLI/runbook to invite the first operator; (b) env-configured email invited at startup | **Approved 2026-10-01.** **(a)** — auditable and matches existing runbook practice | US-023 |
| D6 | Deletion grace period | 14 / 30 / 90 days | **Approved 2026-10-01.** **30 days** (configurable). This answers only the grace-period part of ADR 0020 Q2 early (so US-025 can show a purge date); recorded in ADR 0020 D2.2 (accepted 2026-10-02) | US-025, US-039 |
| D7 | Distinct Tenant Owner role | (a) no — rely on last-admin protection; (b) yes | **Decided 2026-10-01.** **(a)** for MVP; revisit if a customer asks for an owner distinct from admins | — |
| D8 | Split with RBAC UI | Members page (US-030) here; role assignment/editing UI in US-019/US-020 | **Approved 2026-10-01.** One members list, built in US-030; each row links to the US-019/US-020 role screens, which do not build their own list | US-030 |
| D9 | Enterprise SSO | build on Spring Security vs buy (WorkOS / Auth0) | **Decided 2026-10-01.** **Build OIDC on Spring Security** (already in the stack; no per-connection fee; identity stays in Nexus). Re-evaluate buying only if a customer needs SAML or SCIM (US-043), at US-042 Gate 1 | US-042 |
| D10 | Plan tiers | names and seat limits per tier | **Decided 2026-10-01.** Tiers and their limits are configuration data (a `plan_tier` value on `tenants`, limits in config), not code. Tiers (owner, 2026-10-01): **Free**, **Teams**, **Enterprise**. Member limits (decided at the owner's request): Free 5, Teams 50, Enterprise 500 by default, changed per contract with the per-tenant override (US-034) | US-034 |
| D11 | MFA for operator accounts | (a) required before GA; (b) optional / later | **Approved 2026-10-01.** **(a)** — NFR-SEC-4 is a GA blocker. Delivered by US-045 | GA, US-045 |
| D12 | ADR 0019 — per-tenant quotas | The five open questions in ADR 0019 | **Accepted 2026-10-02 (delegated).** Rate limit per tenant per tier (Free 300 / Teams 1,200 / Enterprise 6,000 req/min, starting values to load-test), seats checked in the database, one concurrent export; `429` + `Retry-After` for rate, `409` for quotas; rate limits fail open as ADR 0016 D4; metrics labelled by tier, not tenant id | US-034, US-038 |
| D13 | ADR 0020 — data lifecycle | The five open questions in ADR 0020 | **Accepted 2026-10-02 (delegated).** Audit events 13 months (PCI DSS 10.5.1), tokens 30 days after expiry, backups 35 days "beyond use"; purge hard-deletes tenant rows and keeps a tombstone; erasure anonymises the user row; old audit data leaves by monthly partition drop through a separate `nexus_retention` account; one region for MVP. Legal to confirm periods before GA | US-036, US-038, US-039, US-046 |

### 8.2 Open questions

1. US-018 (RBAC hardening) is planned but not yet filed. Will it include EPIC-002 Open Decision #4
   (still OPEN)? If not, a story must be added ahead of US-021. **Resolved 2026-10-01:** the owner
   will land the three build checks before Epic 3 starts; this stays an entry criterion (§7)
   whichever story carries them.
2. Should the `MEMBER` role receive `tenant:read` so US-031 can call `GET /tenants/me`, or should a
   narrower "tenant summary" come with `/users/me`? **Decided 2026-10-01:** a tenant summary on
   `/users/me`; `MEMBER` does not get `tenant:read` (US-031 AC8).
3. Which user status represents a reversible member deactivation (US-030 AC2)? **Decided
   2026-10-01:** the existing `DISABLED`, with an explicit admin-only reactivation (US-030 AC2).
4. What exact operator identity, if any, may be shown to tenants in their audit view (US-036 AC4)?
   **Decided 2026-10-01:** a role label and event id only (US-036 AC4).
5. Do existing environments hold any `users`/`roles` rows with a tenant id other than the bootstrap
   tenant? (US-021 AC2 fails the migration if so — run the check in each environment first.)
   **Resolved 2026-10-01:** no environment is set up yet, so there is no existing data to check.
   US-021 AC2's pre-check stays as a guard.
6. Which story delivers MFA for operator accounts before GA (NFR-SEC-4 / R3)? **Resolved
   2026-10-01:** US-045, added to this epic's MVP.

### 8.3 Risks

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| R1 | A missed tenant predicate leaks data (pool model) | Med | Critical | US-021 FKs, US-021 ArchUnit extension, NFR-ISO-3 ITs, pre-GA pen test |
| R2 | Platform authority misconfigured → tenant admin gains cross-tenant control | Low | Critical | US-023 AC1/AC2/AC4 as merge-blocking tests; separate permission namespace |
| R3 | Operator accounts protected by password only (no MFA exists) | Med | High | US-045 (MVP; GA blocker per D11 and NFR-SEC-4) |
| R4 | FK migration fails on unexpected data in some environment | Low (no environment exists yet) | High | Migration pre-check with clear error (US-021 AC2) |
| R5 | Suspension bypass via existing tokens | Low (after US-025) | High | Per-request status filter; login/refresh blocked; ≤ 60 s SLO test |
| R6 | ArchUnit cannot see JPQL bodies; a bound-but-unused `tenantId` still leaks | Med | High | Code review + cross-tenant ITs; spike Hibernate `@TenantId`/`@Filter` as a follow-up |
| R7 | `auth_events` grows into a general audit log with a misleading name and identity-context ownership | Med | Low | Accept for this epic; revisit with ADR 0020 |
| R8 | ADR 0019/0020 periods or limits turn out wrong for real customers or law | Low | Med | Both accepted 2026-10-02 with values held in config / one table; load test (ADR 0019 rule 2) and legal review (ADR 0020 rule 1) before GA |
| R9 | Changing sign-in URLs (D1) breaks existing bookmarks / email links | Low | Med | US-027 AC4 keeps bootstrap-tenant behaviour |
| R10 | Duplicate members UI between this epic and RBAC UI | Low (D8 approved) | Low | D8: one list in US-030 |
| R11 | A deactivated member keeps API access until their access token expires (≤ 15 min) | High (by design today) | Med | US-030 AC2 names it; Gate 2 decides whether to add a per-request user-status check alongside US-025's tenant check |
| R12 | The invitation-grant path (US-028 AC8) bypasses `RoleAssignmentService`'s caller gate and becomes a new privilege-escalation route | Med | Critical | Grant only the role frozen on an invitation that passed the gate when issued; single-use hashed token; mandatory security review of US-028 |

---

## Appendix A — Industry research comparison

> **Method and confidence.** Research was done by web search restricted to vendor-owned domains;
> direct page fetches were blocked by the environment's egress policy, so claims rest on
> search-result extracts of official pages. Items the research could not confirm from an official
> page are marked _(unverified)_ and are **not** used as the sole basis for any story. Re-open the
> URL before quoting a figure in a contract or ADR.

### A.1 Comparison

| Product | Hierarchy | RBAC approach | SSO / SCIM | Delegated admin | Lifecycle / grace | Isolation / tiering | Quotas / limits | Audit retention / export | Self-serve vs operator |
|---|---|---|---|---|---|---|---|---|---|
| Salesforce | Org (+ sandbox orgs); My Domain URL per org | Profiles + permission sets / groups (muting); record access via org-wide defaults, role hierarchy, sharing | SAML/OIDC via My Domain; SCIM _(unverified)_ | Delegated administration _(unverified)_ | Developer Edition: self-reactivate ≤ 30 days, via Support ≤ 60 days | Editions; 4 sandbox tiers | Sandboxes per edition | Setup Audit Trail ≥ 180 days; CSV + API | Very strong self-serve (Setup) |
| Atlassian Cloud | Organization → sites → apps | Groups + admin roles (org, site, app, user-access admin) | SAML + SCIM with Atlassian Guard | Site / app / user-access admins | Managed account deactivated 14 days before deletion | Plans; data residency; Isolated Cloud | Sandboxes: 1 per app (Premium) / up to 5 (Enterprise) | Up to 180 days (Guard/Enterprise); export advised | Admin UI + Organizations REST API |
| Slack Enterprise Grid | Org → workspaces | Fixed owner/admin tiers + system roles | SAML; SCIM on Business+/Enterprise | Workspace owners; system roles | Deactivation keeps profile; workspace deletion permanent | EKM add-on; single-region data residency | — _(not researched)_ | Audit Logs API Enterprise-only; retention _(unverified)_ | Org admin dashboard |
| Microsoft Entra ID | Tenant → administrative units; multi-tenant orgs | Built-in + custom roles, scopable to AUs | SAML/OIDC; outbound SCIM; B2B guests | Administrative units, restricted-management AUs | Deleted users restorable 30 days | Licence tiers | — _(not researched)_ | 7 days (Free) / 30 days (P1/P2); Azure Monitor for longer | Portal + Graph API |
| GitHub Enterprise Cloud | Enterprise → orgs → teams | Built-in + up to 20 custom repo and 20 custom org roles | SAML (org or enterprise); SCIM; EMU | Org owners under enterprise owners (owners get no org content by default) | Deleted repo restore / member reinstatement within 90 days | Personal accounts vs EMU | 20 custom repo + 20 custom org roles | 180 days (Git events 7); streaming to SIEM/storage | UI + REST |
| Shopify Plus | Organization → up to 10 stores | Organization roles + store roles | SAML + SCIM after domain verification | Store user administrator | _(unverified)_ | Plan tier | 10 stores; unlimited staff | _(unverified)_ | Admin UI |
| Stripe | Organization → accounts; Connect platform → connected accounts | Built-in + custom roles | SAML with JIT; SCIM; group mapping | Per-account roles | _(unverified)_ | Connect controller properties | — _(not researched)_ | Security history / activity 180 days; CSV; Activity Logs API | Dashboard + API |
| AWS Organizations + SaaS Lens | Root → OUs (≤ 5 levels) → accounts | IAM + SCP/RCP guardrails | IAM Identity Center _(not researched)_ | Delegated-administrator accounts | Closed account reopenable within 90 days | Silo / pool / bridge; tier-based silo for premium tenants | 10 accounts default (adjustable); 2,000 OUs | CloudTrail _(not researched)_ | API / IaC-first |
| Auth0 Organizations | Tenant → organizations → members | Roles per membership | Per-organization connections; auto-membership | "My Organization" API _(blog source)_ | Invitation TTL default 7 days, max 30 | Pooled | 100 k orgs, 10 connections per org (defaults) | 1–30 days by plan; log streams | Dashboard + API |
| WorkOS | Organization → memberships | Multiple roles per membership; IdP group → role mapping | SSO + Directory Sync; Admin Portal | Customer IT via Admin Portal | Directory events drive deprovisioning | — | — _(not researched)_ | 30 days default, configurable up to 10 years; streaming | Customer-facing Admin Portal |
| Okta | Single org or hub-and-spoke orgs | Custom admin roles + resource sets | SAML/OIDC; SCIM client | Resource-set-scoped admins | "Deprovision", not delete | Separate orgs for residency / strong delegation | 10 k resource sets; 1 k resources per set | System Log 90 days | Admin console + API |

### A.2 Table-stakes vs differentiators

**Table stakes** (expected by the first mid-market/enterprise buyer) and where this epic covers them:

| Capability | Covered by |
|---|---|
| Tenant entity with admins; users belong to a tenant | US-021, US-024 |
| Invitation with expiring token and pre-assigned role | US-028 |
| Small set of built-in roles with server-side checks | EPIC-002 (exists) + US-024 seeding |
| Every query scoped by tenant; tenant context from the token | US-021, NFR-ISO-1 |
| Suspend / deactivate users and tenants; soft delete with grace | US-025, US-030 |
| Tenant-visible audit log with export | US-036 |
| Operator console with audited actions | US-037, US-025 |
| Enforced MFA / SSO at least on a paid tier | Operator MFA: US-045 (MVP); SSO: US-042 (backlog) |

**Differentiators** (enterprise tier; deliberately Later or out of scope): SCIM with group mapping
(US-043, backlog); domain verification → managed accounts (US-041, backlog); custom roles / scoped delegated admin
(custom roles exist via US-015; scoped delegation not planned); multi-level hierarchy (US-044, backlog);
audit streaming and configurable retention; data residency, BYOK/EKM, silo tiers; per-tenant
sandboxes; customer-facing IT admin portal; per-tier noisy-neighbour throttling (US-034).

### A.3 Fit for Nexus

| Pattern | Fit now? | Reason |
|---|---|---|
| Pool isolation with automated guards | **Yes** | Matches single MySQL + monolith; guards are cheap (US-021) |
| Per-tenant slug in sign-in URL | **Yes** | Needed to resolve tenant before authentication; Salesforce/Slack precedent |
| Invitations with role + 7-day expiry | **Yes** | Cheap; replaces "everyone joins default tenant" |
| Separate platform authority | **Yes** | Required to fix G3 |
| Soft delete with grace and restore | **Yes** | Cheap now, expensive to retrofit |
| Global identity + multi-tenant membership | Not now | Schema assumes per-tenant users; no demand yet (D2) |
| Multi-level hierarchy | Not now | No consuming feature (D4) |
| Hibernate `@TenantId` / `@Filter` | Spike later | Could strengthen R6 but touches RBAC lock queries |
| SSO / SCIM / domain verification | Later | Build-vs-buy (D9) when a deal requires it |
| Silo / bridge, residency, BYOK | Not now | Operational cost far exceeds current need |
| Audit streaming to SIEM | Not now | Keep `auth_events` schema stream-friendly |

---

## Appendix B — Sources

AWS
- https://docs.aws.amazon.com/wellarchitected/latest/saas-lens/silo-pool-and-bridge-models.html — silo, pool, bridge definitions
- https://docs.aws.amazon.com/wellarchitected/latest/saas-lens/pool-isolation.html — pool isolation
- https://docs.aws.amazon.com/pdfs/wellarchitected/latest/saas-lens/wellarchitected-saas-lens.pdf — SaaS identity, tenant context in JWT, noisy neighbour, tiering, onboarding
- https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html — SCPs as guardrails
- https://docs.aws.amazon.com/organizations/latest/userguide/orgs_getting-started_concepts.html — OUs, delegated administrator
- https://docs.aws.amazon.com/organizations/latest/userguide/orgs_reference_limits.html — account/OU limits
- https://docs.aws.amazon.com/accounts/latest/reference/manage-acct-closing.html — 90-day post-closure period

Auth0
- https://auth0.com/docs/manage-users/organizations — Organizations overview
- https://auth0.com/docs/manage-users/organizations/configure-organizations/send-membership-invitations — invitation flow
- https://auth0.com/docs/api/management/v2/organizations/post-invitations — `ttl_sec` default 7 days, roles
- https://auth0.com/docs/manage-users/organizations/configure-organizations/enable-connections — per-org connections
- https://auth0.com/docs/deploy-monitor/logs/log-data-retention — log retention by plan

WorkOS
- https://workos.com/docs/domain-verification — DNS TXT domain verification
- https://workos.com/docs/directory-sync/understanding-events — directory sync events
- https://workos.com/docs/authkit/roles-and-permissions — membership roles
- https://workos.com/docs/reference/audit-logs/retention — audit retention

GitHub
- https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/accessing-the-audit-log-for-your-enterprise — 180 days, Git events 7 days
- https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise — audit streaming
- https://docs.github.com/en/enterprise-cloud@latest/admin/user-management/managing-users-in-your-enterprise/roles-in-an-enterprise — enterprise owners
- https://docs.github.com/en/enterprise-cloud@latest/admin/managing-iam/understanding-iam-for-enterprises/about-enterprise-managed-users — EMU
- https://docs.github.com/en/enterprise-cloud@latest/organizations/managing-peoples-access-to-your-organization-with-roles/managing-custom-organization-roles — custom org roles

Slack
- https://docs.slack.dev/admins/audit-logs-api/ — Audit Logs API, Enterprise only
- https://slack.com/help/articles/360018112273-Types-of-roles-in-Slack — org and workspace roles
- https://docs.slack.dev/admins/scim-api/ — SCIM API
- https://slack.com/help/articles/360019110974-Slack-Enterprise-Key-Management — EKM
- https://slack.com/help/articles/360035633934-Data-residency-for-Slack — data residency
- https://slack.com/help/articles/204475027 — deactivation and profile-data deletion

Microsoft
- https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/administrative-units — administrative units
- https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-reports-data-retention — log retention
- https://learn.microsoft.com/en-us/entra/identity/app-provisioning/user-provisioning — SCIM provisioning
- https://learn.microsoft.com/en-us/entra/fundamentals/users-restore — 30-day user restore
- https://learn.microsoft.com/en-us/entra/external-id/what-is-b2b — B2B guests

Atlassian
- https://support.atlassian.com/user-management/docs/verify-a-domain-to-manage-accounts/ — domain verification
- https://support.atlassian.com/security-and-access-policies/docs/view-audit-log-activities/ — 180-day org audit log
- https://support.atlassian.com/provisioning-users/docs/understand-user-provisioning/ — SCIM
- https://support.atlassian.com/user-management/docs/give-users-admin-permissions/ — admin roles
- https://support.atlassian.com/user-management/docs/delete-a-managed-account/ — 14-day deactivation before deletion

Salesforce
- https://help.salesforce.com/s/articleView?id=003834041&language=en_US&type=1 — "Permissions in Profiles Retirement Cancelled"; permission-set-led model still recommended
- https://admin.salesforce.com/blog/2026/the-salesforce-admins-guide-to-profiles-and-permissions — profiles for defaults, permission sets for access
- https://help.salesforce.com/s/articleView?language=en_US&id=admin_monitorsetup.htm — Setup Audit Trail
- https://help.salesforce.com/s/articleView?id=xcloud.domain_name_url_formats.htm&language=en_US&type=5 — My Domain URLs
- https://help.salesforce.com/s/articleView?id=sf.admin_deactivate_org.htm&language=en_US&type=5 — Developer Edition deactivation windows

Shopify
- https://help.shopify.com/en/manual/organization-settings/expansion-stores — store limit
- https://help.shopify.com/en/manual/your-account/users/roles/role-categories — organization vs store roles
- https://help.shopify.com/en/manual/your-account/users/security/advanced-security-features/scim — SCIM on Plus

Stripe
- https://docs.stripe.com/get-started/account/orgs/setup — Organizations vs Connect
- https://docs.stripe.com/get-started/account/teams/roles — roles and custom roles
- https://docs.stripe.com/get-started/account/sso/scim — SCIM
- https://docs.stripe.com/activity-logs — activity / security history

Okta
- https://developer.okta.com/docs/concepts/multi-tenancy/ — single org vs hub-and-spoke
- https://help.okta.com/oie/en-us/content/topics/security/custom-admin-role/custom-admin-roles.htm — custom admin roles and resource sets
- https://developer.okta.com/docs/guides/scim-provisioning-integration-overview/main/ — SCIM lifecycle
- https://help.okta.com/en-us/content/topics/reports/syslog-filters.htm — System Log 90 days

Internal
- `docs/ARCHITECTURE.md`, `docs/story/2-rbac/EPIC-002.md`, ADRs 0004, 0006, 0009, 0011–0016, 0019, 0020 in `docs/adr/`.

---

## Appendix C — Verification log

Five verification passes were run on this rewrite (2026-09-30 → 2026-10-01), plus a sixth on the 2026-10-04 restructure. Each pass re-read the
epic, re-checked codebase claims by opening the code, re-checked research attributions against
Appendix A/B, and checked story quality and consistency.

| Pass | Method | Found | Fixed |
|---|---|---|---|
| 1 | Script resolving every cited file path; grep checks of key claims (JWT `verify()`, `@RequiresPermission` call sites, `token_version` use, `JpaAuthEventRepository`, Redis key builders, MDC propagation) | All paths resolved. 6 story "Pattern" cells cited vendor features not in the research; US-017 described as shipped; US-030 overstated deactivation (access tokens are not re-checked per request); no story for operator MFA | Patterns re-attributed or marked _(not researched)_; US-017 status corrected; US-030 AC2 states the 900 s residual; added R11 and open question 6 |
| 2 | Full end-to-end re-read | Broken cross-reference (§3.3); lifecycle restore/PENDING gaps; `AttributeEncryptor` is typed to `EmailCipher` only (cannot be reused for tenant contacts as the old draft assumed); US-016 gate misdescribed (verified against ADR 0017); research table lacked a quotas column | All fixed; ADR 0017 wording used; quotas column added |
| 3 | Independent fresh-context adversarial review (20 findings), each spot-checked in code before acting | First-admin invitation could not be granted through `RoleAssignmentService` (same trap as G4; `user_roles.assigned_by` NOT NULL); adding platform permissions to `RbacDangerousPermissions` would break ADR 0018 admin-equivalence; `PENDING` lifecycle dead end; US-022 AC3 untestable before US-027; US-018 not yet filed; ADR 0013 D6 overstated; D6 vs ADR 0020 overlap; US-027/US-026 conflict on `PENDING`; ADR 0018 admin-equivalent caller omitted; no way to manage further operators; rate-limit store is in-memory by default; `user_roles` blocks DELETE only; forward reference in US-026; missing dependencies (US-024, US-034, US-036); US-040 persona; missing code anchors; ~10 vague ACs; bootstrap-tenant literal locations | All 20 fixed; added R12 (invitation-grant path) and made US-028/US-029 mandatory security-review stories |
| 4 | Targeted re-read of every Pass-3 change (the second independent reviewer hit a rate limit, so this pass was done directly) | Operator-tenant `PLATFORM_*` roles carry no dangerous permission, so the ADR 0017 gate would let any `user:write` holder there assign them; US-021 dependency wording | US-023 AC3 requires `TENANT_ADMIN` in the operator tenant to assign/revoke `PLATFORM_*` roles; dependency reworded |
| 5 | Scripted structure check (persona / capability / outcome / priority table / Given-When-Then / dependencies per story; AC numbering; MVP dependency order; no e-mail addresses or personal names) + path check | US-024 AC numbering out of order | Fixed; re-run of both scripts clean (the only unresolved path is the old draft's `V4__tenant_schema.sql`, quoted deliberately) |
| 6 | 2026-10-04 size audit against `/breakdown` sizing (≈400 production lines per task, 2–6 tasks per story, > 8 needs justification) and restructure | 5 stories too large, 1 under-sized label, 6 pairs with no value apart; US-028 AC7 scheduled before the US-030 page it lives on; no accept page for invitees; AC numbering out of order in four stories; garbled US-039 AC2; `TNT_` vs ADR 0019 `TENANT_`; US-042 title contradicting D9; US-046 not stating a reusable job runner | Merged to 15 stories (§5.2), Later identity stories moved to the backlog, partitioning moved to US-021 AC7, US-046 owns the job runner, US-045 split line agreed, all defects fixed. AC count checked by script: 138 before = 123 carried + 15 moved; 1 added (US-028 AC14) |

**Residual limits of verification.** Vendor documentation could not be fetched directly (egress
policy); research claims rest on search extracts of official pages and are marked where unverified.
Targets marked _(inferred)_ (latency budgets, story-point calibration, operator-identity display in
tenant audit views) have not been validated.
