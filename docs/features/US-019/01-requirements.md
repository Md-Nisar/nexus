# US-019 — Prerequisites for the RBAC Access Management UI: Requirements

**Status:** Approved at Gate 1 · **Owner:** Business Analyst

**Gate 1:** approved 2026-10-19 by the story owner, Md Nisar Ahmed
**Date:** 2026-10-18 · **Base:** `main` @ `2962b0e` (US-018 merged), branch `feature/US-019`
**Risk tier (from discovery):** high-risk (new PII-bearing endpoints, live authorization profile, atomic permission write path, change to denial disclosure). Full Gate 2 threat model and Phase 7 audit apply.

**Sources:** `docs/story/2-rbac/US-019.md` (authoritative, 31 items in Groups A-D), `US-020.md`, `EPIC-002.md` (US-019 entry), `docs/features/US-019/00-discovery.md`, benchmark `/tmp/claude-0/-home-user-nexus/03ad35e1-08cd-5f2e-b90b-c6d2776a6251/scratchpad/us019-benchmark.md`, US-018 closure record and ADRs 0006, 0014-0016, 0021-0025.

**Evidence tags.** **[VERIFIED]** = I re-checked it in code on 2026-10-18. **[REPORTED]** = taken from the discovery note or story and not re-checked by me. **[INFERENCE]** = my reading, not stated in a source. **[U]** = benchmark claim that was unverified (search-summary only, or general knowledge); must be verified before it goes into an ADR. **[S]** = seen in a search summary of the cited URL, not read in full.

No real names or emails appear in this document. Dev-seed credentials in the code are not repeated here.

---

## 1. Problem statement and business value

US-020 is the tenant-admin Access Management console. No screen calls any RBAC endpoint today. A gap review found that the console cannot be built as a pure UI story: it lacks backend endpoints (user directory, single-role read, live authorization profile), has a frontend defect in `permissionGuard`, has no app shell or design-system wrappers, has no test personas, and has unresolved product and security decisions.

US-019 closes those gaps so US-020 starts on a correct, tested platform and the UI never disagrees with the server's authorization rules.

Business value, stated as outcomes:
- Tenant admins get a console that neither mispredicts what they may do nor leaks data (US-020 depends on US-019 B4/B5).
- Security and Privacy approve the new PII display surface (emails) before it exists, not after (D5).
- US-020 is estimable and schedulable: every blocker is named, owned and sequenced.

**Bounded contexts:** `rbac` (B3-B8, most of Group B), `identity` (B1/B2 user directory), `common` (shared paging types if identity needs them), frontend `core` / `shared` / `features`, test and CI infrastructure, documentation. No new bounded context.

## 2. Scope and non-goals

**In scope:** the 31 items of the story (A1-A11, B1-B10, C1-C4, D1-D6), as re-stated in section 4 against current code.

**Non-goals (story Out of Scope plus clarifications):**
- The console screens themselves (US-020).
- User provisioning, invites, deactivation (Epic 3).
- US-018 work other than the two intersections the story names (A5 and A6); everything else of US-018 is closed.
- i18n framework adoption (D3 only centralises copy).
- [INFERENCE] Access-review campaigns, direct user-to-permission grants, time-bound assignments (US-020 non-goals, restated so nobody pulls them into this story).
- Choosing an implementation. This document states what must be true; classes, DDL and endpoint schemas belong to `/design`.

## 3. Context summary of what exists (spot-checked)

| Claim | Check | Result |
|---|---|---|
| `RbacDangerousPermissions` and `requireActiveTenantAdmin` are gone from production code | grep of `nexus-backend/src/main` | **[VERIFIED]** no hits. `ArchUnit RETIRED_SYMBOLS` guard **[REPORTED]** |
| Admin predicate is `RbacAdministrators.isAdministrator(held, catalogueIds)`; wrapper at `RoleAssignmentService.java:453` | grep | **[VERIFIED]** call sites at `RoleAssignmentService:453,740` and `RoleManagementService:640` |
| System `MEMBER` role holds `user:read` | `V5__rbac_schema.sql:128-136` | **[VERIFIED]** ("TENANT_ADMIN gets all 7; MEMBER gets user:read only") |
| Permission catalogue is 8 entries mirrored by hand on the frontend | `common/security/Permissions.java` | **[VERIFIED]** (V5 seeds 7, V6 adds `user:role:assign`). The mirror and its parity test are described in the Javadoc |
| `DevDataInitializer` is `@Profile("dev & !break-glass")` | `DevDataInitializer.java:41` | **[VERIFIED]**; the story's "dev/test profiles" is wrong |
| `SKIP_ACCESS_DENIED_REDIRECT` already exists and is used by the interceptor | grep | **[VERIFIED]** in `core/http/skip-access-denied-redirect.ts`, `api-error.interceptor.ts` and its spec |
| `shared/types/permission.ts` exists | glob | **[VERIFIED]** (contents of labels/grouping not read; **[REPORTED]** that labels and grouping are absent) |
| `permission.guard.ts` doc comment says a `canActivate` array is evaluated "sequentially" | `permission.guard.ts:22` | **[VERIFIED]** the wrong comment exists. That Angular uses `combineLatest` in `prioritizedGuardValue()` is **[REPORTED]** from the story and discovery; the router-level test in A1 is what proves it |
| Refresh de-duplication lives only in `auth.interceptor.ts` (`refreshInFlight`, module-private); `authGuard` calls `authService.refresh()` directly | `auth.interceptor.ts:25,64`; `auth.guard.ts:27` | **[VERIFIED]**. So `AuthService.refresh()` itself has no dedupe |
| Playwright config starts only the frontend | `playwright.config.ts` (`baseURL` `http://localhost:2000`, `webServer`) | **[VERIFIED]**; backend-dependent specs skip when the backend is down (`e2e/auth/*.spec.ts` use `test.skip`/`testInfo.skip`) |
| Only `performance-smoke.yml` references MySQL | workflow grep (counts) | **[VERIFIED]** frontend-ci has e2e references, none for MySQL; whether the e2e job is a required status check is **not visible from the repo** |
| `findActivePermissionNames` reads live from DB | `UserRoleQueryPort`, `JpaUserRoleRepository` | **[VERIFIED]** |
| Everything else in the discovery table (ArchUnit layer rules, `PageParams` location, `EmailBlindIndexService` behaviour, `RoleView` shape, `resolveRoleInTenant`, 429 plumbing, `findRole` soft-delete filtering) | not re-checked | **[REPORTED]** / unverified; to be confirmed in `/design` |

## 4. Story text vs current code (corrections table)

| # | Story text says | Current reality | Effect on this story |
|---|---|---|---|
| K1 | B5: derive `isSensitive` from "the backend's single source (today `RbacDangerousPermissions`)" | That class is retired by US-018 M3 **[VERIFIED]**. No per-permission "sensitive" concept exists; what exists is per-role "admin-defining" (holds the whole catalogue) and the `RBAC_010` provenance rule **[REPORTED]** | B5 has no source to derive from. The meaning must be defined (Q2). High risk |
| K2 | B4: "same predicate `requireActiveTenantAdmin` uses" | Retired. Predicate is `RbacAdministrators.isAdministrator`; wrapper `isCallerAdministrator` is package-private in `RoleAssignmentService` **[VERIFIED]** | B4 must reuse the domain predicate; must not re-implement it |
| K3 | A5: typed catalogue is "the frontend half of US-018 B5", everything is `string` | `Permission` type already exists in `shared/types/permission.ts` **[VERIFIED]** (and guard/directive typing **[REPORTED]**) | A5 shrinks to labels, grouping and a label-completeness test |
| K4 | A6: "delivers US-018 C6 ... unless US-018 ships it first" | US-018 shipped it **[VERIFIED]** | A6 shrinks to confirming spec coverage of both branches |
| K5 | B9: record when US-018 C1/C2/C3 ship | Merged on `main` **[REPORTED]**; `STATUS.md` rows are stale | B9 is answered; remaining work is correcting `STATUS.md` (US-018 doc fix, not this story's code) |
| K6 | C1: seed in "dev/test profiles" | `DevDataInitializer` runs under `dev & !break-glass` only; the `test` profile never runs it **[VERIFIED]** | Personas for ITs need a separate mechanism, or the story wording changes to dev only (Q-N2) |
| K7 | C1: seed a second tenant "with its own admin" | No tenants table exists (V5 comment); system roles and `role_permissions` are seeded by migration for the bootstrap tenant only **[REPORTED]** | A second tenant's roles do not exist unless created in code; the story does not say how (Gap G6) |
| K8 | B3: cross-tenant "follows the current US-015 rule, or the US-018 B1 rule once shipped" | US-018 is shipped; the 404 `ROLE_NOT_FOUND` rule applies **[REPORTED]** | Remove the conditional |
| K9 | D4: "permission-cache TTL 900 s + token TTL 900 s = 30 min" | Story cites `application.yml:143,194`. US-018 A9 (revocation epoch, `ADR-0022`) may shorten this **[REPORTED]**; I did not re-read the config | Wording must be re-grounded in current config before D3 content is approved (Q-N3) |
| K10 | A1: `permissionGuard` doc comment and contract spec accept same-array composition | Comment wrong **[VERIFIED]**; `DEVELOPMENT_GUIDE.md` also repeats it **[REPORTED]** (`:149`, `:158-163`) | D6 must fix those lines |
| K11 | C4: "Playwright config starts only the frontend" (to verify) | Confirmed **[VERIFIED]** | C4 is a CI job to create |
| K12 | Story says "~30 criteria" | A1-A11, B1-B10, C1-C4, D1-D6 = **31** items | "~30" is right; 31 is the count used here |

## 5. Functional requirements

Status values: **Delivered** (verify only), **Extend** (exists, change), **Create**, **Human** (a decision or artefact people produce; code cannot satisfy it). Priority is the story's. Behavioural items use Given/When/Then.

### Group A — Frontend

| ID | Status | Requirement (testable) |
|---|---|---|
| **A1** P0 | Extend | **Given** an entitled signed-in user, **when** they reload or deep-link to a route protected by `authGuard` and `permissionGuard`, **then** they land on that route and not on `/access-denied`. **Given** an unentitled user, same action, **then** `/access-denied`. **Given** a signed-out user, **then** `/auth/login`. A router-level test with a real `Router` and a refresh delayed 500 ms proves the first case. The `permissionGuard` doc comment, the contract spec and `DEVELOPMENT_GUIDE.md` are corrected. The chosen option (Q7) is enforced by the contract spec (option b: the spec rejects `[authGuard, permissionGuard]` in one array). **Constraint:** the fix must not cause a second `POST /refresh` in the same cold start (see R5) |
| **A2** P0 | Create | A layout route, parent of all signed-in pages and carrying `authGuard`, provides: header with product name; primary nav from a typed config filtered by permission; user menu with logout (moved out of `DashboardComponent`); skip-to-content link; `header`/`nav`/`main` landmarks. `/dashboard` moves under it. Below 960 px the nav collapses to a menu button. Existing test ids `logout-button` and `dashboard-root` keep working or the specs that use them are updated in the same change **[REPORTED]**. The shell and the existing root header in `app.html` do not both render a header for signed-in pages (Q12) |
| **A3** P0 | Create | Nine wrappers in `shared/ui` (`nx-checkbox` with `indeterminate`, `nx-tabs` routable, `nx-breadcrumb`, `nx-chip`, `nx-tooltip`, `nx-menu`, `nx-skeleton`, `nx-search-field` debounced with clear, `nx-page-header`), each with a spec, a preview entry and an axe pass; typed-confirmation variant on `NxDialog`; `NxAnnouncer` wrapping CDK `LiveAnnouncer` (polite). Only `shared/ui` imports Material/CDK; no raw hex/px; component styles within 4 kB warn / 8 kB error. **Gap:** unit tests have no axe today **[REPORTED]**; "an axe pass" needs a defined mechanism (Gap G8) |
| **A4** P0 | Extend | `NxTable` supports a custom cell template (actions column, badge-plus-icon), an empty-state slot (**[REPORTED]** already present), a sticky header and an optional caption. Existing callers' specs pass unchanged |
| **A5** P0 | Extend (mostly delivered) | `Permission` union exists **[VERIFIED]**. Add `PERMISSION_LABELS` (readable label per permission) and resource grouping metadata. A test fails when the backend catalogue fixture contains a permission with no label. Resource derivation: segment before the first `:` (US-020 A3 parse rule) |
| **A6** P0 | Delivered (verify) | `SKIP_ACCESS_DENIED_REDIRECT` is exported from `core/http` **[VERIFIED]**. **Given** an `RBAC_001` 403, **when** the request does not carry the token, **then** the client navigates to `/access-denied` with no query params; **when** it carries the token, **then** no navigation. Both branches have a unit test (the spec file exists; branch coverage not checked) |
| **A7** P1 | Create | Wildcard `**` route renders Not Found with a link home, inside the shell when signed in |
| **A8** P1 | Create | A `TitleStrategy` sets `"{page} · Nexus"` from route `title`; after navigation focus moves to the page `h1` (or `main`). WCAG 2.4.2 / 2.4.3. Existing AccessDenied self-managed focus must not double-handle |
| **A9** P1 | Extend | **Given** a user on Access Denied, **then** the page shows their current role names and a "Contact your administrator" target taken from `AppConfig`, replacing the `TODO(PM)` mailto. **Blocked on a PM decision** for the contact value and where it comes from (Q-N5). Role names shown come from a source that exists client-side (JWT roles claim is up to 15 min stale; B4 is the live source) (Q-N5) |
| **A10** P2 | Extend | **Given** a signed-out user opens a protected URL, **when** they sign in, **then** they land on that URL. `returnUrl` accepted only if it starts with `/`, does not start with `//`, and contains no scheme or backslash [INFERENCE: backslash and encoded variants are not in the story; see Edge cases]. Otherwise `/dashboard` |
| **A11** P1 | Create | A typed contract for RBAC and user-directory DTOs, by option (a) generated from OpenAPI with CI regeneration check, or (b) hand-written interfaces plus a contract test against recorded responses (Q8). Either way a backend DTO change that is not reflected fails a test |

### Group B — Backend

| ID | Status | Requirement (testable) |
|---|---|---|
| **B1** P0 | Create | `GET /api/v1/users` (filters `status`, `email`, paging, `size` <= 100) and `GET /api/v1/users/{userId}`; permission gate decided in Q1; tenant from the JWT. Response fields exactly: `userId, email, status, emailVerified, createdAt`; never `tenant_id`, `email_hmac`, password hash, lockout counters. **Given** two tenants, **when** tenant A lists users, **then** no tenant B user appears. **Given** a cross-tenant `userId`, **then** 404 identical in body shape to a missing id. **Given** `email=` with an exact existing email in the tenant, **then** one result; with a non-existing or other-tenant email, **then** an empty 200 page (indistinguishable). No prefix/contains search. **Given** `size` > 100, **then** reject or clamp as `api-design` states (the story says either; Q-N6). Logs carry actor id and tenant id, never the email or the queried email. Behind `feature.nexus-us019-user-directory.enabled` (default `false`); when off the route is 404 `RESOURCE_NOT_FOUND` **[REPORTED]**. **Not satisfiable until Q1 and D5 are decided** |
| **B2** P1 | Create | `GET /api/v1/users?ids=` with <= 100 ids, same shape; ids outside the tenant are silently omitted. **Given** 101 ids, **then** rejected (the story does not say how; Gap G7). Must not become an existence oracle across tenants (omission is identical to non-existence) |
| **B3** P0 | Extend | `GET /api/v1/roles/{roleId}` with `role:read`: 200 own role; 404 missing; 404 cross-tenant with the same body as missing **[REPORTED rule]**; soft-deleted role behaviour must be tested (not verified whether `findRole` filters soft-deleted) |
| **B4** P0 | Create | `GET /api/v1/users/me/authorization`, authenticated, own data only, no path variable. Returns `roles`, `permissions`, `isAdministrator`, read live from the DB. **Given** a role revoked and the access token not yet refreshed, **then** the response reflects the revocation immediately. **Given** a user holding a custom role that holds the whole catalogue, **then** `isAdministrator` is true. `isAdministrator` uses `RbacAdministrators.isAdministrator`; not re-implemented. Not served from the permission cache or JWT claims. Flag and controller placement: Q6 |
| **B5** P0 | Create, **definition needed** | `PermissionResponse` gains additive `isSensitive`. **Given** `GET /permissions`, **then** `isSensitive` is true exactly for the set defined by Q2. A test fails when the catalogue and the sensitive set disagree. **Not testable until Q2 is answered** |
| **B6** P1 | Extend | `RoleResponse` gains additive `memberCount` (active holders; count excludes revoked) and `permissionCount`. Counts are for the caller's tenant only. Gate: is `memberCount` acceptable under `role:read` (story asks Gate 1). Residual: `memberCount = 1` on an admin-defining role discloses a single administrator (Q-N7). Page of 100 roles must not issue per-role queries (see NFR performance) |
| **B7** P1 | Extend | Additive `reason` on `RBAC_001` only for an allow-list; cross-tenant, malformed-auth and missing-tenant denials stay opaque. **Given** a throttled caller, **then** 429 with `Retry-After`, not a 403 reason. The story's allow-list includes `THROTTLED`, but today throttle surfaces as `NOT_TENANT_ADMIN` and the throttle port returns a boolean with no retry-after **[REPORTED]**, so returning that reason would mislead. Disclosure rules need the Gate 2 threat model first |
| **B8** P1 | Create | `PUT /api/v1/roles/{roleId}/permissions` with `{ permissionIds }`: all-or-nothing, same per-permission rules as attach/detach (system-role immutability, grant-subset, provenance `RBAC_010`, duplicate handling), one audit event per change, same transaction, post-commit cache/epoch effects as attach/detach. **Given** one item violates grant-subset, **then** the whole request is rejected, no rows change, no success audit rows. **Given** the target set equals the current set, **then** success with no audit rows and no epoch bump **[REPORTED]**. **Given** an unknown or other-tenant permission id, **then** rejected the same way (not specified; Gap G9). Concurrency and locking: Q4, Q5 |
| **B9** P1 | Delivered (doc only) | Answer recorded: US-018 C1/C2/C3 are on `main`. Action: correct `docs/features/US-018/STATUS.md`. [INFERENCE] That file is outside this story's code; confirm ownership |
| **B10** P2 | Extend | Each RBAC and user-directory operation documents its error responses (`RBAC_001`-`RBAC_009`, `RBAC_010` [INFERENCE: story lists up to 009, code has 010], 404 codes, `VALIDATION_FAILED`) and the `ProblemDetail` schema. Verified by an OpenAPI test that fails when a documented code is missing |

### Group C — Environments, test data, rollout

| ID | Status | Requirement |
|---|---|---|
| **C1** P0 | Extend | **Given** a fresh dev DB, **when** the app starts under `dev`, **then** the following exist in the bootstrap tenant: a second `TENANT_ADMIN`, a `MEMBER`, a "role manager" custom role (`role:read`, `role:write`) with a holder, a "user manager" custom role (`user:read`, `user:role:assign`) with a holder, one locked user, one pending (unverified) user; and a second tenant with its own admin. **Given** a re-run, **then** nothing is duplicated. **Given** the `prod` profile, **then** nothing is seeded. Dev credentials documented as dev-only. Open: test-profile coverage (K6), how the second tenant's roles are created (K7), how locked/pending states are produced without a domain method **[REPORTED unverified]** |
| **C2** P0 | Create | A shared Playwright fixture logs in as each C1 persona (API login plus `storageState`) and exposes an axe helper (`wcag2a`, `wcag2aa`, zero critical/serious). New specs under `e2e/access-management/`. Today login is by UI against hardcoded `http://localhost:1000` **[REPORTED]** |
| **C3** P1 | Human + doc | A written per-environment plan for the three flags (us012, us015, us019), including confirmation of prod's current values. The console is never released where its APIs are off. **Cannot be satisfied from the repo**: prod values are not in it. Needs an Ops/PM owner |
| **C4** P1 | Create | CI runs the console e2e suite against a real backend + MySQL + Redis (or a documented stub), and the suite is a required check. Pattern exists in `performance-smoke.yml`. Whether e2e is required today is unknown (Q9) |

### Group D — Decisions and documentation

| ID | Status | Requirement |
|---|---|---|
| **D1** P0 | Delivered | Epic ownership resolved 2026-10-05; EPIC-002 updated. Verify only |
| **D2** P0 | **Human** | Wireframes and hi-fi designs for every US-020 page and dialog (desktop and 320 px) with accessibility annotations, approved by PM and UX. Code cannot satisfy this |
| **D3** P1 | **Human** | One reviewed content deck: errors per code, confirmations, disabled-reason text, empty states, propagation text. Benchmark text can seed it |
| **D4** P0 | Human + verify | Propagation wording grounded in config. Recommended text: "Changes reach affected users within about 30 minutes, or as soon as they sign in again." The number must be recomputed from current config (K9) and re-reviewed |
| **D5** P0 | **Human** | Security/Privacy approve: emails shown to the directory-permission holders; the enumeration posture; CSV export and retention (US-020 E3); admin-roster exposure on the Members tab (US-018 RES-37). Recorded as an ADR-0006 addendum plus a Gate 2 threat model covering B1, B4, B7. B1 cannot ship before this |
| **D6** P1 | Extend | Developer guide documents the shell, guard composition rule, typed permissions, 403 opt-out, personas. Corrects the "sequentially" statements. Doc and code must not disagree (docs/README rule) |

## 6. Non-functional requirements

**Security and tenant isolation**
- NF-S1: Every new endpoint derives the tenant from the JWT only, never from a parameter. Every repository method on tenant-owned data carries "Tenant" in its name or `@Param("tenantId")` (ArchUnit **[REPORTED]**).
- NF-S2: Cross-tenant ids and misses are indistinguishable (status, body shape, and, where measurable, timing class) for B1, B2, B3.
- NF-S3: Each new `@RestController` handler carries exactly one access marker; B4 is authenticated-only with no path variable, UUID or request argument (ArchUnit **[REPORTED]**).
- NF-S4: Frontend gating is UX only; server stays authoritative.
- NF-S5: Directory enumeration is rate-limited and audited (the story is silent; benchmark section 9 marks this as design judgement [U]). Throttling policy for B1 `email=` is open (Q-N1).
- NF-S6: `returnUrl` open-redirect resistance (A10), tested with `//evil`, `/\evil`, `https://`, `javascript:`, encoded variants.

**PII**
- NF-P1: Email is returned only by B1/B2 and only to holders of the directory permission (Q1). It is never in logs, metrics labels, audit-event payloads, error messages or traces. ADR-0006: lookup via `EmailBlindIndexService` only.
- NF-P2: No `email_hmac`, hash, or counters in any response. A contract test asserts the exact field set.
- NF-P3: Retention and CSV handling is a D5 decision, not code-defined here.

**Performance and paging**
- NF-F1: List endpoints cap `size` at 100. [INFERENCE: the story gives no RPS/latency target.] No target RPS or p95 is stated anywhere in the source: see Gap G1. Proposed for confirmation: B1/B3/B4 p95 under 200 ms at the dev stack data volume; B4 is called once per console open and after own-access changes, so expected low RPS; B1 at admin-only usage, expected under 10 RPS. Hot-path determination (template question): **not hot path as far as the source shows** [CONFIRM].
- NF-F2: B6 counts must be computed with a fixed number of queries per page, not per role (US-020 allows up to 500 roles per tenant).
- NF-F3: B1 uses the existing tenant+status index; no migration is expected **[REPORTED]**. The `email=` path uses the existing blind-index lookup.
- NF-F4: B8 request size bound is unspecified (maximum `permissionIds` length; catalogue is 8 today). Gap G9.

**Availability and rollout**
- NF-A1: All new endpoints are behind flags, default `false` (B1, B2, B4 under us019, B3, B5, B6, B8 under us015 **[story]**). A disabled controller yields 404 `RESOURCE_NOT_FOUND` **[REPORTED]**.
- NF-A2: Each flag turns on independently without a deploy order dependency except as stated in section 9. No SLO is stated for these endpoints (Gap G1).

**Accessibility (WCAG 2.2 AA)**
- NF-X1: Every new wrapper and shell element passes axe (`wcag2a`, `wcag2aa`, plus 2.2 rules where the axe version supports them) with zero critical/serious violations, light and dark themes. The story and US-020 cite **WCAG 2.1 AA**; the request is for **2.2 AA** (Q-N4). 2.2 adds target size minimum (2.5.8), focus not obscured (2.4.11 - relevant to sticky headers in A4 and the shell), dragging movements, consistent help, redundant entry, accessible authentication. The sticky table header (A4) and the shell header must not obscure focused elements.
- NF-X2: Skip link, landmarks, one `h1` per page, focus to `h1` on navigation (A8), polite live-region announcements (A3 `NxAnnouncer`), reflow at 320 px, `prefers-reduced-motion` respected.
- NF-X3: Disabled controls that need an explanation use `aria-disabled` with focus retained and visible reason text, not tooltip only (benchmark section 2 [S] css-tricks, PatternFly, Polaris).
- NF-X4: Tri-state checkbox follows the APG checkbox pattern [S] (checked / mixed / unchecked).

**Observability** (per `docs/observability-standards.md`; the standard was not re-read, names below are placeholders for `/design`)
- NF-O1: Each new endpoint emits a request metric (outcome by status class), a counter for denials and a counter for cross-tenant misses (existing pattern for roles **[REPORTED]**), with no email or user id as a metric label.
- NF-O2: Logs carry actor id, tenant id, trace id, outcome. WARN on cross-tenant attempt. Never the email, the queried email, or the request body.
- NF-O3: Audit events: B8 writes one event per permission change in the same transaction (ADR-0024 **[REPORTED proposed]**; check status, see R10). B1 lookups: whether a directory-read or email-lookup audit event is required is open (Q-N1). B4 is a read of own data: no audit event [INFERENCE, CONFIRM]. B7 denials keep the existing denial audit path.
- NF-O4: Seeding (C1) logs counts, not credentials or emails.

**i18n**
- NF-I1: Copy is centralised (D3) but no i18n framework is adopted.

## 7. Feature flags and rollout implications

- New flag `feature.nexus-us019-user-directory.enabled` (default `false`; true in `dev` and `test` yml; absent in prod). Covers B1, B2 and, if Q6 is answered that way, B4.
- B3, B5, B6, B8 sit under `feature.nexus-us015-rbac-role-management.enabled` (existing). Consequence: B5/B6 change existing DTOs; additive fields appear for everyone once us015 is on. They are non-breaking by design but contract tests need extending.
- B4 placement is unresolved (Q6): rbac controllers sit under us015; the story assigns B4 to us019.
- Rollout order constraint: the console (US-020) must not be released where B1/B3/B4 are off. US-020 F6 handles disabled backends in the UI; US-019 C3 is the written plan. Prod flag values are unknown from the repo (R9).
- `docs/deployment-process.md` assumes percentage rollout; the boolean flags cannot do it **[REPORTED]**. This story does not change that; it affects how safely B1 can be enabled gradually. Flag as an Ops question (Q-N8).
- Flags removal/cleanup is not addressed anywhere (Gap G10).

## 8. Dependencies and sequencing

- **Blocked by:** nothing (US-009 to US-018 are merged).
- **Blocks:** US-020 (P0 list: A1-A6, B1, B3-B5, C1, C2, D2, D4, D5).
- **Hard internal dependencies:**
  - B1 depends on Q1 and on D5 (privacy sign-off) and the Gate 2 threat model before merge.
  - B5 depends on Q2.
  - B6 depends on the `memberCount` disclosure decision.
  - B7 depends on the threat model; `THROTTLED` depends on throttle plumbing.
  - B8 depends on Q4/Q5 and the threat model.
  - A1 option (b) depends on A2 (the shell is the ancestor route). A7 and A8 are easier after A2.
  - C2 depends on C1; C4 depends on C2.
  - A9 and the shell nav depend on B4 if live role names are wanted.
  - A11 option (a) depends on B10.
  - D3 depends on D2 for placement; D3 depends on K9/D4 for the propagation text.
  - D6 last.
- **Shared with other work:** paging types (`PageParams`, `PageMetadata`, `PageLinks`) live in `rbac.interfaces.rest`; identity may not depend on rbac's interface layer if layering forbids it **[REPORTED]**, so B1 may force them into `common` (a refactor touching US-018 C2 code; scope impact, Q-N9).

## 9. Proposed split into deliverable slices

The story itself says it must split. The proposal below refines the discovery recommendation by separating human deliverables, since those have owners and lead times that code does not.

| Slice | Contents | Type | Depends on | Notes |
|---|---|---|---|---|
| **S0 — Human decisions (start now, in parallel)** | D2 (UX), D3 (content), D4 text, D5 (privacy/security), C3 (flag plan), Gate 1 answers Q1-Q12 | Human | Q1/Q2 answers feed S1 | Longest lead time; D5 blocks B1 |
| **S1 — Backend P0** (US-019a) | B1, B3, B4, B5 (+ B2 if cheap, same controller) | Backend | Q1, Q2, Q6, D5, threat model | Blocks US-020 C-group. High risk |
| **S2 — Frontend foundations** (US-019b) | A2 first, then A1, A4, A3, A5 (labels), A6 (verify) | Frontend | A1 needs A2; Q7, Q12 | Independent of S1; can run in parallel |
| **S3 — Backend P1** (US-019c) | B6, B7, B8, B10 | Backend | Q3, Q4, Q5, threat model | B6 is small and could move into S1 if US-020 A2 needs counts early |
| **S4 — Environments and tests** (US-019d) | C1, C2, C4 | Test infra / CI | C1 needs persona definitions; C2 needs C1; C4 needs C2 | P0 items C1, C2 gate US-020 kickoff |
| **S5 — Frontend P1/P2 and docs** | A7, A8, A9, A10, A11, D6, B9 doc fix | Frontend / docs | A2; A9 needs PM contact decision; A11 needs Q8 | D6 last |

Human deliverables that code cannot satisfy: **D2, D3, D5** (and the sign-off half of D4, C3, A9's contact value). They need named owners and approval records, not a PR.

## 10. Edge cases

- **Empty and boundary inputs:** `email=` empty string; `email=` with whitespace or Unicode normalisation variants (service normalises; confirm tests); `size=0`, `size=-1`, `size=101`, non-numeric; `page` beyond last; `ids=` empty, duplicated, 100 vs 101, malformed UUID; `permissionIds` empty (does it remove all permissions? story silent), duplicated, unknown, null; role with zero permissions.
- **Cross-tenant:** user id, role id, permission ids in B8 from another tenant (permissions are global, roles are tenant-scoped); batch with mixed tenants.
- **Concurrent updates:** two admins editing the same role (B8); an attach/detach racing a replace; revoking the last admin role concurrently with B8 removing permissions from an admin-defining role (could produce a tenant with no administrator, see R4); user assigned a role while B4 is being read.
- **Stale data:** B4 returns live truth while the UI nav uses JWT-derived `AuthStore` permissions, so the two can disagree for up to the token TTL (US-020 G6 handles it).
- **Soft-deleted / locked / pending users:** do they appear in B1? Are they excluded from `memberCount`? Story says only "active holders" for roles and the status filter for users; behaviour for deleted users is unspecified (Gap G7).
- **Cold start (A1):** delayed refresh; refresh fails (expired cookie); refresh returns 429 (interceptor retries; guard behaviour unspecified); two tabs; deep link with query string and fragment; `returnUrl` surviving the redirect through login, MFA if any [INFERENCE: not in source].
- **Partial failure:** B8 audit-write failure must roll back the change (ADR-0024 intent); cache evict or epoch bump fails after commit; seeding aborted half-way (C1 idempotency).
- **Network timeouts:** B4 slow at console open (US-020 depends on it for affordances): the UI behaviour belongs to US-020, but B4's own timeout budget is unstated.
- **Permission denials:** directory read by MEMBER (Q1); B4 called with a token whose roles were all revoked; B3 by a user without `role:read`; throttled caller (B7).
- **Feature flag off:** B1 returns 404, which the UI must distinguish from "user not found" (US-020 F6 relies on "the whole resource returns 404"; a single missing user also returns 404, so the UI cannot tell flag-off from not-found per id).
- **Seeding:** re-run after partial seed; seed under `break-glass` profile (excluded); user already exists with different state; second-tenant admin id collisions.

## 11. Assumptions

| # | Assumption | Flag |
|---|---|---|
| AS1 | Q1 will be resolved before B1 is designed; until then B1 is blocked, not defaulted | [CONFIRM] |
| AS2 | The catalogue stays at 8 permissions for this story; a new permission (Q1 option a) would add a row, a constant, a frontend mirror and a migration | [CONFIRM] |
| AS3 | Dev-only personas are sufficient for US-020 e2e; no staging seed is required | [CONFIRM] |
| AS4 | The product owner's 2026-10-05 approval covers scope but not the corrections in section 4 | [CONFIRM] |
| AS5 | Hand-written frontend types (A11 b) are acceptable even though the catalogue is already hand-mirrored | [CONFIRM] |
| AS6 | No migration is needed for B1 (index exists); B5 option (a) and B6 need none | [CONFIRM, REPORTED] |
| AS7 | Spring/Angular router behaviour in the story's A1 defect description is correct. The router-level test proves it before any fix is chosen | [CONFIRM] |
| AS8 | B4 requires no audit event | [CONFIRM, INFERENCE] |
| AS9 | The benchmark's vendor recommendations are defaults, not requirements, until D2/D3/D5 approve them | [CONFIRM] |
| AS10 | Compliance frameworks named in US-020 (SOC 2 CC6.2/6.3) and GDPR apply; no source names the legal basis for showing emails to admins | [CONFIRM with Legal] |

## 12. Risks

| ID | Severity | Risk | Mitigation (suggestion, not a design) |
|---|---|---|---|
| **R1** | **Critical** | **Every MEMBER holds `user:read` (V5), so gating B1 on it exposes all tenant emails to every user and makes `?email=` a tenant-wide existence oracle.** This is not a hypothetical: the grant is in the seed migration **[VERIFIED]** | Decide Q1 before design. If a new permission is chosen, existing tenants need it granted deliberately to admins. Threat model B1 first |
| **R2** | **High** | `isSensitive` has no defined meaning after the retirement of the "dangerous permission" concept. Wrongly flagged or unflagged permissions drive UI badges, grant-reason text and the danger dialog (US-020 A3, A4, B3, B6) | Q2 decision with a definition written in the DoD and a parity test; D3 copy approved |
| **R3** | **High** | B7 reason disclosure exposes authorization rule internals; and `THROTTLED` as a 403 reason is misleading because throttling currently maps to `NOT_TENANT_ADMIN` **[REPORTED]** | Allow-list only; opaque for cross-tenant/malformed; 429 for throttle; threat model before implementation |
| **R4** | **High** | B8 concurrency and locking: attach/detach take no set lock; a replace that adds and removes is a new race shape, and removing permissions from an admin-defining role could leave a tenant with no administrator or race with last-admin protection **[REPORTED / INFERENCE]**. Editor is read-modify-write, so lost updates are likely (US-020 G3 accepts last-write-wins) | Q4/Q5; Gate 2 threat model; concurrency ITs |
| **R5** | **High** | A1 option (a) could issue a second `POST /refresh` (`AuthService.refresh()` has no dedupe **[VERIFIED]**; `authGuard` calls it directly **[VERIFIED]**), tripping refresh-token reuse/theft detection and revoking the family **[REPORTED]**. Even option (b) leaves the `authGuard` refresh and the interceptor's proactive refresh as two callers (pre-existing, unquantified) | Prefer option (b); add a test asserting exactly one refresh request on cold start; check the interceptor/guard overlap |
| **R6** | **High** | Silent-skip e2e in CI: backend-dependent specs `skip` when the backend is unreachable **[VERIFIED]**, and the CI e2e job has no backend. US-020's e2e and axe scenarios could pass green with zero assertions executed; a "required check" (C4) would then be meaningless | C4 must make a skipped console spec a failure in CI (no silent skip), assert the number of executed tests, and prove the backend is reachable first |
| **R7** | **High** | B4 widens PII/authorization surface and is the UI's source of truth; a wrong `isAdministrator` misguides every affordance, and admin-equivalence is easy to re-implement incorrectly | Reuse the single predicate; IT with an admin-equivalent custom role |
| **R8** | **High** | The count/identity side-channel: `memberCount` under `role:read` (B6) tells a role reader how many people hold a role, and `=1` on an admin-defining role reveals a sole administrator | D5 sign-off; Q-N7 |
| **R9** | **Medium** | Prod flag values unknown; the console could ship where APIs are off, or an API be turned on before D5 | C3 plan with a named Ops owner; flag-off behaviour tested |
| **R10** | **Medium** | ADR-0024 (atomic audit) is described in the story as "proposed"; B8's audit design depends on it **[not checked]** | Confirm ADR status before design |
| **R11** | **Medium** | Scope: 31 items across FE, BE, CI and product; story is unestimated | Section 9 split; Gate 1 estimates per slice |
| **R12** | **Medium** | Human deliverables (D2, D3, D5) have no owner or date and block P0 work; code cannot unblock them | Assign owners at Gate 1; start S0 immediately |
| **R13** | **Medium** | Moving shared paging types to `common` (for B1) touches US-018 C2 code | Decide placement in `/design`; regression ITs |
| **R14** | **Medium** | Adding A2 shell changes where `/dashboard` lives; e2e specs use test ids and a root header exists in `app.html` | Keep test ids; update specs in the same change; Q12 |
| **R15** | **Medium** | Open-redirect via A10 `returnUrl` | Allow-list validation with adversarial tests (NF-S6) |
| **R16** | **Low** | Propagation text understates lag if config changed by US-018 A9 | D4 recheck, one constant |
| **R17** | **Low** | Dev personas and seed credentials accidentally active outside dev | Profile guard test (C1 scenario 15) |

## 13. Open questions for Gate 1

Format: options, **recommendation**, trade-off. Roles in brackets are the addressee.

**Q1 [PM, Security, Architect] — `user:read` held by MEMBER (blocking).**
- (a) New permission (e.g. `user:directory:read`) gates B1/B2; `user:read` unchanged. **Recommended.** Trade-off: one more catalogue row, constant, frontend mirror, migration and grants for admins; existing users keep current rights unchanged.
- (b) Keep `user:read`; accept that every member sees all emails; record in D5. Trade-off: no code cost, but a tenant-wide email exposure and an enumeration oracle, and probably a GDPR minimisation objection.
- (c) [INFERENCE, mine] Remove `user:read` from MEMBER. Trade-off: closes the hole, but changes existing behaviour for every tenant and anything relying on it; not in the story.
- Benchmark: Salesforce gates the Assigned Users page with a setup permission [S] (benchmark 6).

**Q2 [Architect, Security] — Meaning of `isSensitive` (B5).**
- (a) A static set in `Permissions`, kept in step by `PermissionsCatalogueIT`. **Recommended.** Trade-off: smallest; requires a human decision on which members, and must be updated by hand with the catalogue.
- (b) A DB column. Trade-off: migration and an admin-editable surface; overkill for 8 rows.
- (c) Derived: "a permission whose grant can create an administrator". Trade-off: self-maintaining but its definition is complex and today no code computes it per permission.
- Whichever is chosen, the badge definition US-020 A4 uses ("grants administrative control over users, roles or the tenant") must match it. Vendor precedent: Entra "PRIVILEGED" label [S, UI semantics U].

**Q3 [Security, PM] — Ship B7 `reason` now or defer?**
- (a) Ship the allow-list now with `THROTTLED` as a real 429 + `Retry-After`. **Recommended** (benchmark 8: OWASP error-handling [S], AWS denial messages [S]). Trade-off: needs throttle-port change and a threat model.
- (b) Defer; keep the generic 403. Trade-off: the console shows "you don't have permission" and relies on up-front disabling (US-020 B6/C3/C4).
- Note: the allow-list excludes last-admin and system-role rules in the story (they have their own codes `RBAC_002`/`RBAC_003`).

**Q4 [Architect, PM] — B8 concurrency: ETag/`If-Match` or last-write-wins?**
- (a) Strong ETag, `If-Match` required (428 missing, 412 stale), 409 reserved for business conflicts. **Recommended** (Google IAM etag, read-modify-write [S]; 428 [S]; 412 text [U]). Trade-off: adds a header contract on `GET /roles/{id}` (B3) and a client concern; US-020 G3 currently assumes last-write-wins and would change.
- (b) Last-write-wins (the story's G3). Trade-off: simplest; silent overwrites between two admins.

**Q5 [Architect, Security] — B8 lock: take the existing set lock when the role's before or after state is admin-defining?**
- (a) Yes, either state. **Recommended pending the threat model.** Trade-off: serialises admin-role edits; safest against zero-administrator races.
- (b) No lock, as attach/detach (RES-28 accepted). Trade-off: no contention; a new race shape remains.
- Cannot be decided without the Gate 2 threat model; this is an input, not an answer.

**Q6 [Architect] — B4 placement and flag.**
- (a) rbac controller, flag us019. (b) rbac controller, flag us015. (c) separate flag. **Recommendation: (a)**, because the story assigns B4 to us019 and the console needs B1/B4 together; but the controller must live in `rbac` because identity cannot be called from rbac, and rbac controllers sit under us015, so the flag split is unusual. Trade-off: two flags to set coherently (C3). Confirm.

**Q7 [Architect, Frontend lead] — A1 fix.**
- (b) `authGuard` on the shell parent, `permissionGuard` on children, contract spec rejects same-array. **Recommended.** Trade-off: couples A1 to A2; relies on documented per-level sequencing; no new async code.
- (a) `permissionGuard` awaits session-ready. Trade-off: guards stay composable, but needs a shared in-flight refresh and risks a second refresh (R5).

**Q8 [Architect] — A11 typed contract.**
- (b) Hand-written DTO interfaces plus contract test. **Recommended.** Trade-off: cheapest, can drift, test mitigates.
- (a) Generate from OpenAPI. Trade-off: no drift, but springdoc is disabled in prod and there is no export step or generator; requires B10 first.

**Q9 [Architect, Ops] — C4 CI.**
- (a) New CI job running Playwright against a compose backend (copy `performance-smoke.yml`), required for `e2e/access-management/`. **Recommended.** Trade-off: CI time and flakiness; but the only way to get real signal (R6).
- (b) Documented stub. Trade-off: cheap; UI and server can disagree, which is exactly what this story exists to prevent.
- Sub-question: is e2e a required status check today? Not visible from the repo; Ops must answer.

**Q10 [PM] — Split.** Approve section 9 (S0-S5), or the discovery's four-slice version (backend P0; frontend A1-A6; backend P1; environments/docs, with D2/D3/D5 tracked as human). **Recommendation:** section 9, because it separates human deliverables with owners and dates. Trade-off: more tracking overhead.

**Q11 [PM, UX, Security] — Owners and dates for D2, D3, D5.** Recommendation: name them at Gate 1; seed D3/D2 with the benchmark defaults (section 14). Trade-off: none, other than calendar time.

**Q12 [Architect, UX] — Shell vs the existing `app.html` header.**
- (a) Move the root header into the shell; public pages get a minimal header. (b) Keep it for public pages only; shell has its own. **Recommendation: (b)** if the theme toggle and wordmark must appear on login; trade-off: two headers to maintain vs. regressions on public pages. UX decision.

**Questions I add**

- **Q-N1 [Security, Architect] — Directory abuse controls.** Should `?email=` be rate-limited per caller and audited? Options: (a) throttle + audit event per lookup (event stores no email); (b) log only; (c) none. **Recommendation (a)** [U: benchmark 9 marks this design judgement]. Trade-off: new throttle and audit event type.
- **Q-N2 [QA, Architect] — Test-profile personas (K6).** Does US-020's `*IT` need seeded personas under `test`, or only Playwright against `dev`? Recommendation: dev only; ITs create their own data.
- **Q-N3 [Architect, Ops] — Propagation number.** Re-derive from current config after US-018 A9. Recommendation: one constant sourced from config values, text kept at "about 30 minutes" until verified.
- **Q-N4 [PM, UX] — WCAG level.** Sources say 2.1 AA; this request says 2.2 AA. Recommendation: target 2.2 AA (adds target-size and focus-not-obscured, which affect the sticky header and shell). Trade-off: a few extra criteria to design for. Axe may not cover the new 2.2 criteria; some need manual checks.
- **Q-N5 [PM] — A9.** Where does the contact target come from and what is its value? Also: show live role names (needs B4) or JWT role names (up to 15 min stale)?
- **Q-N6 [Architect] — `size` > 100.** Reject (400) or clamp? Recommendation: reject, so clients notice. Trade-off: stricter. Check `api-design` for the standing rule.
- **Q-N7 [Security, PM] — `memberCount` under `role:read`.** Allow, or gate behind `audit:read`? Recommendation: allow with the sole-administrator residual accepted in D5, because US-020 C5 needs the count to prevent lockout before submit.
- **Q-N8 [Ops] — Flag mechanism.** Boolean flags cannot do the percentage rollout `deployment-process.md` assumes. Do we need a staged rollout for B1?
- **Q-N9 [Architect] — Paging types location.** Move `PageParams/PageMetadata/PageLinks` to `common` for identity? This modifies US-018 C2 code; is that in scope?
- **Q-N10 [Legal, Security] — Legal basis** for showing emails to administrators, and retention for CSV export (D5). The source names neither.

## 13a. Gate 1 decisions (2026-10-19)

The story owner approved this document at Gate 1 with the recommendations in section 13 adopted as the answers, without change:

- Q1: a new permission (`user:directory:read`) gates the user directory (B1, B2). `user:read` is left as is. The MEMBER exposure (R1) is therefore closed by design, not accepted.
- Q2: `isSensitive` is a static set in `Permissions`, kept in step by `PermissionsCatalogueIT`.
- Q3: ship the B7 allow-list now; throttling becomes a real 429 with `Retry-After`.
- Q4: `ETag` and `If-Match` on the permission replace (428 missing, 412 stale, 409 only for business conflicts).
- Q5: take the set lock when the before or after state is administrator-defining, to be confirmed by the Gate 2 threat model.
- Q6: B4 is an `rbac` controller under the us019 flag.
- Q7: A1 uses option (b): `authGuard` on a shell parent route, `permissionGuard` on its children.
- Q8: A11 uses option (b): hand-written DTOs plus a contract test.
- Q9: a CI job runs Playwright against a compose backend, and skipped specs count as failures.
- Q10: the S0 to S5 split is approved; D2, D3 and D5 are human tracks.
- Q11, Q-N5, Q-N8, Q-N10: remain open human decisions. They need named owners and dates and do not block the technical slices.
- Q12: keep the `app.html` header for public pages; the shell gets its own header.
- Q-N1 to Q-N4, Q-N6, Q-N7, Q-N9: the recommendations in section 13 apply. Q-N9 (moving the paging types to `common`) is decided at design time.

## 14. Design benchmark defaults (for D2/D3/D5; not requirements)

Adopt unless Gate 1 objects. Tag shows evidence strength; **[U] items must be verified before going into an ADR**, and **all [S] items are search-summary evidence, not full page reads**.

1. **Editor layout:** native table grouped by resource, labelled checkbox per row, tri-state group checkbox, staged edits, diff before save. APG checkbox [S] https://w3.org/WAI/ARIA/apg/patterns/checkbox ; Auth0 staged picker [S]; GitHub custom roles [S]. "Vendors don't do pre-save diff" is **[U]**.
2. **Sensitive permissions:** badge (icon, text, tooltip); danger-variant review; no typed confirmation for grants. Unheld permissions shown disabled with visible reason, `aria-disabled`, focusable. Stripe grant ceiling [S, partial snippet]; AWS permission boundaries [S]; Entra PRIVILEGED label [S, semantics U]. Disabled vs hidden rationale is design judgement [U].
3. **Assigning roles:** both entry points, exact-email lookup on the role side, "what this adds" preview. Salesforce role-side and user-side [S]; Auth0 [U]; Okta [S]. Last-admin precedents: Entra PIM [S], GitHub/Atlassian only indirect [U].
4. **Destructive actions, tiered:** ordinary revoke gets a danger confirm with impact; delete role and self-revoke of admin need typed confirmation; block delete while members exist; no undo toast. AWS delete-role flow [S]; GitHub typed repo name via third-party tutorials only [U for first-party].
5. **Propagation text:** one constant, "within about 30 minutes, or as soon as they sign in again". Google ("about 2 minutes ... 7 minutes or longer", no ceiling) [S]; AWS eventual consistency [S]; Azure "up to 10 minutes" [S]. These figures need first-party verification before quoting.
6. **Access review MVP (US-020 E):** two read-only lookups, gated by `audit:read`. AWS Access Advisor [S]; Google Policy Analyzer [S]; Entra campaigns not fetched [U].
7. **Navigation:** left secondary nav, breadcrumbs, skeleton/empty/error states with retry and trace id; hide nav entries a user can never use, disabled-with-reason for blocked actions in-page. Hide-vs-disable for nav has no vendor source [U].
8. **Denial messaging:** allow-listed `reason` for in-tenant rule failures; cross-tenant/unknown/malformed opaque; 429 + `Retry-After`. OWASP Error Handling [S]; AWS denial messages [S]; 403-vs-404 OWASP guidance [U]; Google denial text [U].
9. **Directory privacy:** exact match via blind index, page <= 100, no emails in logs; CSV gated by `audit:read`, formula-injection escaping (`= + - @` tab CR, note OWASP says Excel may not preserve the prefix after re-save) [S]. GDPR Art. 5(1)(c)/(e) [U, not fetched].
10. **API:** `PUT /roles/{id}/permissions` full-set replace; ETag/`If-Match` (428/412); keep attach/detach. Google `setIamPolicy` + etag [S]; AWS PutRolePolicy semantics [U]; Okta per-permission calls, no ETag evidence [S].

**Caveat:** the benchmark could not fetch first-party pages (egress proxy 403 for AWS, Google, w3.org, OWASP). Do not quote any of the above in an ADR without opening the URL.

## 15. Gaps (missing from the source entirely)

- **G1:** No RPS, p95 latency or availability SLO for any new endpoint; no data-volume expectations beyond "up to 500 roles per tenant" (US-020).
- **G2:** No definition of "sensitive" (Q2) and no decision record for the `user:read` MEMBER grant (Q1).
- **G3:** No legal basis or retention rule for displayed emails and CSV export (Q-N10).
- **G4:** No throttle or audit policy for directory lookups (Q-N1).
- **G5:** No stakeholder named for D2, D3, D5 and C3, no dates.
- **G6:** No instruction on how the second tenant (C1) gets its roles, or how locked and pending users are produced.
- **G7:** Behaviour for deleted/soft-deleted users, ids that fail UUID parsing, and >100 ids is not stated (B1/B2).
- **G8:** No definition of how "an axe pass" works in unit tests for A3 (no axe in unit tests today **[REPORTED]**).
- **G9:** B8: empty `permissionIds` semantics, maximum length, handling of unknown ids, response body and status, and whether the request is idempotent are not stated.
- **G10:** Flag clean-up and retirement are not addressed.
- **G11:** No rollback plan for B1/B4 (disable flag is implied, not stated).
- **G12:** No acceptance criterion for observability on any item (metrics, logs, audit); all of section 6's observability items are derived by me.
- **G13:** No statement on whether tests that today assert RBAC_001 body shape (B7 additive `reason`) are contract-frozen.
- **G14:** WCAG level mismatch (2.1 vs 2.2) between sources and request.

## 16. Stakeholder map

| Stakeholder | Cares about | Needs from this story |
|---|---|---|
| Product Owner / PM | US-020 schedule, scope, split | Gate 1 decisions Q1, Q3, Q10, Q11, A9 contact; estimates per slice |
| UX / Design | Console visuals, a11y annotations, copy | D2, D3; benchmark defaults; shell/header decision (Q12) |
| Tenant administrators (end users of US-020) | See and change access safely, honest messages | B4 accuracy, B5 meaning, clear denial reasons |
| Security / Privacy | PII surface, enumeration, disclosure, escalation | D5, Gate 2 threat model for B1, B4, B7, B8; Q1, Q2, Q-N1 |
| Legal / DPO | Lawful basis, retention, minimisation | Q-N10, D5 |
| Architect | Layering, flags, concurrency, ADRs | Q4-Q9, Q-N9; ADR-0006 addendum |
| Backend engineers | Clear contracts, no re-implementation of the admin predicate | B-series DoD, reuse findings |
| Frontend engineers | Guard fix, shell, wrappers, typed contract | A-series DoD, Q7, Q8, Q12 |
| QA | Personas, fixtures, CI that does not silently skip | C1, C2, C4, R6 |
| Ops / Release | Flag values per environment, CI changes | C3, C4, Q-N8 |
| Accessibility specialist | WCAG 2.2 AA conformance | NF-X1 to X4, Q-N4 |
| Support | Understand "access denied" reasons, propagation lag | D3 text, B7 |
| Compliance / audit (SOC 2) | Evidence of access control and reviews | Audit events from B8; CSV policy |

## 17. Success metrics

Measured after rollout; targets are proposals to confirm because the source gives none (Gap G1).

- **Delivery:** all P0 items closed and US-020 kicked off without a new blocker found mid-sprint (count of US-020 tickets blocked by US-019 gaps = 0).
- **Correctness:** A1 cold-start misroute count = 0 in e2e on a real backend; exactly one `/refresh` request on cold start.
- **Safety:** zero cross-tenant disclosures in ITs and in prod logs; zero emails in logs (log scan); B1 `email=` miss and other-tenant hit responses indistinguishable (test).
- **Authorization accuracy:** B4 `isAdministrator` agrees with the server's own admin decision in 100% of IT cases, including an admin-equivalent custom role.
- **UX truthfulness:** share of console 403s that were predicted by the UI (US-020 B6/C3/C4) rising; rate of generic "no permission" messages falling once B7 ships.
- **Quality gates:** axe zero critical/serious on every new wrapper and shell element; console e2e suite executes (no silent skip) and is required in CI.
- **Operations:** B1/B3/B4 p95 within the target confirmed at Gate 1; error rate under agreed threshold; flags in all environments recorded in the C3 plan.
- **Governance:** D5 sign-off and ADR-0006 addendum recorded before B1 is enabled in prod.
