# US-018 — Requirement Analysis Document (Gate 1)

**Story:** Harden RBAC for production readiness (principal-architect review remediation)
**Epic:** EPIC-002 — RBAC Foundation
**Status:** Draft · **Owner:** Business Analyst · **Gate 1:** approved 2026-09-26 (see §14)
**Source documents:** `docs/story/2-rbac/US-018.md` (authoritative, 30 ACs in Groups A–D); `docs/story/2-rbac/EPIC-002.md` (§"US-018", "Recommended Sprint Order", "Open Decisions"); `docs/adr/0003, 0009, 0013–0018`; prior Gate 1 docs `docs/features/US-012` through `US-017/01-requirements.md`; verified against shipped code (`RoleAssignmentService.java`, `JwtRs256Service.java`, `JwtAuthenticationFilter.java`, `permission.guard.ts`, `api-error.interceptor.ts`, `V5__rbac_schema.sql`) on 2026-09-26 — citations below marked **[VERIFIED]** where independently re-checked in code, **[REPORTED]** where taken from the story/discovery notes without independent re-verification.
**Status of story as received:** DRAFT, "not yet through Gate 1" — the story itself states it is too large to deliver as one unit and instructs Gate 1 to split it (US-018.md Risks row 1).

No PII (real names/emails) appears in this document. Where the source material names an individual owner, this document refers to them as "the story's designated owner."

---

## 1. Context

A principal-architect review of EPIC-002's already-shipped RBAC module (US-009–US-017) rated it 6.5/10 for production readiness. The review found the authorization model, audit trail, operability and API completeness were not GA-ready, even though tenant isolation, schema design, and test discipline were strong. US-018 collects every finding from that review into one story (30 acceptance criteria across four severity groups: A — Critical/High/Epic-3-and-GA blockers; B — Medium; C — missing production features; D — documentation/maintainability) so it can be triaged and split at this Gate. The headline finding (G1) is that the epic never adopted a grant-subset ("you can only grant what you already hold") anti-escalation rule; instead, US-015–US-017 layered ad hoc "dangerous permission" predicates on top of a name-based (`TENANT_ADMIN`) check, leaving two open escalation residuals — **US-016 RES-1(b) / T-E27 (High)** and **US-017 RES-13** — with an owner review date of 2026-11-27. Group A closes those residuals, makes audit writes atomic, adds a supported bootstrap/break-glass path, enforces deny-by-default on every controller, and delivers near-immediate revocation; it is a hard blocker for Epic 3 kickoff. Groups B–C are GA/enterprise-onboarding blockers (per the story's own Dependencies section — see Gaps §8 for the scope-labeling inconsistency this creates). Group D is non-blocking documentation cleanup.

**Bounded context:** `rbac` (existing, `com.example.nexus.rbac`), with cross-cutting changes into `identity` (JWT/`JwtClaims` contract, `JwtRs256Service`, `JwtAuthenticationFilter`) and the Angular frontend (`permission.guard.ts`, `api-error.interceptor.ts`). No new bounded context.

**Non-goals (per the story's own Out of Scope):** platform-wide/super-admin roles; ABAC or hierarchical roles; the Epic 3 Tenant Admin UI; per-tenant role seeding on tenant creation (Epic 3); backfill of assignments made during the US-015→US-016 exposure window (tracked separately under US-016).

---

## 2. Split Proposal

> **Delivery model (decided 2026-09-26):** US-018 stays one story. The rows below are **milestones inside US-018**, not separate stories. Gate 2 designs all milestones up front (one design + threat model, organised per milestone, one approval). Gate 3 groups tasks by milestone; each milestone ends with its own `/review`, `/security-review`, `/test-validate`, `/pre-pr-check` and PR.

The story cannot be delivered, reviewed, or threat-modeled as one unit — it touches a 1,130-line service **[VERIFIED — `RoleAssignmentService.java`, 1,130 lines]**, the frozen JWT contract, a Flyway migration, and both backend and frontend. Below is a refinement of the story's own suggested split ("(1) A8, (2) A1–A5, (3) A6, (4) A7, (5) A9–A11, (6) B, (7) C, (8) D"), broken further where coupling/risk profiles diverge materially within a suggested group.

| # | Milestone | AC scope | Priority | Rough size | Depends on | Ships independently? | Rationale for the split point |
|---|---|---|---|---|---|---|---|
| 1 | Deny-by-default enforcement | A8 | P0 | S | None | Yes | Purely additive (ArchUnit rule + `@PublicEndpoint` + self-invocation check); zero coupling to the assign/attach rewrite. Closes EPIC-002 Open Decision #4 on its own. |
| 2 | Grant-subset anti-escalation core | A1, A2, A3, A4 | P0 | L | None (can start immediately) | Yes, but only as a set — see below | These four must ship together: A2/A3 depend on A1's new permission existing to be meaningfully separate from `user:write`; A4 must compose correctly with A2's ordering (see Gap §8.2). Splitting them further risks an interim state where the assign/attach path is inconsistently gated. |
| 3 | Retire superseded machinery | A5 (+ D3, per the story's own "do alongside A5" note) | P1 | M | **2** | Yes, once 2 is merged | Explicitly a follow-on to A1–A4 in the story's own text ("Follow-on to A1–A4, same ADR"). Kept as its **own** milestone, not folded into 2, because its risk profile is materially different (Critical, not High — see Risks §6) and its DoD requires a separate threat-model sign-off before any control is removed. Bundling it with 2 would force the P0 fix to wait on a Critical-risk removal review. |
| 4 | Audit write atomicity | A6 | P0 | M | **2** (sequencing, not a hard blocker) | Yes | Orthogonal concern (durability, not authorization) but touches the same methods (`assign`/`revoke`/`attachPermission`/`detachPermission`) that 2 rewrites. Sequence after 2 to avoid rebasing a transactional-boundary change against an authorization rewrite mid-flight. |
| 5 | First-admin bootstrap / break-glass | A7 | P0 | M | None | Yes | New, additive capability (CLI or token); does not modify `assign()`/`revoke()`'s existing logic. Can run in parallel with 2–4. |
| 6 | Token claim validation hardening | A11 | P1 | S | None | Yes | Small, low-risk, fixes a live defect (see §4 verified findings) with no external dependency (no Redis). Deliberately split out of the "A9–A11" grouping so a quick, low-risk fix isn't held up by A9's Redis/contract-version work. |
| 7 | Revocation epoch & cache fan-out | A9, A10 | P0 | L | Should follow **6** (both touch `JwtRs256Service`/`JwtClaims`; A11's validation should land on the pre-epoch contract first) | Yes | A10's own DoD note ("or rely on A9's epoch bump") means A10 is likely subsumed by A9's design — kept as one milestone so that decision is made once, not twice. Introduces Redis as a new dependency of the authorization decision itself (not just a performance cache) — highest-risk item after 3; see Risks §6. |
| 8 | Group B — hardening | B1–B8 | P1/P2 | L | B6 should be decided after **7** (its own note: "must stay consistent with A9"); B8 touches the same file as 2 — sequence after 2 | Yes, as a set; individual ACs are low-coupling to each other except B6/B8 above | Kept as one story per the story's own priority label (P1/P2), but flagged internally: B1 (breaking-change risk to clients/tests), B2 (schema), B3/B5/B7 (low risk, can go first within this story), B4 (ADR-only decision, no build — see Open Question 7), B6 (sequence after 7), B8 (sequence after 2). |
| 9 | Group C — missing features | C1, C2, C3, C5, C6 | P1/P2 | L | C3 benefits from **4** (atomic audit) and **2** (stable authorization model) being merged first, not strictly blocked | Yes | C4 deliberately **excluded** from this story — see row 10. |
| 10 | Time-limited assignments (conditional) | C4 | P2 | Unknown — schema-risk item | **9** would need to exist first if this is picked up at all | Only if Gate 1 decides "in scope" (recommended: out of scope — see Open Question 5) | V5's own migration warns this touches `active_key`/the `revoked_at` CHECK constraint — a real schema-risk item, not a routine CRUD addition. Given no source document names a driving business requirement, default is to **not** file this as a story at all pending PM confirmation. |
| 11 | Group D — docs/maintainability | D1, D2, D4, D5 | P2 | S | D4 should land last (documents A1–A4, A8, A9, B5 — needs all of them merged to be accurate) | Yes (D1/D2/D5 immediately; D4 sequenced last) | D3 already folded into milestone 3 above per the story's explicit instruction. D5 is traceability-only (no implementation) — consider tracking it as a checklist item on the epic rather than a full Gate 2/3 cycle. |

**Recommendation — which milestone goes through Gates 2–3 first:** **Milestone 2 (A1–A4, the grant-subset core)**, not A8.

Reasoning: A8 is genuinely low-risk and low-coupling, and it is *a* named Epic 3 entry criterion (EPIC-002 Open Decision #4) — but it is not the only one. Group A as a whole is also an Epic 3/GA blocker per the story's own header, and within Group A, A1–A4 close **US-016 RES-1(b) / T-E27**, which US-017's own implementation record explicitly states was "materially amplified" by US-017's shipped changes, and which carries a hard, dated review deadline (2026-11-27) that is very plausibly earlier than an "unscheduled" Epic 3 kickoff. A8, by contrast, protects a class of bug (an unguarded future controller) that does not exist yet — there are no protected Epic 3 controllers today. Prioritizing A8 first optimizes for the easiest Gate 2/3 cycle, not the highest-severity, most time-boxed open risk. Given the two are fully decoupled (row 1 vs row 2 above), there is no technical reason they cannot run as parallel streams if capacity allows; if only one slot exists, **[PM]**/**[Architect]** should confirm this recommendation against current staffing, since it reverses the story's own suggested first pick.

---

## 3. Verified Discovery Findings (re-checked in code, 2026-09-26)

| Finding | Verification |
|---|---|
| `RoleAssignmentService.java` is 1,130 lines | **[VERIFIED]** exact line count confirmed |
| `JwtRs256Service.verify()` checks `schema_version` is *present* but never checks it equals `JwtClaims.CURRENT_VERSION` | **[VERIFIED]** — `verify()` (lines 107–159) null-checks `schemaVersion` but has no equality comparison anywhere in the method. A11 is real. |
| A null/absent `tenant_id` reaching `JwtAuthenticationFilter` causes an NPE via `Map.of(...)` | **[VERIFIED]** — `JwtRs256Service.verify()` reads `tenant_id` with no null check (line 143) and returns it straight into `JwtClaims`; `JwtAuthenticationFilter.doFilterInternal()` then puts `claims.tenantId()` directly into `Map.of(...)` (lines 80–84), which throws `NullPointerException` on any `null` argument. Confirmed exploitable path, not just a theoretical one. |
| `permissionGuard` fails open when `data.permission` is missing | **[VERIFIED]** — `permission.guard.spec.ts` has four dedicated tests asserting "fails open (returns true)" for missing, non-string, null, and empty-string `data.permission`. This is *tested, intentional* behavior today, not an oversight — worth noting for whoever picks up C6/A8-adjacent frontend work, since "fixing" it would break an existing, deliberately-written contract test. |
| `api-error.interceptor.ts` does not redirect on 403 | **[VERIFIED]** — the interceptor only logs and normalizes the error into `AppError`; no navigation/redirect logic exists anywhere in the file. C6 is real and unstarted. |
| No composite FK tying `user_roles.tenant_id` to the role's tenant | **[VERIFIED]** — `V5__rbac_schema.sql` defines `fk_user_roles_user`, `fk_user_roles_role`, `fk_user_roles_assigner`, none of which constrain `(role_id, tenant_id)` jointly. B2 is real. |
| Feature flags `feature.nexus-us012-rbac-role-assignment.enabled` / `feature.nexus-us015-rbac-role-management.enabled` exist and default off | **[VERIFIED]** flags present in `application.yml`, `application-dev.yml`, `application-test.yml`; default values not individually re-confirmed per-environment in this pass — treat as **[REPORTED]** for the specific "both default `false`" claim and confirm before relying on it for the B1/breaking-change risk assessment (Risk §6, item 8). |
| `RoleResolutionService` re-reads role names live; `attach`/`detach` don't clear holders' cache entries; Redis permission cache TTL 900s | **[REPORTED]** — not independently re-traced in this pass; consistent with EPIC-002's US-015 Technical Notes on cache fan-out. Recommend the Architect re-confirm at Gate 2 design time, since A9/A10/B6 all depend on this being accurate. |
| `RoleManagementService`'s mint-side gate (`attachPermission`/`detachPermission`) is name-based | **[REPORTED]** — matches US-017's own implementation-status record of RES-13 verbatim; not independently re-read in this pass. |

---

## 4. Functional Requirements

Traced to AC IDs. **[SPEC]** = directly stated by the story. **[INFERENCE]** = not stated verbatim; derived from the story's Notes/Technical Notes/Test Scenarios and flagged for Gate 1 sign-off. Compound ACs (testing more than one independently-verifiable fact) are split into lettered sub-requirements.

### Milestone 1 — A8

| FR | Requirement | Tag |
|---|---|---|
| FR-A8.a | Every `@RestController` method must carry either `@RequiresPermission` or a new `@PublicEndpoint` annotation, enforced by an ArchUnit rule that fails the build otherwise | [SPEC] |
| FR-A8.b | Identity's currently-`permitAll` endpoints are explicitly annotated `@PublicEndpoint`, not left bare | [SPEC] |
| FR-A8.c | A same-class self-invocation check flags direct (non-proxied) calls to `@RequiresPermission`-annotated methods, since Spring AOP proxies do not intercept self-invocation | [SPEC] |

### Milestone 2 — A1–A4

| FR | Requirement | Tag |
|---|---|---|
| FR-A1.a | A new code-seeded permission (proposed name `user:role:assign`) is the sole gate on `POST`/`DELETE /api/v1/users/{userId}/roles` | [SPEC] |
| FR-A1.b | `user:write` no longer, by itself, confers role-assignment ability | [SPEC] |
| FR-A1.c | `TENANT_ADMIN` is granted the new permission via migration | [SPEC] |
| FR-A1.d | The new permission's naming (three colon-separated tokens: `user:role:assign`) deviates from EPIC-002's own stated `resource:action` (two-token) convention — flagged [INFERENCE] as needing explicit confirmation, not silently accepted, since it sets precedent for future permissions | [INFERENCE] |
| FR-A2.a | `assign()` denies with `403` + `RBAC_001` unless every permission on the target role is a subset of the caller's currently-held permissions | [SPEC] |
| FR-A2.b | The caller's held-permission set is computed from a live DB read of active role assignments, never the JWT's `permissions[]` claim | [SPEC] |
| FR-A3.a | `attachPermission()` denies with `403` unless the caller holds the specific permission being attached, via the same live-DB-read rule as FR-A2.b | [SPEC] |
| FR-A4.a | A non-admin caller (i.e., a caller who does not hold a fully admin-equivalent role) cannot assign any role to themselves; the attempt returns `403` | [SPEC] |
| FR-A4.b | Every denied self-assignment attempt writes a `ROLE_ASSIGNMENT_DENIED` audit row | [SPEC] |
| FR-A4.c | The exact check-ordering between FR-A2's grant-subset denial and FR-A4's self-assignment denial when both would independently fire (e.g., a non-admin self-assigning a role whose permissions they also don't hold) is not specified — which `DenialReason`/error path takes precedence is undefined | [INFERENCE — flagged as a Gap, §8.2] |

### Milestone 3 — A5

| FR | Requirement | Tag |
|---|---|---|
| FR-A5.a | A new ADR records which ANY/ALL predicates, canaries, and lock-set logic from US-016/US-017 become redundant once A1–A4 ship, and removes them | [SPEC] |
| FR-A5.b | The last-admin lockout guard (US-012 AC5) is explicitly preserved, not removed | [SPEC] |
| FR-A5.c | `RoleAssignmentService` shrinks "materially" in line count — no numeric target given | [SPEC — target unquantified, flagged as untestable as written; see Gaps §8] |
| FR-A5.d | No existing IT may be weakened without explicit threat-model sign-off; the story does not name who grants that sign-off or what "weakened" means for a test that becomes logically obsolete (vs. one that is deliberately deleted) | [INFERENCE — flagged as a Gap, §8.2] |

### Milestone 4 — A6

| FR | Requirement | Tag |
|---|---|---|
| FR-A6.a | `ROLE_ASSIGNED`, `ROLE_REVOKED`, `ROLE_CREATED`, `ROLE_PERMISSION_GRANTED`, `ROLE_PERMISSION_REVOKED` are written in the same transaction as the mutation they record (or via a transactional outbox — see Open Question 3) | [SPEC] |
| FR-A6.b | An audit-write failure rolls back the paired mutation — no `user_roles`/`roles`/`role_permissions` change may commit without its audit row | [SPEC] |
| FR-A6.c | Denial events keep their existing `REQUIRES_NEW` (survive-rollback) path, unchanged by FR-A6.a/b | [SPEC] |

### Milestone 5 — A7

| FR | Requirement | Tag |
|---|---|---|
| FR-A7.a | An audited, supported mechanism can create a tenant's first `TENANT_ADMIN` when the tenant has zero active admins | [SPEC] |
| FR-A7.b | The same or an equivalent mechanism can recover a tenant that has been reduced to zero admins | [SPEC] |
| FR-A7.c | Every invocation writes an audit event and fires an alert | [SPEC] |
| FR-A7.d | No manual production SQL is required for either case | [SPEC] |
| FR-A7.e | Whether the mechanism is a CLI or a bootstrap token is explicitly left open by the story ("e.g.") — see Open Question 4 | [OPEN] |

### Milestone 6 — A11

| FR | Requirement | Tag |
|---|---|---|
| FR-A11.a | `JwtRs256Service.verify()` rejects (401) tokens whose `schema_version` does not equal `JwtClaims.CURRENT_VERSION` | [SPEC] |
| FR-A11.b | `verify()` rejects (401) tokens missing `tenant_id`, rather than allowing a downstream NPE/500 | [SPEC] |

### Milestone 7 — A9, A10

| FR | Requirement | Tag |
|---|---|---|
| FR-A9.a | A permissions epoch (per-user or per-tenant — see Open Question 2), stored in Redis, is embedded in the access token | [SPEC] |
| FR-A9.b | `JwtAuthenticationFilter` checks the epoch on every request via one O(1) lookup | [SPEC] |
| FR-A9.c | `revoke`, `attachPermission`, and `detachPermission` all bump the relevant epoch | [SPEC] |
| FR-A9.d | A token carrying a stale epoch is rejected with 401; the client is expected to refresh | [SPEC] |
| FR-A9.e | Fail-open vs fail-closed behavior for a Redis outage is explicitly undefined by the story pending this Gate — see Open Question 1 | [OPEN] |
| FR-A10.a | `attachPermission`/`detachPermission` clear the permission cache for every active holder of the affected role, OR rely on FR-A9's epoch bump to achieve the same effect — the story leaves the mechanism choice open | [OPEN — see Open Question 1's dependency] |

### Milestone 8 — Group B

| FR | Requirement | Tag |
|---|---|---|
| FR-B1.a | Cross-tenant targets return 404 with the same body as a genuine not-found | [SPEC] |
| FR-B1.b | The WARN log and `CROSS_TENANT_TARGET` denial metric are retained despite the status-code change | [SPEC] |
| FR-B2.a | A new migration adds `UNIQUE (id, tenant_id)` on `roles` | [SPEC] |
| FR-B2.b | A new migration adds a composite FK `user_roles(role_id, tenant_id)` → `roles(id, tenant_id)` | [SPEC] |
| FR-B3.a | No metric emitted by the RBAC module carries a `tenantId` tag | [SPEC] |
| FR-B4.a | Gate 1 (this document) records a decision on object/ownership-level authorization scope — see Open Question 7 | [OPEN, resolved in §7] |
| FR-B5.a | A single backend constants type is the only source of permission strings referenced by `@RequiresPermission` | [SPEC] |
| FR-B5.b | A startup check or test fails if any `@RequiresPermission` value is absent from the `permissions` table | [SPEC] |
| FR-B5.c | The frontend gains a `Permission` union type consumed by `permissionGuard`/`*appHasPermission` | [SPEC] |
| FR-B6.a | A benchmark decides whether the Redis permission cache is kept (with measured benefit recorded) or removed | [SPEC — decision, not a fixed requirement] |
| FR-B7.a | A documented, tested mechanism grants every newly seeded permission to every tenant's `TENANT_ADMIN` | [SPEC] |
| FR-B8.a | The denial throttle only blocks privileged role changes, not benign ones | [SPEC] |
| FR-B8.b | The throttle uses a shared store (Redis) in multi-instance deployments, or production config asserts single-instance | [SPEC] |

### Milestone 9 — Group C (excl. C4)

| FR | Requirement | Tag |
|---|---|---|
| FR-C1.a | `PATCH /api/v1/roles/{roleId}` updates name/description for custom roles | [SPEC] |
| FR-C1.b | `DELETE /api/v1/roles/{roleId}` deletes custom roles | [SPEC] |
| FR-C1.c | Either operation on a system role returns 409 + `RBAC_003` | [SPEC] |
| FR-C1.d | Deleting a role with active holders returns 409 unless its assignments are revoked first; all steps audited | [SPEC] |
| FR-C2.a | `GET /roles`, `GET /permissions`, `GET /users/{userId}/roles` follow the existing `api-design` pagination standard | [SPEC] |
| FR-C3.a | "Who holds role X" and "who holds permission Y" endpoints exist, tenant-scoped, permission-guarded | [SPEC] |
| FR-C3.b | An "effective permissions for user U" endpoint exists, tenant-scoped, permission-guarded | [SPEC] |
| FR-C5.a | The conflict between EPIC-002's stated default role (`MEMBER`) and the shipped code (no default role) is resolved by an explicit decision — see Open Question 6 | [OPEN, resolved in §7] |
| FR-C6.a | A 403 with `RBAC_001` routes the user to `/access-denied` via `api-error.interceptor.ts`, without breaking components that already handle 403 themselves | [SPEC] |

### Milestone 11 — Group D

| FR | Requirement | Tag |
|---|---|---|
| FR-D1.a | US-016/US-017 implementation-status sections move out of `EPIC-002.md` into `docs/features/<ID>/`; the epic keeps a one-line status per story | [SPEC] |
| FR-D2.a | Stale statements corrected: "US-002 is the Epic 3 gate" → US-009; story-point totals reconciled; US-013's "reads from the JWT" statement removed; `MEMBER` default-role statement matches the C5 decision | [SPEC] |
| FR-D4.a | The developer guide documents A1–A4, A8, A9, and B5 | [SPEC] |
| FR-D5.a | US-016/US-017 staging soak, RC-21 staging execution, and RC-19 Ops sign-off remain tracked on their own merge checklists — this story neither closes nor absorbs them | [SPEC] |

---

## 5. Non-Functional Requirements

| Category | Requirement / finding |
|---|---|
| **Performance** | EPIC-002's existing budget: permission check adds < 5ms p95 to endpoint response time, JWT-only, at 200 RPS on a guarded endpoint. This story adds I/O to two paths that budget never accounted for: (1) A2/A3's live-DB-read grant-subset check on `assign`/`attach` (low-volume, admin-only path — no RPS target stated anywhere), and (2) A9's Redis epoch lookup on **every** authenticated request platform-wide, which directly threatens the existing <5ms budget. No updated target is stated in the source material for either. **[CONFIRM with Architect before Gate 2 of milestone 7.]** |
| **Scalability** | No tenant-size, role-count, or concurrent-session figures are given anywhere in the source material to size A9's Redis epoch traffic or evaluate per-user vs per-tenant epoch tradeoffs (see Open Question 2). |
| **Availability (SLO)** | No SLO is stated for the RBAC assign/attach/revoke API or the permission-check path anywhere in the story, the epic, or prior US-012/US-015/US-016/US-017 Gate 1 docs (recurring gap — also flagged in `docs/features/US-016/01-requirements.md`). A9 introduces Redis as a new dependency of the *authorization decision itself* (previously Redis was explicitly "a performance optimisation — the JWT is the authority," per EPIC-002 [ARC]); this is a philosophy change with no stated availability target to design the fail-mode against. See Open Question 1. |
| **Security** | Core to the whole story. Explicit rules stated: grant-subset checks must use a live DB read, never the JWT (A2/A3); self-assignment is denied by default for non-admins (A4); audit writes must be atomic with the mutation (A6); every controller method must be explicitly permission-gated or explicitly public (A8); token claims must be fully validated (A11). No fail-mode (timeout/error) is specified for the new A2/A3 live-DB-read path itself — an unhandled DB error there should presumably fail closed (deny), consistent with the rest of the story's posture, but this is not stated. |
| **Observability** | A7's break-glass usage "fires an alert" with no channel/severity/runbook specified. B3 requires removing `tenantId` from metric tags (cardinality), moving attribution to structured logs — this changes an existing dashboard/query pattern used by prior canaries (`nexus.rbac.dangerous_permission_granted`, `nexus.rbac.self_role_assignment`); no migration plan for existing alert queries is stated. |
| **Accessibility** | Not addressed anywhere in this story. C6's Access Denied redirect reuses the existing page (built to WCAG 2.1 AA under US-013) — no new UI surface is introduced by Group A–D as scoped, so no new accessibility work is implied, but this is an inference, not a stated requirement. |
| **i18n** | Not addressed anywhere in this story. No new user-facing strings are identified beyond existing 403/404/409 error copy. |
| **Audit / compliance** | C3's access-review endpoints are explicitly justified by "SOC 2 CC6.2/6.3 quarterly access reviews" — the only explicit compliance citation in the story. A6's atomicity requirement is framed against "Epic goal #3 (100% of events audited)" from EPIC-002. |

---

## 6. Business Rules & Constraints

- **Grant-subset rule (A2/A3):** a caller may only grant/attach a permission they themselves currently, actively hold — evaluated by live DB read, never JWT claims.
- **Self-assignment rule (A4):** a non-fully-admin-equivalent caller may never assign any role to themselves.
- **System-role immutability (pre-existing, US-015):** `TENANT_ADMIN`/`MEMBER` cannot be edited via API; C1's new PATCH/DELETE must respect this (409 + `RBAC_003`).
- **Append-only audit (pre-existing, ADR-0003/0009):** `auth_events` blocks UPDATE/DELETE at the trigger level; A6 must not weaken this.
- **Last-admin lockout (pre-existing, US-012 AC5):** must survive A5's cleanup unchanged.
- **Tenant isolation (pre-existing, all RBAC stories):** a permission or role in one tenant never satisfies a check in another; B1/B2 strengthen, not relax, this.
- **Deny-by-default (A8, new):** every controller endpoint must be explicitly classified as protected or public; no endpoint may exist unclassified.
- **Permission naming convention (pre-existing, EPIC-002 [BA]):** `resource:action`, lowercase, colon-separated, code-defined only — A1's proposed `user:role:assign` is a three-token departure from this; needs explicit confirmation (FR-A1.d).

---

## 7. Edge Cases

| # | Edge case | Notes |
|---|---|---|
| EC1 | **A2 evaluated for a caller who is themself `TENANT_ADMIN`.** `TENANT_ADMIN` currently holds all 7 seeded permissions, so today it trivially passes any grant-subset check. But B7 (new permissions must reach every tenant's `TENANT_ADMIN`) is itself an unresolved gap today — if a new permission is added without B7's mechanism in place, `TENANT_ADMIN` in an existing tenant could fail its *own* grant-subset check on a role carrying that new permission. **A2 and B7 interact directly**; sequencing B7 ahead of or alongside any future permission addition matters once A2 ships. |
| EC2 | **A4 (no self-assignment) vs A7 (bootstrap/break-glass).** A7's entire purpose is creating a tenant's first `TENANT_ADMIN` from zero admins — functionally a "self"-assignment by the operator/mechanism performing the bootstrap. A4's DoD does not name an exemption for A7's path. If A7 is implemented as a call into the same `assign()` method A4 gates, it will be denied by its own story's other AC. This must be resolved explicitly at Gate 2 design for milestones 2 and 5 (either A7 bypasses `assign()` entirely via a separate privileged path, or A4 gains an explicit bootstrap exemption). |
| EC3 | **A1 as a breaking change.** AC1 states only that `TENANT_ADMIN` is granted `user:role:assign` by migration. Any *custom* role created via US-015 that currently holds `user:write` specifically to gain role-assignment ability loses that ability silently on deploy, with no migration/backfill path specified. Whether this matters in practice depends on the `[REPORTED]` claim that both parent feature flags default `false` with no production consumers (see §3) — this should be **independently reconfirmed**, not assumed, before treating the breaking change as a non-issue. |
| EC4 | **A5 vs existing US-016/017 ITs.** `LastAdminLockoutIT`, `AdminEquivalentLockoutIT`, and `RoleAssignmentSecurityIT` were built and hardened (including a same-day Critical/High fix cycle under US-017's own security review) specifically to exercise the ANY/ALL predicate machinery A5 proposes retiring. The AC requires sign-off before "weakening" any of them but does not define who signs off, or how a test that becomes logically obsolete (its assertion no longer applies) is distinguished from one that is deliberately deleted to hide a regression. |
| EC5 | **Concurrent attach + self-assign race.** Two admins concurrently attach a dangerous permission to a role while a third user attempts to self-assign that same role in the timing window — not covered by any AC in Group A as worded; A3's grant-subset check and A4's self-assignment check both fire on different calls and neither is stated to consider the other's in-flight state. |
| EC6 | **Redis outage mid-request for A9.** Beyond the fail-open/fail-closed policy question (Open Question 1), no AC addresses partial failure — e.g., Redis reachable but slow (timeout) vs. Redis fully down — these likely warrant different handling (fail fast on timeout vs. a longer circuit-breaker window on full outage), and neither is specified. |
| EC7 | **Empty/no-permission target role in A2.** A role with zero attached permissions is a trivial subset of any caller's permission set and would always pass A2's check — presumably intended, but not explicitly confirmed. |
| EC8 | **B8 throttle ordering vs A2/A3.** Today the denial throttle runs *before* the privilege check (per the story's own Notes on `RoleAssignmentService.requireNotThrottled`). If A2/A3's grant-subset check also runs after the throttle, an attacker could use throttle-timing differences to probe which permissions a role carries without needing the grant-subset check to actually fire — not analyzed by either A2/A3 or B8 as worded. |
| EC9 | **Partial failure in A6 if an outbox is chosen.** Same-transaction insert has a clean all-or-nothing failure mode; a transactional outbox introduces a second failure mode (the outbox write succeeds, but the relay to `SecureEventService`/downstream consumers fails or lags) that is not addressed by any AC. Relevant only if Open Question 3 resolves toward an outbox. |
| EC10 | **In-flight tokens at A9's token-version bump.** A9 changes the frozen `JwtClaims` contract and bumps `JwtClaims.CURRENT_VERSION` (per the story's Technical Notes, following the US-010 AC7 precedent). No AC states what happens to already-issued, still-valid access tokens at the old version at the moment of deploy — hard cutover (every active session gets a 401 on next request) vs. a grace window is unaddressed. |

---

## 8. Gaps

### 8.1 Missing from the source material entirely
- No story-point estimate exists for US-018 or any of the groups (explicitly "unestimated — pending Gate 1" in the story header); this document's "rough size" column (§2) is a rough T-shirt sizing only, not a substitute for Gate 3 task breakdown.
- No availability SLO exists for the RBAC API anywhere in the epic or any prior RBAC Gate 1 doc — a recurring gap across US-012 through US-018.
- No tenant-size or session-concurrency figures exist to size A9's Redis epoch traffic (needed for Open Question 2).
- No documented customer/compliance driver exists for C4 (time-limited assignments) — nothing pulls toward "in scope."
- No alerting-channel/runbook detail exists for A7's "fires an alert" requirement (paging severity, on-call ownership).
- No error-code registry reference confirms `RBAC_003` (and any other new codes this story introduces) don't collide with an already-reserved range.
- No UX/copy guidance exists for A7's break-glass flow or C1's role-deletion confirmation — both are backend-only ACs as worded, but a production break-glass/delete flow typically needs *some* operator-facing surface (even API/CLI-only) with defined confirmation semantics.
- No target sprint/date exists for Groups B–D the way Group A has a 2026-11-27 hard date — priorities (P1/P2) are stated but not scheduled.
- No performance target exists for the new A2/A3 live-DB-read path or for the assign/attach endpoints specifically (only the pre-existing JWT-only <5ms p95 budget for read-path permission checks).
- No grace-period/dual-version-acceptance policy exists for the A9 token-contract version bump's production cutover (EC10).

### 8.2 Contradictions and ambiguities within the story requiring resolution before design
- **A2 vs A4 ordering** (also EC-adjacent): both can independently deny the same request (a non-admin self-assigning a role whose permissions they also lack); the story does not state which `DenialReason`/response takes precedence, or whether both audit rows are written.
- **A4 vs A7**: A4's blanket "no self-assignment for non-admins" rule has no stated exemption for A7's bootstrap path, which is definitionally a self/zero-admin assignment (EC2).
- **FR-A5.c** ("shrinks materially") is not a testable acceptance criterion as worded — no numeric or percentage target is given.
- **EPIC-002 [BA] vs [ARC] on default role at registration** — direct quote conflict:
  - [BA]: *"Principle of least privilege: default role on registration is no permissions (explicit assignment required)"*
  - [ARC]: *"System role: `MEMBER` — default role for new users; `user:read` permission only"*
  Current shipped code assigns no role at all, which literally matches neither statement precisely (no role ≠ "MEMBER auto-assigned"; no role is also not the same *implementation* as "a role with no permissions"). This is C5's stated decision to make — see Open Question 6.
- **Group A vs Groups A–C as "GA blockers"**: the story header states "P0 for Group A (Epic 3 / GA blockers); P1 for Groups B–D," implying only Group A blocks GA, but the story's own Dependencies section states "Blocks: … GA / enterprise onboarding (Groups A–C)" — i.e., Group C (priority P1/P2) is *also* a stated GA blocker despite its lower AC-level priority labels. This inconsistency should be resolved explicitly by PM before sprint planning, since it affects whether milestones 9–10 can trail behind GA readiness or must precede it.

---

## 9. Assumptions

All flagged `[CONFIRM]` require explicit stakeholder sign-off before Gate 2 design begins on the affected milestone.

- Both parent feature flags (`feature.nexus-us012-rbac-role-assignment.enabled`, `feature.nexus-us015-rbac-role-management.enabled`) currently default to `false` in every environment including production, with zero live production consumers today, materially reducing the blast radius of A1's breaking change (EC3) and B1's 403→404 change. **[CONFIRM with Tech Lead/Ops]** — verified in code that the flags exist and default `false` in the checked config files; not independently confirmed as "zero production traffic" against a live environment.
- "Live DB read" in A2/A3 is assumed to mean a read inside the same transaction as the write, using the tenant-wide pessimistic locking pattern already established in `RoleAssignmentService`. **[CONFIRM with Architect]** at Gate 2 design.
- A1's proposed permission name `user:role:assign` is assumed to be a placeholder, not final, given its departure from the two-token naming convention. **[CONFIRM with Architect / naming-convention owner]**.
- A9's Redis-backed epoch mechanism is assumed compatible with, and not preempted by, B6's "keep or remove the Redis permission cache" decision — i.e., Redis is assumed to remain infrastructure regardless of B6's outcome, since A9 needs it independently. **[CONFIRM with Architect]** — the story itself flags this dependency ("B6... must stay consistent with A9, which may reuse Redis anyway") without resolving it.
- The `RoleResolutionService`/cache-TTL/fan-out behavior described in the Discovery Findings is assumed accurate as reported, since it was not independently re-traced in this pass (§3). **[CONFIRM with Architect]** before Gate 2 design of milestones 4, 7, and 8 (B6).
- "Existing ITs" in A5's DoD is assumed to mean, at minimum, the suite named in the story's own Test Scenario 16 (`CrossTenantPermissionIT`, `LastAdminLockoutIT`, `AdminEquivalentLockoutIT`, and unnamed others via "…"). **[CONFIRM with QA/Security]** that this list is exhaustive before A5's threat-model sign-off.
- Groups B–D are assumed not to gate Epic 3 kickoff (only Group A does, per the story header), notwithstanding the Group A–C GA-blocker inconsistency noted in §8.2. **[CONFIRM with PM]**.

---

## 10. Risks

| # | Risk | Severity | Mitigation |
|---|---|---|---|
| R1 | A5 retires ANY/ALL predicates, canaries, and lock-set logic that may still protect a path A1–A4 don't cover (the story's own risk table names this) | **Critical** | Keep A5 as its own Gate 2/3 cycle (milestone 3), gated by a mandatory ADR and a dedicated threat-model re-pass before any control is removed; do not bundle with the A1–A4 P0 delivery. |
| R2 | US-016 RES-1(b)/T-E27 remains an open, High-severity escalation path, and per US-017's own record was "materially amplified" by US-017's shipped changes; every sprint milestone 2 (A1–A4) slips past the 2026-11-27 review date compounds this window | **High** | Prioritize milestone 2 ahead of A8 and all of Groups B–D (see §2 recommendation); do not let a lower-risk, faster-to-ship item (A8) displace it in sprint planning. |
| R3 | A9 introduces Redis as a dependency of the authorization decision itself (not just a performance cache) on every authenticated request platform-wide, with no stated fail-mode or availability SLO | **High** | Resolve fail-open/fail-closed explicitly at Gate 1 (Open Question 1) with Security sign-off; add a circuit breaker/timeout budget; benchmark before Gate 2 closes. |
| R4 | A1 may silently remove role-assignment capability from any existing custom role holding `user:write` for that purpose, with no backfill mechanism specified (EC3) | **High** (pending confirmation of zero-production-consumers assumption in §9) | Confirm the zero-consumer assumption before treating this as low-risk; if any production tenant holds a custom `user:write`-based role, define an explicit backfill/communication step before A1 ships. |
| R5 | EPIC-002's <5ms p95 permission-check budget was set for a JWT-only check; A2/A3's live-DB-read requirement and A9's per-request Redis epoch lookup both add I/O the budget never accounted for, and no updated target exists | **High** | Get an explicit, separately-stated performance NFR from the Architect for (a) the assign/attach path and (b) the epoch-check path, before Gate 2 design of milestones 2 and 7; benchmark both against it. |
| R6 | Milestones 2 (A1–A4), 4 (A6), and 8's B8 all modify the same ~1,130-line `RoleAssignmentService` file; parallel branches risk merge conflicts and regression of each other's changes | Medium–High | Sequence explicitly per §2's dependency column; do not run 2, 4, and B8 as fully independent parallel workstreams without a shared integration branch or tight rebase cadence. |
| R7 | C4 (time-limited assignments), if approved in scope, reopens the `active_key`/`revoked_at` CHECK constraint design that V5's own migration comment flagged as foreseeable risk, under GA time pressure | Medium | Recommend "out of scope for GA" (Open Question 5) absent a named business driver; if reversed, size it as its own full Gate 1–3 cycle, not a Group C sub-item. |
| R8 | B1 (403→404) requires updating `CrossTenantPermissionIT` and API docs in the same change; an incomplete rollout (some endpoints changed, others not) would leave an inconsistent existence-oracle surface, partially defeating the purpose of the change | Medium | Require an exhaustive endpoint audit as part of milestone 8's Gate 2 design, not a per-endpoint incremental rollout. |

---

## 11. Open Questions

Each is decidable now, at Gate 1, with a recommendation. Final sign-off rests with the named role(s).

**OQ1 — [Security, Architect] A9: Redis-outage behavior — fail-open, fail-closed, or time-boxed degrade?**
- (a) Fail-open: on Redis outage, skip the epoch check and fall back to today's JWT-only decision. Availability preserved; the revocation-latency guarantee A9 exists to deliver silently degrades to the pre-A9 15–30 min lag for the duration of the outage, with no alert unless one is separately built.
- (b) Fail-closed: on Redis outage, deny/401 every authenticated request. Preserves the revocation guarantee; converts any Redis blip into a full platform outage across every tenant.
- (c) Time-boxed degrade with alert: behave like (a) but only for a bounded grace window, paging on entry, requiring incident acknowledgment to extend.
- **Recommendation: (c).** Matches the story's own instruction to decide this explicitly at Gate 1, and is consistent with EPIC-002's existing philosophy that the JWT (not the cache/epoch layer) is the authority. Pure fail-closed (b) risks becoming the platform's largest new availability liability for a property the epic itself frames as "within seconds," not a hard compliance SLA. Security must not accept silent, un-alerted degradation, so plain fail-open (a) is not recommended without (c)'s alerting layer.

**OQ2 — [Architect] A9: per-user or per-tenant epoch?**
- Per-user: precise blast radius (only the affected user's tokens invalidate), more Redis keys/writes.
- Per-tenant: one key per tenant; any role change for any user forces every other active session in the tenant to re-auth, even unaffected users.
- **Recommendation: per-user.** A shared per-tenant epoch turns every ordinary role change into a tenant-wide forced-refresh event, which doesn't match the story's own framing ("a stale token gets 401" — describing the affected token's owner, not every session in the tenant). Revisit only if per-user proves operationally too expensive — no tenant-size/session data exists in the source material to evaluate that tradeoff quantitatively (Gap §8.1); Architect should confirm against real numbers.

**OQ3 — [Architect] A6: same-transaction insert vs. transactional outbox?**
- Same-transaction insert: simplest; matches the story's own Notes ("`auth_events` is in the same database, so this is cheap"); couples audit-write latency/locking to the RBAC write path.
- Transactional outbox: decouples delivery from the write transaction; adds a relay/poller and an eventual-consistency window; no current downstream consumer (message bus, SIEM) needs that decoupling.
- **Recommendation: same-transaction insert.** No stated requirement today needs outbox-style decoupling (SIEM export is explicitly out of scope elsewhere in the epic); an outbox is unjustified complexity for a single-database, single-consumer audit trail. Revisit if/when `auth_events` gains an off-box consumer.

**OQ4 — [Architect, Security] A7: admin CLI vs. one-time bootstrap token?**
- CLI: operator-invoked, audited via existing infra access controls (SSH/kubectl); requires a new operational tool; gated by infra access, not app-level trust.
- Bootstrap token: tenant-owner self-service via API/UI; no on-call engineering needed for routine recovery; introduces a new bearer-secret with generation/storage/rotation/expiry concerns, and a leaked token is a direct, unmitigated privilege-escalation primitive.
- **Recommendation: CLI (operator-gated).** Consistent with this story's overall philosophy elsewhere (A2/A3's live-DB-read rule, A4's no-self-assignment rule) of narrowing trust surfaces, not widening them; a bootstrap bearer token is a new escalation primitive that cuts against that pattern, for what is explicitly a rare, high-consequence recovery action, not a routine self-service one. Security should confirm.

**OQ5 — [PM, Security] C4: are time-limited role assignments in GA scope?**
- In scope: requires redesigning the `active_key`/CHECK-constraint mechanism V5 itself flagged as a foreseeable risk — a real schema change, its own Gate 1–3 cycle.
- Out of scope: matches the pattern of every other Group C/D "decide" item with no stated business driver.
- **Recommendation: out of scope for GA.** No source document names a customer, compliance, or committed-date driver for expiring assignments. Revisit if one surfaces (Gap §8.1).

**OQ6 — [PM, Architect] C5: does registration default new users to `MEMBER`, or continue assigning no role?**
- Source conflict (quoted in full, §8.2): EPIC-002 [BA] — *"default role on registration is no permissions (explicit assignment required)"*; EPIC-002 [ARC] — *"System role: `MEMBER` — default role for new users."*
- (a) Auto-assign `MEMBER` on registration: matches [ARC]'s stated intent and the seeded role's description.
- (b) Keep current no-role default; correct the epic's [ARC] section to match reality.
- **Recommendation: (b).** Least-privilege-by-default is the safer posture, and avoids silently granting `user:read` to every self-registered user with zero explicit administrative action. PM should confirm this doesn't break an onboarding UX expectation not documented anywhere in the source material (Gap §8.1) — e.g., whether a brand-new user needs any self-visibility permission before an admin grants further access.

**OQ7 — [Architect] B4: is object-level/resource-ownership authorization in scope for this story, or ADR-only (deferred)?**
- Build now: closes a real gap (any `user:write` holder can act on any user in the tenant today).
- ADR-only: record the accepted risk, defer the build; consistent with B4's own lowest (P2) priority and the epic's existing ABAC-out-of-scope boundary.
- **Recommendation: ADR-only for GA**, with the ADR explicitly naming the accepted risk (an admin-equivalent user can act on any tenant user) so it is not later mistaken for "solved."

**OQ8 — [PM, Security] B1: 404 (existence-oracle closure) or keep 403 for cross-tenant targets?**
- **Recommendation: 404**, as the story proposes. This is the standard mitigation for cross-tenant ID enumeration; the zero-production-consumer assumption (§9, pending confirmation) minimizes breaking-change risk; requires the exhaustive endpoint audit noted in Risk R8.

**OQ9 — [Tech Lead, PM] Feature-flag strategy: one flag per milestone, one umbrella Group-A flag, or flagless?**
- Per-child-story flags: maximum rollback granularity; more flags to retire later.
- One umbrella flag: simpler, but an incident forces all-or-nothing rollback across every Group A change including the last-admin lockout guard and audit atomicity.
- Flagless (matching the story's own note that A8/B3 "need none"): justified for changes that only *narrow* behavior already gated off in production by the existing US-012/US-015 flags (both currently `false`, no production consumers per the assumption in §9).
- **Recommendation: flagless for Group A** (milestones 1–7), since the parent US-012/US-015 flags already gate the entire surface in production and there is nothing to canary against yet; revisit per-story flags only once those parent flags are planned to flip to `true` — **[CONFIRM with Tech Lead]** that timeline, since it is not stated in any source document (Gap §8.1).

---

## 12. Stakeholder Map

| Stakeholder | Interest / need |
|---|---|
| Platform Security Owner (story persona) | Owns the whole remediation; signs off on A5's threat-model re-pass and A9's fail-mode decision (OQ1). |
| Tenant Administrators | Direct users of assign/attach/revoke; experience new 403s (A2–A4), new 404s (B1), new role-lifecycle endpoints (C1). |
| Business Users / self-registered users | Affected by C5's default-role decision (OQ6). |
| Development Teams | Consumers of `@RequiresPermission`/`@PublicEndpoint` (A8), the typed permission catalogue (B5), developer-guide updates (D4). |
| Security & Compliance | Audit atomicity (A6); SOC 2 CC6.2/6.3 access-review endpoints (C3); break-glass alerting (A7). |
| SRE / Ops | A7's operational ownership if CLI-based (OQ4); A9's new Redis dependency and on-call burden; B8's multi-instance throttle correctness. |
| Epic 3 (Tenant Management) team | Hard-blocked on milestones 1 (A8) and 2 (A1–A4) landing; consumes the role-management API surface Groups A–B harden. |
| Architect | Owns the ADRs for milestones 2, 3, and 7; the JWT contract version bump; the Redis fail-mode/epoch-granularity decisions (OQ1, OQ2). |
| PM | Arbitrates priority between the 2026-11-27 hard date and an unscheduled Epic 3 kickoff; owns the Group A–C GA-blocker scope inconsistency (§8.2); decides C4/C5/B4/B1 (OQ5–OQ8). |
| Legal / Compliance | SOC 2 CC6.2/6.3 driver behind C3; audit-immutability requirements underpinning A6. |

---

## 13. Success Metrics

- Zero privilege-escalation findings in a pre-GA penetration test scoped specifically at the RBAC module, re-verifying that A1–A4 actually close US-016 RES-1(b)/T-E27 and US-017 RES-13 (not just mitigate them).
- US-016 RES-1(b)/T-E27 and US-017 RES-13 marked **fully closed** — not "mitigated" — in the epic's own tracking, with no review-date carry-forward past 2026-11-27.
- 100% of `ROLE_ASSIGNED`/`ROLE_REVOKED`/`ROLE_CREATED`/`ROLE_PERMISSION_GRANTED`/`ROLE_PERMISSION_REVOKED` mutations have a corresponding audit row, confirmed by a production audit-reconciliation sweep after milestone 4 (A6) ships — not merely asserted by unit tests.
- A revoked permission/role stops working within a measured p95/p99 (not just "seconds, not 15–30 min") after milestone 7 (A9) ships, captured from a staging soak or production canary.
- Zero unguarded-controller findings, continuously enforced by the child-story-1 (A8) ArchUnit rule in CI — not a one-time audit.
- The EPIC-002 <5ms p95 permission-check budget is re-measured and confirmed (or explicitly revised) under representative load after A2/A3/A9 ship.
- Zero-admin tenant recovery (A7) demonstrated end-to-end in an operational drill, not just covered by an integration test.
- At least one Group C access-review query (C3) is exercised by Security/Compliance in an actual quarterly access review, evidencing the SOC 2 control operates in practice, not only that it was built.

---

## 14. Gate 1 Decisions (approved 2026-09-26)

| Item | Decision |
|---|---|
| Delivery model | One story; the §2 rows are milestones inside US-018, each ending in its own review, security review, test validation and PR |
| Gate 2 style | All milestones designed up front: one design and threat model, organised per milestone, one approval |
| GA blockers | **Group A only**. Groups B–D follow GA, sequenced by priority (resolves the §8.2 header vs Dependencies inconsistency) |
| OQ1 A9 Redis outage | Time-boxed fail-open with alert |
| OQ2 Epoch granularity | Per-user |
| OQ3 A6 audit atomicity | Same-transaction insert (no outbox) |
| OQ4 A7 bootstrap | Operator-run CLI |
| OQ5 C4 time-limited assignments | Out of scope for GA (milestone 10 not planned) |
| OQ6 C5 default role | No role at registration; correct EPIC-002 |
| OQ7 B4 object-level authz | ADR accepting the risk; not built |
| OQ8 B1 cross-tenant response | 404 |
| OQ9 Feature flags | No new flags for Group A (parent US-012/US-015 flags already gate the surface) |

Still to resolve in Gate 2 design: EC2 (A4 vs A7 bootstrap path), A2/A4 denial precedence, A1 backfill for existing `user:write` custom roles, updated performance budgets for A2/A3 and A9, and re-tracing the two `[REPORTED]` findings.
