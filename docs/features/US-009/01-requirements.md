# US-009 — Requirements Analysis: Establish RBAC Data Model and Seed System Roles and Permissions

_Output of `/analyze-story` (business-analyst) + `feature-discovery` skill. Feeds Gate 1._

**Status:** Draft · **Owner:** _(BA — pending PM/Architect review)_ · **Gate 1:** **Approved 2026-07-16 — see §17**

---

## 1. Problem Statement

The platform currently has no authorization model — EPIC-001 established *who* a user is (authentication), but every endpoint is implicitly open to any authenticated user. US-009 lays the foundational data model for *what a user is allowed to do*: a tenant-scoped Roles + Permissions schema, with the two system roles (`TENANT_ADMIN`, `MEMBER`) and the full closed permission set seeded via Flyway migration rather than created at runtime. This story is purely schema + seed data — no enforcement (US-011), no JWT population (US-010), no assignment API (US-012) is in scope here. It is the hard gate for Epic 3 (Tenant Management) kickoff: `TENANT_ADMIN` must exist in the database before Tenant Management can enforce any admin boundary.

**Bounded context:** `rbac` (`com.example.nexus.rbac`) — **new**, greenfield. Verified: no `com.example.nexus.rbac` package exists anywhere in `nexus-backend/src/main/java` or `nexus-backend/src/test/java` (glob search returned zero matches).

**Non-goals (per story's own Out of Scope section):**
- Runtime/dynamic permission creation — permissions are code-defined (i.e., migration-defined) only.
- Platform-wide / super-admin roles.
- UI for role management (Epic 3).
- Role creation and role-permission management APIs (deferred to US-015, non-gating).
- Anything JWT-, cache-, or enforcement-related (US-010, US-011) or assignment-API-related (US-012) — this story only needs the schema and seed rows to exist and be provably correct under Testcontainers.

---

## 2. Bounded Context

`com.example.nexus.rbac`, mirroring the existing `com.example.nexus.identity` hexagonal layout — verified by reading the full `identity` package listing:

```
identity/domain/                        → rbac/domain/          (Permission, Role, RolePermission, UserRole — if entities are built this story; see §11 OQ-6)
identity/application/port/out/          → rbac/application/port/out/
identity/infrastructure/persistence/    → rbac/infrastructure/persistence/
identity/interfaces/rest/dto/           → rbac/interfaces/rest/dto/  (not needed until US-012/US-015 — no endpoints in this story)
```

This layering is enforced automatically, not by convention: `HexagonalArchitectureTest.java` (`nexus-backend/src/test/java/com/example/nexus/architecture/HexagonalArchitectureTest.java`, lines 18-29) defines its ArchUnit rules against generic `..domain..` / `..application..` / `..infrastructure..` / `..interfaces..` package-suffix patterns scoped to `com.example.nexus` as a whole, with `allowEmptyShould(true)` explicitly so the rules "pass while no bounded context exists yet and activate automatically as soon as the first one is created" (comment, lines 15-16). No `rbac`-specific ArchUnit configuration is needed — the moment `com.example.nexus.rbac.domain.*` classes exist, they are already covered.

---

## 3. Non-Goals

Confirmed directly from the story's "Out of Scope" section and cross-checked against EPIC-002 for consistency — no contradictions found:
- Runtime permission creation (permissions are code-/migration-defined only, per ADR-0013 D1).
- Platform-wide / super-admin roles (EPIC-002 PM section: "out of scope for Epic 2 — belongs to an internal operations epic").
- Role-management UI (Epic 3).
- Role creation / role-permission management APIs (US-015, explicitly non-gating per EPIC-002 Open Decision #2).
- JWT population, permission enforcement, assignment API, audit event emission, Angular guards — all later stories (US-010 through US-014); US-009 delivers only the schema + seed data they depend on.

---

## 4. Reuse-First Survey (Greenfield Framing)

Unlike US-008 (a gap-closure story against extensive existing code), **there is no existing RBAC code to survey** — confirmed by the empty glob for `**/rbac/**`. The reuse-first discipline here therefore applies to **patterns and infrastructure from the `identity` context**, not to RBAC code itself.

### 4.1 What exists and can be reused directly (verified)

| Asset | Location | Reuse |
|---|---|---|
| `UuidGenerator` port | `identity/domain/UuidGenerator.java` | `@FunctionalInterface` with a single `UUID newId()` method — context-agnostic despite living under `identity.domain`. `rbac` application code can inject this port directly; no new abstraction needed. |
| `UuidV7Generator` adapter | `identity/infrastructure/crypto/UuidV7Generator.java` | `@Component` production implementation using `UuidCreator.getTimeOrderedEpoch()` (uuid-creator library, ADR-0005) — the story's Technical Notes explicitly call for reusing this "directly, no new pattern." Verified present and trivially reusable via constructor injection from any bounded context. |
| `UuidV7Converter` | `identity/infrastructure/persistence/UuidV7Converter.java` | `@Converter(autoApply = true)` — this is a **JPA-persistence-unit-global** auto-apply converter (16-byte big-endian `BINARY(16)` ↔ `UUID`), not scoped to the `identity` package. Any `UUID`-typed field on a future `rbac` `@Entity` gets this conversion automatically with zero additional annotation or configuration, regardless of which package the entity lives in. |
| Flyway append-only trigger precedent | `V2__identity_schema.sql` lines 92-110 (`trg_auth_events_no_update` / `trg_auth_events_no_delete`) | Exact `BEFORE DELETE ... BEGIN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = '...'; END;` shape the story's Technical Notes cite as the precedent for `user_roles`'s hard-delete block. Verified syntax includes the `BEGIN/END` wrapper with an inline comment explaining it's required because "single-statement form without BEGIN/END causes HY000 on MySQL 8.4 via JDBC." |
| Migration numbering / naming convention | `V1__baseline.sql`, `V2`–`V4` | Confirmed current head is `V4__auth_events_add_user_agent.sql`. `V5__rbac_schema.sql` is correctly the next available version. |
| Testcontainers MySQL 8.4 target | `TestcontainersConfiguration.java` line 63: `new MySQLContainer<>("mysql:8.4")` | Confirms the story/ADR-0013's premise — MySQL 8.4 is the actual CI target, which is *why* the original Postgres-style partial unique index spec was invalid and D2's generated-column technique is necessary. |
| `users` table PK/column shape | `V2__identity_schema.sql` lines 12-28 | `id BINARY(16) NOT NULL` PK, `tenant_id BINARY(16) NOT NULL` with no FK to any `tenants` table (none exists yet). `roles.tenant_id`/`user_roles.tenant_id` correctly follow the same "no FK, just a `NOT NULL BINARY(16)`" pattern already established for `users.tenant_id`. |
| ArchUnit hexagonal-layering enforcement | `HexagonalArchitectureTest.java` | Applies automatically to any new `rbac.*` classes with zero configuration change (see §2). |
| ADR-0013 (Accepted) | `docs/adr/0013-rbac-data-model-and-enforcement-contract.md` | D1 (permission naming), D2 (`active_key` generated-column technique), D3 (exception-handler precedence — not needed until US-011), D4 (cache-fan-out default — not needed until US-015) are **resolved decisions**, not open questions for this analysis. |

### 4.2 What must be created (genuinely new — no existing counterpart)

| Asset | Type | Reason |
|---|---|---|
| `com.example.nexus.rbac` package tree | Bounded context | Confirmed zero existing files. |
| `V5__rbac_schema.sql` | Flyway migration | Net-new; creates all 4 tables, indexes, seed rows, and the `user_roles` trigger. |
| `active_key` generated-STORED-column + `uq_user_role_active` unique index | Schema mechanism | Net-new MySQL-specific technique (ADR-0013 D2) — no prior generated column exists anywhere in the current schema. |
| `trg_user_roles_no_delete` | Trigger | New trigger instance following the `trg_auth_events_no_*` shape; `user_roles` needs **only** the DELETE-blocking trigger, not an UPDATE-blocking one (unlike `auth_events`), since `revoked_at` is an intentional, permitted UPDATE path for soft-delete — a **material divergence** from the copied precedent, not a literal copy (see §8, §13 Gap 2). |
| Seed data statements (7 permissions, 2 roles, ~8 role_permissions rows) | DML in the migration | Net-new; no seed-data precedent exists via Flyway in V1–V4. |
| Migration-time UUID literals for seeded rows | Schema/data | The Java `UuidGenerator`/`UuidV7Generator` port only runs inside the Spring application at runtime — Flyway SQL cannot invoke it. Seed rows need hardcoded literal `BINARY(16)` values (see §11 OQ-2). |
| `nexus_app` DB grants for the 4 new tables | Infra/ops (out-of-band, per ADR-0012 §2) | **Currently entirely unaddressed** in all three provisioning mechanisms — see §11 OQ-4 and Risk Register (Critical). |

### 4.3 What needs extension (not full rewrite)

None identified — there is no existing RBAC-adjacent code to extend; every asset in §4.2 is additive net-new work layered on the reusable patterns in §4.1.

---

## 5. Acceptance Criteria — Annotated

| # | Criterion | Status | Verification Note |
|---|---|---|---|
| AC1 | All 4 RBAC tables created via `V5__rbac_schema.sql` | **Ready, with one type-convention discrepancy to confirm** | `V5` is correctly the next migration slot. But the story's Explicit Column Lists use bare `TIMESTAMP`, while every existing table in `V2`–`V4` uses `DATETIME(6)` (microsecond precision) for all temporal columns. Real, literal type mismatch vs. established convention — see OQ-1. |
| AC2 | 7 system permissions seeded | **Ready to implement as-is** | Permission set/naming matches ADR-0013 D1 exactly. |
| AC3 | System roles seeded with correct permissions, verified by join query | **Blocked on one open question, otherwise ready** | `roles.tenant_id` is `NOT NULL` with no default; the only "default tenant" concept (`nexus.identity.default-tenant-id`) is a per-environment runtime property with no fallback, unreadable from a static Flyway migration. See OQ-3 — the most significant open question here. |
| AC4 | `user_roles` hard delete blocked via `BEFORE DELETE` trigger | **Ready, with a test-coverage gap** | Mechanism is proven and reusable. Multi-row `DELETE` behavior is not exercised by any stated test scenario (see OQ-5) — almost certainly safe (whole-statement abort on InnoDB) but unverified. |
| AC5 | Tenant isolation on `roles` | **Ready to implement as-is** | `UNIQUE (tenant_id, name)` is unambiguous. |
| AC6 | One active role assignment per `(user_id, role_id)` via `active_key` | **Ready to implement as-is** | ADR-0013 D2 fully resolves the mechanism. |
| AC7 | Migration clean-forward in CI | **Ready to implement as-is** | Directly exercises the existing Testcontainers MySQL 8.4 harness; no new test infrastructure required. |

**Net assessment:** 5 of 7 ACs are ready as-is. AC3 has one genuine, unresolved design question (seed-row `tenant_id` sourcing) that should be resolved before implementation, not discovered mid-migration-authoring. AC4 has a test-coverage gap, not a design gap.

---

## 6. Functional Requirements

- **FR1** — `V5__rbac_schema.sql` creates the 4 tables with the columns/types/constraints in the story's Explicit Column Lists, subject to the `TIMESTAMP` vs. `DATETIME(6)` resolution (OQ-1).
- **FR2** — Migration inserts exactly 7 `permissions` rows (`tenant:read`, `tenant:write`, `user:read`, `user:write`, `role:read`, `role:write`, `audit:read`), each with a non-null `description`.
- **FR3** — Migration inserts exactly 2 `roles` rows (`TENANT_ADMIN`, `MEMBER`), both `is_system_role = TRUE`, scoped to a `tenant_id` resolved per OQ-3.
- **FR4** — `role_permissions` rows associate `TENANT_ADMIN` with all 7 permissions and `MEMBER` with exactly `user:read`.
- **FR5** — `user_roles.active_key` is a `STORED` generated column: `NULL` when `revoked_at IS NOT NULL`, a deterministic non-null function of `(user_id, role_id)` otherwise; enforced unique via `uq_user_role_active`.
- **FR6** — A `BEFORE DELETE` trigger on `user_roles` raises `SQLSTATE '45000'` for any deletion attempt, single- or multi-row.
- **FR7** — `roles` enforces `UNIQUE (tenant_id, name)`.
- **FR8** — Re-inserting an active `user_roles` row for an already-active `(user_id, role_id)` fails uniqueness; re-inserting after revocation succeeds.
- **FR9** — V1→V5 applies cleanly against a fresh MySQL 8.4 instance; all tables/indexes/seed rows verifiable immediately after.

---

## 7. Non-Functional Requirements

**Performance:** No RPS/latency target applies — no runtime API surface. No migration execution-time budget is stated (likely a non-issue given seed-row volume).

**Scalability:** `role_permissions`'s composite PK `(role_id, permission_id)` covers role→permission lookups efficiently; there is no secondary index on `permission_id` alone (a hypothetical future "which roles grant permission X" reverse lookup would table-scan — not a defect for this story, flagged for whoever eventually needs it). `role_permissions.created_at` does not need an index — no query pattern in US-009/010/012/015 filters or sorts by it.

**Security:**
- Tenant isolation (AC5) enforced at the DB level, consistent with "server-side enforced, never trust the client."
- Append-only `user_roles` (AC4) mirrors the `auth_events` audit-trail rationale.
- **`nexus_app` least-privilege DB grants (ADR-0012):** verified across `nexus-database/mysql/init/02-grants-post-schema.sql`, the Testcontainers grants callback, and the prod runbook — all three hardcode grants to exactly `auth_events`, `users`, `refresh_tokens`, `auth_tokens`. **None of the four new RBAC tables appear in any grant statement anywhere in the repo.** Testcontainers ITs will not catch this gap, because the general application connection in `TestcontainersConfiguration` deliberately stays on the container's default `test` user, not `nexus_app`. This only surfaces in docker-compose `full` profile or a real deployment. See OQ-4 / Risk Register (Critical).

**Observability:** No new logging/metrics/audit surface — no runtime code executes in this story.

**i18n/Accessibility:** Not applicable.

---

## 8. Business Rules & Constraints

- Permissions are `resource:action`, lowercase, colon-separated, code-defined only — ADR-0013 D1, resolved.
- `is_system_role = TRUE` rows must never be created/edited/deleted through any future API (US-015 AC7) — this story only seeds them with the flag set correctly.
- `user_roles` is soft-delete only: `revoked_at` is the sole mutation path; the `BEFORE DELETE` trigger must **not** also block `UPDATE`, since `revoked_at` is set via UPDATE. This is a deliberate divergence from the `auth_events` precedent (which blocks both). Implied by AC4's wording but never stated as an explicit "don't copy the UPDATE-blocking trigger too" warning (see Gap 2).
- Referential integrity ordering in `V5`: `permissions`/`roles` before `role_permissions`. Straightforward FK-authoring constraint, not a genuine ambiguity.

---

## 9. Edge Cases

| Case | Expected behavior | Verified / Open |
|---|---|---|
| Duplicate role name, same tenant | Unique constraint violation | Verified |
| Same role name, different tenants | Both persist | Verified |
| Single-row `DELETE` on `user_roles` | `SQLSTATE '45000'` | Verified |
| Multi-row `DELETE` on `user_roles` | Not explicitly covered | **Open — OQ-5.** Almost certainly whole-statement abort (InnoDB row-trigger semantics), but untested. |
| Assign same `(user_id, role_id)` twice while active | Second insert violates `active_key` uniqueness | Verified, ADR-0013 D2 |
| Revoke then re-assign | Second active row inserts; original untouched | Verified |
| Concurrent assignment attempts | Exactly one succeeds | Called for in the story's Risk register as a mitigation, but **not** a numbered Test Scenario — risk of being silently dropped (see Risk Register). |
| `role_permissions` insert with non-existent FK | Blocked by FK constraint | Standard behavior, no gap. |

---

## 10. Dependencies & Assumptions

**Dependencies:** Blocked by US-001 (`V2` applied — verified compatible). Blocks US-010 through US-014 and the Epic 3 kickoff gate.

**Assumptions flagged for confirmation:**
- `[CONFIRM]` Bare `TIMESTAMP` in the column lists is a drafting inconsistency, not an intentional new convention (OQ-1).
- `[CONFIRM]` Seed-row UUID literals don't need to be format-valid UUIDv7 — any well-formed 16-byte value is acceptable (OQ-2).
- `[CONFIRM]` Seeded `TENANT_ADMIN`/`MEMBER` `tenant_id` is a fixed, well-known constant baked into the migration, identical across environments — nothing in the source material actually confirms this (OQ-3, highest-severity assumption here).
- `[CONFIRM]` JPA entities are in scope for this story per the Technical Notes, even though none of the 7 ACs mention entities/repositories/ports (OQ-6).
- `[CONFIRM]` `nexus_app` grants for the four new tables belong to *some* story's Definition of Done before anything beyond Testcontainers-only CI runs against `V5` (OQ-4).

---

## 11. Open Questions

_ADR-0013's D1–D4 are resolved, Accepted decisions, cited as settled inputs — not re-litigated here. `V5` migration numbering and the ADR-0013 renumbering are already correctly resolved in the story text and verified against the actual `docs/adr/` listing. The items below are new findings from direct code verification, not present in the story, epic, or ADR._

| # | Question | Stakeholder | Assumption if unanswered | Risk if assumption wrong |
|---|---|---|---|---|
| OQ-1 | Column lists specify bare `TIMESTAMP`; every existing table (`V2`–`V4`) uses `DATETIME(6)`. Follow the story's literal spec, or the project's established convention? | Architect | Drafting inconsistency — follow `DATETIME(6)` | If intentional, silently switching deviates from a reviewed spec without sign-off; if not, shipping `TIMESTAMP` introduces an inconsistent mix of temporal types with different UTC/range semantics |
| OQ-2 | Seed rows need literal `BINARY(16)` UUIDs (Flyway can't call the Java UUIDv7 port). Must these be format-valid UUIDv7, or any well-formed 16-byte literal? | Architect | Any valid UUID-shaped literal is acceptable | A future tool/test asserting UUIDv7 version-nibble correctness across *all* rows could fail unexpectedly on seed rows |
| OQ-3 | `roles.tenant_id` is `NOT NULL`; the only "default tenant" concept is a per-environment runtime property (`NEXUS_IDENTITY_DEFAULT_TENANT_ID`, no fallback in `application.yml`) unreadable from a static migration. What literal value does `V5` use, and how is it guaranteed to match each environment's actual configured default? Dev and Testcontainers happen to share the same literal today (`00000000-0000-7000-8000-000000000001`), but nothing enforces that prod matches. | PM, Architect | Migration hardcodes the same sentinel UUID already used by dev/Testcontainers, as a fixed platform-wide constant | If a real deployment configures a *different* default tenant ID, seeded roles are scoped to the wrong/nonexistent tenant — silently breaking Epic 3's admin gate with no migration-time error, only a confusing later failure |
| OQ-4 | `nexus_app`'s grants (all 3 provisioning artifacts: dev docker-compose init SQL, Testcontainers grants callback, prod runbook) list only `auth_events`, `users`, `refresh_tokens`, `auth_tokens` — none of the 4 new RBAC tables. Testcontainers CI cannot catch this (app queries run as a different, default `test` user there). Is granting `nexus_app` access to the new tables in this story's scope, or explicitly deferred to whichever story first performs a runtime read/write (US-010 at the latest)? | Architect, Ops/DBA | Out of US-009's DoD, but must be explicitly assigned to a specific downstream story now | If left unassigned, the first real deployment or `docker compose --profile full up` after `V5` ships hits `Access denied for user 'nexus_app'` the moment any RBAC query runs — undetectable by current tests |
| OQ-5 | AC4/Test Scenario 4 only test single-row `DELETE`. Should multi-row be added as an explicit scenario? | QA, Architect | Single-row coverage is sufficient (mechanism identical to a proven precedent) | If some non-obvious interaction exists, the gap surfaces as a production incident, not a caught regression |
| OQ-6 | Technical Notes call for JPA entities mirroring `identity`'s layout, but none of the 7 ACs' DoD reference entities/repos/ports. In scope for US-009, or deferred to the first consuming story (US-010 read / US-012 write)? | Architect, PM | Entities are out of scope for US-009's own AC/DoD — Technical Notes are forward-looking guidance, not a hidden AC | If wrong, US-009 ships "incomplete" relative to its own Technical Notes despite passing all stated ACs; if right but misread later, entities might not get built with the intended care |

---

## 12. Risk Register

| Risk | Severity | Likelihood | Mitigation |
|---|---|---|---|
| `nexus_app` has no grants on any of the 4 new RBAC tables in any provisioning mechanism, and Testcontainers CI cannot detect this | **Critical** | High (verified true today) | Resolve OQ-4; add grants to all 3 provisioning artifacts before any environment beyond Testcontainers-only CI is exercised against `V5` |
| Seeded system roles' `tenant_id` is a migration-time literal with no enforced link to each environment's actual configured default tenant | **High** | Medium | Resolve OQ-3 before writing `V5`; if the intent is a fixed constant, document it explicitly rather than leaving it an unreasoned literal |
| Column lists specify `TIMESTAMP` where the rest of the schema uses `DATETIME(6)` | **Medium** | Medium | Resolve OQ-1 at Gate 2; default to `DATETIME(6)` unless there's a stated reason otherwise |
| Multi-row `DELETE` behavior on `user_roles` unverified by any test | **Low** | Low | Resolve OQ-5; add a multi-row assertion as low-cost insurance |
| Story's own required concurrency test (two concurrent assignments, expect one success) isn't tracked as a numbered Test Scenario | **Medium** | Medium | Track explicitly at task-breakdown (Gate 3), not left as implicit Risk-register prose |
| JPA entity scope ambiguity (Technical Notes vs. ACs) | **Low** | Medium | Resolve OQ-6 before estimation — affects story-point accuracy, not correctness |

---

## 13. Gaps (missing from source material entirely)

1. No numeric migration-execution-time budget for `V5` in CI.
2. No explicit statement that `user_roles`'s trigger set must be deliberately asymmetric vs. the `auth_events` precedent (DELETE-only, not UPDATE+DELETE) — inferable from AC4 but never stated as a warning against over-copying the precedent literally.
3. No mention anywhere of `nexus_app` DB grants for the new tables, despite an established, well-documented pattern (ADR-0012) for exactly this situation.
4. No mechanism specified for how a static Flyway migration obtains an environment-specific "default tenant" value.
5. No stated policy on whether seed-row UUIDs need to be format-valid UUIDv7.
6. No numbered Test Scenario for the concurrency case the story's own Risk register asks for.
7. No numbered Test Scenario for multi-row `DELETE`.
8. No decision recorded on whether `roles.updated_at ON UPDATE CURRENT_TIMESTAMP` is forward-looking for a capability nothing in the currently-scoped epic ever exercises (no story ever issues an `UPDATE` against `roles.name`/`description`).
9. No mention of whether `roles`/`user_roles` need a `version` column for optimistic locking, unlike every other mutable table in the schema (`users`, `refresh_tokens`, `auth_tokens` all carry one).

---

## 14. Stakeholder Map

| Stakeholder | Interest |
|---|---|
| Epic 3 (Tenant Management) team | Hard blocking dependency — cannot start until `TENANT_ADMIN` exists and is correctly tenant-scoped (OQ-3 directly threatens this) |
| Architect | Owns OQ-1, OQ-2, OQ-3, OQ-6 — most open items here are architecture-level |
| PM | Owns OQ-3 jointly with Architect, and the story-point impact of OQ-6 |
| Ops / DBA | Owns OQ-4 — the same out-of-band grant pattern ADR-0012 already assigns to Ops, now for 4 more tables |
| Security | Interested in OQ-4 as a direct continuation of ADR-0012's least-privilege posture |
| QA | Owns OQ-5 and the un-numbered concurrency test |
| US-010/US-012/US-015 authors | Direct consumers — US-010 is the first runtime reader (natural deadline for OQ-4 if deferred), US-012 the first writer, US-015 the first mutator beyond seed data |

---

## 15. Success Metrics

No story-specific metrics are stated (internal-platform, schema-only story). Inherited from EPIC-002: `TENANT_ADMIN` exists and is correctly tenant-scoped (binary go/no-go for Epic 3 kickoff); 100% of 7 permissions + 2 system roles present and correctly joined immediately after migration (fully owned and verifiable by this story alone, via AC3/AC7).

---

## 16. Definition of Ready

- [x] Bounded context identified: `rbac` (new, greenfield)
- [x] Existing schema and code verified directly against source — `V1`–`V4`, `TestcontainersConfiguration.java`, `UuidGenerator`/`UuidV7Generator`/`UuidV7Converter`, `HexagonalArchitectureTest.java`, full `identity` package listing, `docker-compose.yml`, all 3 `nexus_app` grant artifacts, `docs/adr/` listing
- [x] Reuse-first survey complete — confirmed genuinely greenfield; patterns (not code) carry over from `identity`
- [x] Annotated AC table: 5 of 7 ACs ready-as-is, AC3 blocked on OQ-3, AC4 has a test-coverage gap (OQ-5)
- [x] ADR-0013 D1–D4 confirmed still valid against current code
- [x] **OQ-1 through OQ-6 resolved at Gate 1 (2026-07-16)** — see §17 below
- [x] Ownership of `nexus_app` grant provisioning (OQ-4) explicitly assigned to **this story** (AC9)

---

## 17. Gate 1 Decisions (resolved 2026-07-16)

| # | Decision |
|---|----------|
| OQ-1 | **Use `DATETIME(6)`, not `TIMESTAMP`.** The story's bare `TIMESTAMP` was a drafting inconsistency, not an intentional deviation. All four tables' temporal columns now specify `DATETIME(6)` with `DEFAULT CURRENT_TIMESTAMP(6)` (and `ON UPDATE CURRENT_TIMESTAMP(6)` for `roles.updated_at`), matching `V2`–`V4` exactly. |
| OQ-2 | **Seed literals must be format-valid UUIDv7.** The 9 seeded PKs (7 `permissions` + 2 `roles`) will be real, correctly-formed UUIDv7 values (not arbitrary 16-byte literals), hardcoded and documented in `V5`'s header comment. Cheap to do correctly; removes any future risk of a "all PKs are v7" assumption tripping on seed data. |
| OQ-3 | **Fix it upstream of the migration, not just in the migration.** `application.yml`'s `nexus.identity.default-tenant-id` gains a fallback default equal to the same literal the migration seeds against (`${NEXUS_IDENTITY_DEFAULT_TENANT_ID:00000000-0000-7000-8000-000000000001}`), making "migration literal" and "runtime default" the same value by construction rather than by coincidence. Recorded as **ADR-0014 D5** (new ADR — ADR-0013 is Accepted and append-only per repo convention). Understood as a bootstrap-only mechanism; Epic 3's per-tenant-creation seeding supersedes it for every tenant provisioned after that ships. |
| OQ-4 | **In scope for US-009, with per-table least-privilege grants.** `nexus_app` grants added to all 3 existing provisioning artifacts: `permissions` (SELECT only), `roles` (SELECT, INSERT), `role_permissions` (SELECT, INSERT, DELETE), `user_roles` (SELECT, INSERT, UPDATE — deliberately no DELETE, matching the trigger as defense-in-depth). Recorded as **ADR-0014 D6**. New AC9 makes this an explicit Definition-of-Done item with a mandatory docker-compose `full`-profile smoke check, since Testcontainers CI structurally cannot detect a missing grant. |
| OQ-5 | **Add it as a test, no design question.** New Test Scenario 9: multi-row `DELETE` on `user_roles` — whole statement aborts, zero rows deleted, `SQLSTATE '45000'`. |
| OQ-6 | **In scope for US-009.** JPA entities + Spring Data repositories for all 4 tables ship with this story (new AC8) — building them alongside the migration that defines their schema keeps the mapping (especially the generated, read-only `active_key` column) correct and tested together. No application services/use-cases yet — those belong to US-010/US-012/US-015, the actual consumers. |

**Net effect on story sizing:** AC8 (entities/repos) and AC9 (grants) are genuinely new scope, not just clarifications — US-009 is revised from **5 to 8 points**; EPIC-002's total moves from 33 to **36**. Two new Test Scenarios (9, 10) and one new Risk (grants verified only outside Testcontainers CI) are added. Full detail in `docs/story/2-rbac/US-009.md` and `docs/story/2-rbac/EPIC-002.md` (both updated), and `docs/adr/0014-rbac-bootstrap-tenant-and-db-grants.md` (new, Accepted).

These decisions are binding inputs to impact analysis (Phase 2) and design (Gate 2); Gate 2 design may still surface refinements but should not need to revisit the *scope* questions above.

---

### Cross-references
- `docs/story/2-rbac/US-009.md` — source story
- `docs/story/2-rbac/EPIC-002.md` — parent epic
- `docs/adr/0013-rbac-data-model-and-enforcement-contract.md` — D1–D4, resolved
- `docs/adr/0014-rbac-bootstrap-tenant-and-db-grants.md` — D5 (tenant sourcing), D6 (grants), resolved at Gate 1
- `docs/adr/0012-least-privilege-runtime-db-user-for-auth-events.md` — basis for OQ-4/Risk Register's Critical finding
- `docs/runbooks/nexus-app-provisioning.md`
- `nexus-backend/src/main/resources/db/migration/V1__baseline.sql` through `V4__auth_events_add_user_agent.sql`
- `nexus-backend/src/test/java/com/example/nexus/TestcontainersConfiguration.java`
- `nexus-backend/src/test/java/com/example/nexus/architecture/HexagonalArchitectureTest.java`
- `docker-compose.yml`, `nexus-database/mysql/init/02-grants-post-schema.sql`
