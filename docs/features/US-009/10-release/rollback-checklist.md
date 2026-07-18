# US-009 — Rollback Checklist

_Phase 10 (`/release-prep`) deliverable. Builds on `rollback.md`; adds checklist structure, explicit owners, and the go/no-go for invoking rollback at all. Schema-only story — this is unusually low-risk to roll back **today**, and gets materially riskier once US-012 ships (see Trigger Conditions and the risk-profile note at the end)._

---

## Trigger Conditions (when to consider invoking this)

Since this story ships no traffic-facing behavior, there is no error-rate/latency/alert trigger in the usual sense. The actual triggers are:

- [ ] **Flyway migration `V5` failed to apply** or applied with unexpected side effects (e.g. checksum mismatch flagged on a subsequent deploy).
- [ ] **Backend fails to boot post-deploy** with a `SchemaManagementException` / `ddl-auto=validate` failure referencing `com.example.nexus.rbac.*` (per `runbook.md`'s first scenario).
- [ ] **The AC9 smoke check fails post-deploy** — `nexus_app` gets `Access denied` on any RBAC table, or the negative grant proof (`ERROR 1143` expected on non-`revoked_at` `UPDATE`) does not hold, or `SHOW GRANTS` shows anything beyond the intended 9-line shape.
- [ ] **A post-deploy discovery that the seeded `TENANT_ADMIN`/`MEMBER` rows are scoped to the wrong tenant** (e.g. `NEXUS_IDENTITY_DEFAULT_TENANT_ID` was misconfigured in the target environment) — this blocks Epic 3's kickoff gate and may warrant a fix-forward re-seed rather than a full rollback (see Decision Tree below).

**No numeric error-rate/latency threshold applies** — there is no runtime request path to measure (`monitoring.md`). Do not invent one for this story.

---

## Decision Tree (before invoking anything)

1. Is the failure a **grant/config problem** (AC9 failure, wrong tenant ID) rather than a **schema/code problem**? → Prefer **fix-forward** (re-run the grant provisioning, or correct the env var and restart) over a full rollback. This is faster and lower-risk than dropping tables.
2. Is the failure a **genuine schema/entity mismatch** (boot failure, `ddl-auto=validate` error) that fix-forward can't resolve in a reasonable window? → Proceed to **Code Rollback** + consider **DB Rollback**, below.

- [ ] **Decision to invoke rollback (vs. fix-forward) made and recorded** — **Owner: [ASSIGN: Backend Lead], escalate to [ASSIGN: Engineering Manager] if unclear within 30 minutes of detection**

---

## Code Rollback

- [ ] **Revert the backend deploy to the previous artifact** — the 5 entities, 4 repositories, and their tests introduce no dependents (`rollback.md`: "no other story's code references `com.example.nexus.rbac` yet"). A plain revert-and-redeploy to the prior commit SHA / Maven artifact version (recorded in `deployment-checklist.md`'s Pre-Deploy step) is safe. — **Owner: [ASSIGN: Backend Lead / DevOps]**
- [ ] **Confirm the reverted artifact boots cleanly** against the (still-present, unreverted) `V5` schema — this is safe because the code rollback alone doesn't require the schema to also roll back; the tables/entities are dormant (no runtime code reads/writes them yet). — **Owner: [ASSIGN: Backend Lead]**

---

## DB / Schema Rollback

**Flyway is append-only (ADR-0003) — there is no down-migration.** Decide whether schema rollback is actually necessary; in most failure modes (boot failure, grant misconfiguration) reverting the code artifact alone is sufficient and the schema can stay in place inertly.

- [ ] **If schema rollback IS deemed necessary:** author and apply a new forward migration (`V6__drop_rbac_schema.sql` or the next free slot) that `DROP TABLE`s all 4 tables in **reverse FK order** — `user_roles`, `role_permissions`, `roles`, `permissions` — and drops `trg_user_roles_no_delete`. — **Owner: [ASSIGN: Backend Lead] authors it; [ASSIGN: DevOps/DBA] applies it to the target environment**
- [ ] **Confirm no real consumer data exists before dropping** — as of this release, nothing writes to `user_roles` beyond the migration's own seed rows (no US-012 assignment code exists yet). Verify with `SELECT COUNT(*) FROM user_roles` — expect 0 (or only rows a manual smoke test itself inserted and can account for). **If this count is unexpectedly non-zero, STOP — do not drop; investigate what wrote to it before proceeding** (this would indicate US-012+ has shipped since this checklist was written, or an ad-hoc write occurred). — **Owner: [ASSIGN: Backend Lead]**
- [ ] **Reproduce seed data if a from-scratch re-apply is later needed** — dropping and re-running a corrected `V5` (or a fresh environment) reproduces the identical 7 permissions / 2 roles / 8 role-permission rows (same UUIDv7 literals) — not a data-loss concern in isolation today. — **Owner: [ASSIGN: Backend Lead]**
- [ ] **Irreversibility flag — read before executing, every time:** once **US-012 (assignment API)** ships and real role assignments accumulate in `user_roles`, dropping these tables becomes **irreversible data loss** of every user's role-assignment history. This scenario does not exist yet (US-012 isn't implemented as of this release), but re-confirm this fact at the time of any future rollback — do not assume today's "safe to drop" state still holds. — **Owner: [ASSIGN: Backend Lead] must explicitly re-verify before every future invocation of this DB rollback step**

---

## Feature Flag Kill Switch

- [ ] **N/A — none exists, by design.** No flag to flip. Confirmed no flag was introduced (schema-only, `03-design.md` §8.2). — **Owner: [ASSIGN: Backend Lead]** (confirm only)

---

## Cache Invalidation

- [ ] **N/A — no cache introduced.** No Redis or other cache touched by this story (`rollback.md`). Nothing to invalidate. — **Owner: [ASSIGN: Backend Lead]** (confirm only)

---

## Grant Rollback (if the grant shape itself is the problem)

- [ ] **If a mistake in the grant shape is discovered post-deploy:** correct the 5 `GRANT` lines in `02-grants-post-schema.sql` (and the other 2 artifacts, kept in sync) and re-apply — grants are idempotent (re-issuing an unchanged `GRANT` is a no-op). If a privilege must be genuinely **removed** (not just added), issue the corresponding `REVOKE` explicitly — `GRANT` statements don't expire on their own. — **Owner: [ASSIGN: DevOps/DBA]**
- [ ] **No operational urgency today** — no application code exercises these grants yet (no consumer until US-010/012/015), so a grant correction can be scheduled rather than treated as an emergency, unless the AC9 smoke check itself is what's blocking a deploy sign-off. — **Owner: [ASSIGN: DevOps/DBA]**

---

## Communication

- [ ] **Notify stakeholders that a rollback was invoked** — at minimum the Epic 3 team (their kickoff gate is directly affected) and whoever is mid-planning on US-010/012/015. — **Owner: [ASSIGN: Release Manager]**
- [ ] **State clearly in the notification whether the schema was dropped or only the code was reverted** — these have very different implications for anyone who might have started building against the schema. — **Owner: [ASSIGN: Release Manager]**

---

## Post-Mortem

- [ ] **Post-mortem scheduled within 2 business days of any rollback invocation.** — **Owner: [ASSIGN: Engineering Manager]**
- [ ] **Root cause documented** — was it a genuine schema/entity defect, a grant-provisioning miss (the story's own highest-risk area, per the threat model's T-E3), or a config/tenant-ID mismatch? — **Owner: [ASSIGN: Backend Lead]**
- [ ] **If the root cause was a missing/wrong grant:** confirm the AC9 smoke check was actually run against the failing environment before this deploy — if it wasn't, that process gap (not the grant mechanism itself) is the real finding. — **Owner: [ASSIGN: QA Engineer]**

---

## Risk Profile Summary (today vs. after US-012 ships)

| Component | Reversible today? | Reversible after US-012 ships? |
|---|---|---|
| Code (entities, repos, tests) | Yes — plain revert | Yes — plain revert (unchanged) |
| Schema (4 tables, trigger, generated column) | **Yes** — no real consumer has written data yet | **No** — becomes irreversible once real assignments accumulate; DROP = permanent loss of assignment history |
| Seed data (7 permissions, 2 roles, 8 grants) | Yes — fully reproducible via fresh `V5` | Yes — seed rows themselves remain reproducible; the *added* real assignment rows are what's lost |
| `nexus_app` grants | Yes — idempotent re-grant/revoke | Yes — unchanged |
| Feature flag | N/A — none exists | N/A |

**This checklist's DB-rollback step is currently low-risk and should stay that way only as long as US-012 has not shipped.** Re-verify the irreversibility flag above every time this checklist is actually invoked.
