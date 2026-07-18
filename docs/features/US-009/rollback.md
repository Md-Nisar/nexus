# US-009 — Rollback Plan

_Phase 9 (`/docs`) deliverable._

## Code rollback

Reverting the code change (the 5 entities, 4 repositories, and their tests) is safe and has no dependents — no other story's code references `com.example.nexus.rbac` yet. A plain revert-and-redeploy is sufficient on the code side alone.

## Schema / data rollback

**Flyway is append-only (ADR-0003) — there is no down-migration.** `V5__rbac_schema.sql`, once applied, cannot be "un-applied" by Flyway itself. If the schema genuinely needs to be rolled back:

1. **If no data has been written beyond the migration's own seed rows** (the expected state for as long as US-009 is the newest RBAC story deployed — nothing else writes to these tables yet): the only path is a **new forward migration** (`V6__drop_rbac_schema.sql` or similar) that explicitly `DROP TABLE`s all 4 tables in reverse FK order (`user_roles`, `role_permissions`, `roles`, `permissions`) and drops `trg_user_roles_no_delete`. This is safe today because nothing depends on the seeded rows existing yet.
2. **If US-012 (assignment) has since shipped and real role assignments exist in `user_roles`**: dropping the tables at that point is **irreversible data loss** — every user's role assignment history disappears. This scenario doesn't exist yet (US-012 isn't implemented), but it's the reason a rollback becomes materially riskier the longer this schema has been live with real consumers. Flag this explicitly before ever executing a rollback once US-012+ have shipped.
3. **The bootstrap `TENANT_ADMIN`/`MEMBER` seed rows themselves** are not "real" user data — dropping and re-seeding them via a fresh `V5` re-run (on a from-scratch environment) reproduces the identical rows (same UUIDv7 literals), so the seed data itself is fully reproducible, not a loss concern in isolation.

## Feature flag kill switch

**None exists** (by design — see `deployment.md`). There is no flag to flip; the rollback path is exclusively code revert + a new forward migration, as above.

## Grant rollback

If the `nexus_app` grants need to be reverted (e.g., a mistake in the grant shape is discovered post-deploy): remove or correct the 5 `GRANT` lines in `02-grants-post-schema.sql` and re-apply (grants are idempotent — re-issuing a `GRANT` is a no-op if unchanged, and a `REVOKE` statement would need to be added to genuinely remove a previously-applied grant, since `GRANT` statements don't expire on their own). Since no application code currently exercises these grants (no consumer exists until US-010/012/015), there is no operational urgency to a grant rollback today.

## Cache invalidation

**Not applicable.** This story introduces no cache (Redis or otherwise) — the permission cache described in ADR-0013 D4/`03-design.md` §7 belongs to US-010, not this story.

## Summary: what's reversible vs. not, today

| Component | Reversible? |
|---|---|
| Code (entities, repositories, tests) | Yes — plain revert |
| Schema (4 tables, trigger, generated column) | Yes, today — no real consumer has written data yet; becomes irreversible once US-012 ships and real assignments accumulate |
| Seed data (7 permissions, 2 system roles, 8 grants) | Yes — fully reproducible via a fresh `V5` application |
| `nexus_app` grants | Yes — idempotent re-grant/revoke, no urgency since unused today |
| Feature flag | N/A — none exists |
