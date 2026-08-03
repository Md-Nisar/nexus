# US-012 — Rollback Plan: Enable role assignment and revocation API

**Feature:** Role assignment / revocation API (`POST`/`GET`/`DELETE /api/v1/users/{userId}/roles[/{roleId}]`)

---

## 1. Primary lever: feature-flag kill switch (fastest, no redeploy)

Flip `feature.nexus-us012-rbac-role-assignment.enabled` to `false` in the affected environment's config and restart/redeploy the config change (not the code). `UserRoleController` is `@ConditionalOnProperty(havingValue = "true")`-gated: when the property is absent or `false`, Spring omits the controller bean entirely, and all three endpoints (`POST`/`GET`/`DELETE /api/v1/users/{userId}/roles...`) return `404`.

**Why this is the fastest lever:** it requires no code revert, no rebuild, and no data change — only a config value flip and an application restart (or, if the flag is sourced from an externalized config server, no restart at all). This is exactly why `03-design.md` §10.1 mandated the flag despite the story's own text saying "Feature flag required: No" — it is the platform's only control against a Critical self-escalation threat (T-E1), so having a config-only kill switch was treated as non-negotiable.

**What this does and does not undo:**
- Removes the three endpoints immediately — no new assignments/revocations can be made via this API.
- Does **not** touch any `user_roles` row already written while the feature was live (see §3).
- Does **not** require a Redis cache flush (see §4).
- Existing JWTs already minted with roles resolved before the flag flip remain valid until their normal expiry/refresh cycle — this is identical to how any other role change already behaves (`RoleResolutionService` re-reads roles live at every mint, independent of this flag).

## 2. Secondary lever: code rollback

If the flag alone is insufficient (e.g. the bug is in `RoleResolutionService`/`TenantAwarePermissionEvaluator` and needs a full revert of behavior, not just endpoint removal), revert the branch/commits for this story.

- **No Flyway migration to reverse.** `02-impact.md` §2.1 confirmed `V5__rbac_schema.sql` already existed before this story and is untouched by it — there is nothing to reverse-migrate. A code revert alone is schema-safe.
- **No destructive rollback needed.** Nothing in this story alters an existing table shape, drops a column, or renames anything. Reverting the code returns the application to its pre-US-012 behavior against an unchanged schema.
- Standard branch-revert process applies (see `CONTRIBUTING.md`); no special sequencing with any other service, since this story has zero cross-service dependents (Nexus is a modular monolith and this is additive-only, per `02-impact.md` §8/§12).

## 3. Data rollback: role assignments/revocations made while the feature was live

**Rolling back the code does not undo any `user_roles` row written while the feature was live, and this is intentional, not a gap.**

Every row created or revoked through this API while it was enabled represents **correct RBAC state at the time it was written** — a real administrative action (a Tenant Administrator granting or revoking a role), not corrupted or malformed data. There is no "undo" semantics implied by a code rollback for state that was valid when written:

- A row inserted by `POST` is a real, intentional grant. Reverting the *code* does not make that grant retroactively invalid — the person who has that role still legitimately received it.
- A row revoked by `DELETE` (`revoked_at` set) is a real, intentional revocation, and `user_roles` is append-only by design (`BEFORE DELETE` trigger + no `DELETE` grant for `nexus_app`) — there is no code path, rolled-back or not, that un-revokes a row.

**If a specific assignment/revocation needs to be manually undone** (e.g. an admin made a mistake, not a bug in this feature), that is an ordinary data-correction action through whatever this team's production-data-change process already is — not a rollback procedure specific to this feature. It is exactly the same class of action the `runbook.md` §2 recovery procedure describes for a zero-active-admins incident: a direct, approved DB write, not a rollback lever.

**Acceptable, by design.** `03-design.md` §12/`02-impact.md` §12 both already classify this feature as non-breaking and trivially reversible on exactly this basis: the schema doesn't change, and the data this feature writes is real state, not a side effect that could be "wrong" independent of the business decision that produced it.

## 4. Cache invalidation on rollback: no separate step needed

`RedisPermissionCacheAdapter.evict(tenantId, userId)` already runs **atomically with** every successful assign/revoke (post-commit, per D14's `afterCommit`/inline-fallback pattern in `RoleAssignmentService`) — it is not a separate maintenance step, and rolling back the feature does not leave anything for a rollback procedure to flush:

- If rolling back via the **feature flag**: no new assignments/revocations can occur post-flip, so no new stale-cache condition can be created going forward. Any cache entries evicted before the flip are already correctly evicted; nothing needs manual invalidation.
- If rolling back via **code revert**: same reasoning — this feature's own writes already evicted their own cache entries at write time. There is no accumulated cache state that only this feature's code can clean up.
- **Belt-and-suspenders, independent of this feature entirely:** `RoleResolutionService` re-reads the user's active roles live from the DB on every JWT mint/refresh and compares against the cached permission set — a US-012-introduced role change (or its absence, post-rollback) is reflected on the next token refresh even if Redis were completely unavailable. Cache eviction here is a latency optimization, not the correctness mechanism (`03b-threat-model.md` §0.1 verified this explicitly).

## 5. Summary — which lever to use

| Scenario | Lever |
|---|---|
| Suspected bug in this feature's own logic (AC4/AC5/AC8 enforcement, DTO shape, etc.), need it off **now** | Feature flag → `false` (§1) |
| Suspected bug in a shared dependency this feature exercises differently than before (e.g. `TenantAwarePermissionEvaluator`), needs a full behavioral revert | Code rollback (§2) |
| An individual assignment/revocation was made in error | Ordinary data-correction process, not a rollback (§3) |
| Any of the above | No migration to reverse; no cache-flush step; no cross-service coordination needed |
