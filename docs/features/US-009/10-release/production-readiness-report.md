# US-009 — Production Readiness Report

_Phase 10 (`/release-prep`) deliverable — final gate before release. Feature: EPIC-002 RBAC Foundation — US-009 (schema-only: Flyway `V5`, 5 JPA entities, 4 repositories, DB grants; zero runtime API)._

---

## Gate answers

| Question | Answer | Evidence |
|---|---|---|
| **Is the code reviewed and approved?** | **Yes.** | `docs/features/US-009/06-code-review.md` — verdict **APPROVE WITH NITS** (0 Blocker, 0 High, 1 Medium, 4 Low). |
| **Is the security review passed?** | **Yes.** | `docs/features/US-009/07-security-review.md` — verdict **APPROVED** (0 Blocker/Critical/High/Medium, 1 Low, 1 Info). The 1 Low (T-T2 wording overstatement) and 1 Info (write grants provisioned ahead of consuming code) are explicitly accepted, not blocking, per the security reviewer's own verdict text. |
| **Are tests green?** | **Yes.** | `docs/features/US-009/08-test-audit.md` — **606/607 passing** (579 backend unit + 27/27 RBAC integration tests against real Testcontainers MySQL 8.4). The 1 skip is a pre-existing, unrelated benchmark test case, explicitly noted as such. JaCoCo `check` goal (90% `*.domain` line-coverage gate) passes at 100% for `rbac.domain`. |
| **Is the migration safe (additive, no expand/contract, no data-loss risk today)?** | **Yes.** | `nexus-backend/src/main/resources/db/migration/V5__rbac_schema.sql` creates 4 net-new tables, one trigger, one CHECK constraint, and seed DML — zero existing tables/columns modified. Confirmed `V5` is the correct next Flyway slot (`V1`–`V4` present, no numbering collision — verified directly via `Glob` on `db/migration/*.sql` during this pass). `02-impact.md` §6: "All changes additive/expand-only... no expand/contract needed." No data-loss risk today: nothing writes to these tables beyond the migration's own seed rows (no consumer code exists until US-010/012/015). |
| **Is there a rollback path, and what's its actual risk profile?** | **Partial — reversible today, not once US-012 ships; the forward drop-migration itself has not been drafted or dry-run tested.** | `rollback.md`: code rollback (revert the 5 entities/4 repos) is safe and trivial today (no dependents exist). Schema rollback requires a **new forward migration** (Flyway is append-only, ADR-0003 — no down-migration mechanism exists anywhere in this codebase, not unique to US-009). `rollback.md` explicitly flags: "If US-012 (assignment) has since shipped and real role assignments exist in `user_roles`... dropping the tables at that point is **irreversible data loss**." As of this release, that scenario does not yet exist. **Gap found during this pass:** the actual `V6__drop_rbac_schema.sql` forward-drop script has not been written or dry-run against a Testcontainers/staging instance — it is described in `rollback.md` as a hypothetical, not an artifact that exists and has been exercised. See Open Items below. |
| **Are DB grants correctly provisioned and verified end-to-end?** | **Yes, with a per-environment re-verification requirement.** | All 3 provisioning artifacts (`nexus-database/mysql/init/02-grants-post-schema.sql`, `TestcontainersConfiguration.nexusAppGrantsCallback`, `docs/runbooks/nexus-app-provisioning.md`) independently re-read and confirmed byte-identical during this pass: 5 statements each, `user_roles` UPDATE column-scoped to `revoked_at` only (ADR-0014 D6, amended ADR-0015 D7). The AC9 smoke check was **executed once this session against real Docker MySQL 8.4** (not just Testcontainers) — `04-tasks.md` T-09-09, `08-test-audit.md` — and passed: `SHOW GRANTS` matched the 9-line shape, the column-scoped negative UPDATE denied with `ERROR 1143`, DELETE denied with `ERROR 1142`. **Caveat:** this verification is per-environment by nature (Testcontainers CI structurally cannot exercise `nexus_app`) — `smoke-test-checklist.md` must be re-run on every new environment's first deploy of `V5`, not assumed from this one session's pass. |
| **Are there any open items that must be resolved before or shortly after this ships?** | **Yes — one hard forward requirement, not blocking this story.** | **T-T2** (`06-code-review.md` Medium, `07-security-review.md` Low): the `chk_user_roles_revoked_not_before_assigned` CHECK constraint only rejects backdating `revoked_at` before `assigned_at` — it does **not** block a future-dated `revoked_at` (MySQL CHECK constraints can't reference `NOW()`). Both reviews independently confirm: **no exploitable path exists today** (no write path — US-012 hasn't shipped), so this is correctly non-blocking for US-009 itself. It **must** be carried forward as a hard requirement for **US-012**: the revoke use-case must add an application-layer `revoked_at <= now()` guard before any write ships, and the threat-model/ADR "RESOLVED" wording should be softened to "partially mitigated." **The 4 Low code-review nits** (concurrency test not asserting the specific exception type — already fixed per `08-test-audit.md`; stale `@IdClass` Javadoc; missing `serialVersionUID`; mutable `byte[]` getter) are correctly non-blocking follow-up polish, not release blockers — none has a security or correctness impact today. |
| **Are there any known issues outside this story's scope the deploy team should be aware of?** | **Yes — two, both pre-existing and explicitly not fixed here.** | (1) `com.example.nexus.identity.infrastructure.seed.DevDataInitializer` has 0% test coverage, which **fails a full unfiltered `mvnw verify`'s JaCoCo gate** — the deploy team should build/verify with the same profile this story's CI actually used, not a bare unfiltered `verify`, or they will see an unrelated red build and may wrongly attribute it to this change. (2) `docker-compose.yml`'s `mysql` service mounts the entire `mysql/init/` directory into `docker-entrypoint-initdb.d`, which fires **before** Flyway runs and crashes MySQL on a genuinely fresh volume when it hits `02-grants-post-schema.sql` referencing tables Flyway hasn't created yet. Worked around via a compose override for this story's own smoke testing; **not fixed in the shared `docker-compose.yml`**. Any team standing up a fresh environment from scratch needs the same override until this is fixed as its own item. Both are documented in `09-technical.md` and flagged for the team, not silently absorbed into this release. |

---

## Standard readiness gate (framework checklist)

| Item | Status | Note |
|---|---|---|
| SLOs defined? (availability, latency, error rate) | **N/A** | No runtime API surface exists in this story — nothing to attach an SLO to yet. First SLO-bearing surface arrives with US-011 (`03-design.md` §7). |
| Capacity validated? (load test vs. expected traffic) | **N/A** | No traffic-facing endpoint. Migration execution time is trivial (~17 seed rows), no CI time budget needed (`02-impact.md` §7). |
| Dependencies healthy? (downstream service SLAs) | **N/A** | Zero new dependencies added (`pom.xml` diff is a JaCoCo exclude only, per `07-security-review.md`). No downstream service calls introduced. |
| Backups in place? | **Yes, inherited** | Covered by the platform's existing MySQL backup policy — this story adds tables to the same schema/instance already backed up; no new backup mechanism needed for 4 additive tables. |
| Disaster recovery tested? | **Inherited, not independently tested for this story** | Same DR posture as the rest of the schema — no story-specific DR test performed (schema-only, additive). |
| Runbook written? | **Yes** | `docs/features/US-009/runbook.md` (3 operational scenarios: migration failure, boot/validate failure, grant `Access denied`) + `docs/runbooks/nexus-app-provisioning.md` (updated with the 5 RBAC grants). |
| Security review signed off? | **Yes** | `docs/features/US-009/07-security-review.md` — **APPROVED**. |
| Privacy review complete (if applicable)? | **N/A, explicitly verified clean** | No PII in any of the 4 new tables — verified independently by both the code reviewer and security reviewer (only UUIDs, names, descriptions, timestamps). |
| Accessibility review complete (frontend)? | **N/A** | Zero `nexus-frontend/` files touched. |
| i18n complete (if applicable)? | **N/A** | No user-facing strings; no frontend surface. |
| Feature flag plan defined? | **N/A, deliberately** | No flag — schema-only, no runtime behavior to gate (`03-design.md` §8.2). Confirmed no flag was added. |
| **Rollback tested at least once in staging?** | **No — not tested.** | See discussion below; this is the one item this report weighs most carefully rather than defaulting past. |

### On the untested rollback — explicit reasoning, not a default

Weighing this honestly rather than waving it through:

- The **code rollback** (revert 5 entities/4 repos) is trivial and low-risk by construction — no dependents exist yet, confirmed by both the design and rollback docs. This half is de facto "tested" by the fact that reverting to any prior commit in this repo is a routine, already-proven operation.
- The **DB rollback** (a hypothetical `V6__drop_rbac_schema.sql`) has genuinely **not** been drafted or dry-run against any environment. This is a real gap, not a nitpick.
- However: (a) this gap is **structural across the entire codebase**, not specific to US-009 — Flyway's append-only convention (ADR-0003) means **no migration in this repo (V1–V4 either) has ever had a tested down-migration**; treating this as a US-009-specific NOT-READY would apply a bar inconsistently against every prior release this platform has already shipped under the same convention. (b) The actual DB rollback, if ever needed today, is about as low-consequence as a schema rollback can be: 4 tables with **zero real consumer data** (only reproducible seed rows), a straightforward 4-statement `DROP TABLE` in reverse-FK order plus one trigger drop — not a complex reshaping migration. (c) `rollback.md` and this report both correctly flag that the risk profile changes materially once US-012 ships real assignments — which has not happened yet.
- **Conclusion: this is a genuine caveat, not a blocker.** Recommended pre-merge action (cheap, ~30 minutes): draft `V6__drop_rbac_schema.sql` now (even if never applied) and dry-run it once against a disposable Testcontainers/staging MySQL instance, purely to prove the DROP order and trigger-drop syntax work — this converts "never tested" into "tested once, held in reserve." This is a **recommended action**, not a condition that must block this release, given the near-zero consequence of the schema in its current, zero-consumer state.

---

## Verdict

## **READY WITH CAVEATS**

### Reasoning

Every hard gate this story actually has jurisdiction over is green: code review approved, security review approved, 606/607 tests passing (27/27 RBAC-specific against real MySQL), the migration is genuinely additive with no data-loss risk today, and the grant provisioning — the story's own highest-risk area per its threat model — has been independently verified byte-identical across all 3 artifacts and smoke-tested once against real Docker MySQL with both required negative proofs passing. This is unusually disciplined, well-documented work; nothing found during this release-prep pass changes that assessment.

It is **not** an unqualified READY because of the caveats below — none of which are severe enough on their own merits to justify NOT READY (no exploitable path, no data at risk, no runtime surface that could actually fail in production today), but all of which are real, named, owned things a deploy team must not lose track of.

### Caveats (carried forward, not blocking)

1. **T-T2 hard requirement for US-012:** the `chk_user_roles_revoked_not_before_assigned` CHECK constraint does not prevent future-dated revocation; US-012's revoke use-case **must** add an application-layer `revoked_at <= now()` guard before any revoke write ships, and the "RESOLVED" wording in `03b-threat-model.md`/ADR-0015 should be corrected to "partially mitigated."
2. **Two pre-existing, unrelated issues** the deploy team should not mistake for a US-009 regression: `DevDataInitializer`'s 0% coverage failing an unfiltered `mvnw verify`, and `docker-compose.yml`'s fresh-volume init-mount crash (worked around locally, not fixed in the shared file).
3. **The DB-rollback path (forward `DROP TABLE` migration) has not been drafted or dry-run** — recommended (not required) pre-merge action: author and dry-run `V6__drop_rbac_schema.sql` once against a disposable instance before this ships, to convert an untested hypothetical into a proven-once fallback.
4. **Grant verification is per-environment, not one-and-done** — the AC9 smoke check passed once this session against Docker MySQL, but `smoke-test-checklist.md` must be re-run on every new environment's first deploy of `V5` (staging, prod), since Testcontainers CI structurally cannot verify `nexus_app`'s real grants and each environment's provisioning is independently executed.

### Top 3 things the deploy team must not miss

1. **Re-run the full smoke-test checklist (grant shape, both negative proofs, exact `SHOW GRANTS` shape) against the actual target environment before signing off** — do not treat this session's one passing run as coverage for a different environment.
2. **`NEXUS_IDENTITY_DEFAULT_TENANT_ID` must already be set to `00000000-0000-7000-8000-000000000001` in the target environment before deploying** — `application.yml` has no fallback by deliberate design (ADR-0015 D8); an unset value means the app **fails to boot**, not a silent misconfiguration.
3. **The `V5` migration + the 5 entities/4 repositories must deploy together, in the same release** — `ddl-auto=validate` will fail boot if they land separately; this is not optional sequencing, it's a hard coupling.
