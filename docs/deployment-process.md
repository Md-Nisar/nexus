# Deployment Process — Nexus

## Environments

| Environment | Purpose | URL | DB | Notes |
|-------------|---------|-----|----|-------|
| `local` | Development | localhost:2000 / :1000 | localhost:3306 | Flyway migrations, root/root |
| `dev` | Shared integration | dev.nexus.internal | dev-db | Auto-deploy on merge to `main` |
| `staging` | Pre-prod mirror | staging.nexus.internal | staging-db | Production data shape; synthetic data |
| `production` | Live | nexus.example.com | prod-db | Guarded deploys |

---

## Branching Flow

```
feature/* ──PR──► main ──auto──► dev ──manual──► staging ──approval──► production
                        ↓
                    hotfix/* ──PR──► main ──►  (same pipeline, expedited)
```

- `main` always deploys to `dev` automatically on merge.
- Staging promotions are manual — run `./scripts/promote-to-staging.sh <tag>`.
- Production deployments require: staging green, 2-person approval, business hours.

---

## Build Artifacts

- **Backend:** Maven produces `nexus-backend-<version>.jar`. Artifact is immutable after build — same jar goes to dev, staging, prod.
- **Frontend:** `npm run build` produces `dist/nexus-frontend/`. Hash-based filenames.
- Both artifacts are tagged with the git commit SHA.
- Artifacts are signed (cosign or equivalent) before promotion to prod.

---

## CI/CD Pipeline

```
Push → Build → Unit Tests → Integration Tests → Coverage Gate → Security Scan
  → Docker Build → Push Artifact → Deploy Dev → Smoke Tests
  → (manual) Deploy Staging → Staging Smoke Tests → (approval) Deploy Prod
```

Each stage gates the next. A failure stops the pipeline.

---

## Schema Management

Nexus uses **Flyway** for all schema changes (ADR 0003). Hibernate runs `ddl-auto=validate` and will refuse to start if entities and schema disagree — so every change ships as a migration. Migrations live in `nexus-backend/src/main/resources/db/migration` as `V<N>__<description>.sql` and are **append-only** (never edit an applied migration).

**For additive changes** (new table, new nullable column, new index):
- Write a new `V<N>__add_*.sql` migration.
- It runs automatically on startup in every environment; verify in dev and staging before prod.
- Include the migration in `docs/features/<FEATURE-ID>/deployment.md`.

**For non-additive changes** (rename, drop, type change, NOT NULL on an existing column):
- Requires DBA review and the **expand/contract** pattern across two deploys:
  1. **Expand deploy:** migration adds the new column/table alongside the old (backward compatible).
  2. **Migrate data:** backfill migration (tested on prod-size dataset with timing).
  3. **Contract deploy:** later migration removes the old column/table once all code uses the new one.

---

## Feature Flags

All new features ship behind a flag. Flag naming: `feature.nexus-<FEATURE-ID>-<slug>.enabled`.

| Environment | Default | Notes |
|-------------|---------|-------|
| `local` | `true` | Developers work with features on |
| `dev` | `true` | Integration always sees the feature |
| `staging` | `true` | QA verifies against the real thing |
| `production` | `false` | Off until explicit rollout decision |

Flags are controlled via config — environment variables or a feature-flag service. They are not in compiled code.

### Rollout plan (typical)

```
Day 1: prod = 1% of users
Day 2: prod = 10%
Day 3: prod = 50%
Day 4: prod = 100% → schedule flag removal
```

Pause rollout if error rate or latency degrades beyond the alert thresholds.

---

## Deployment Checklist (abbreviated)

For the full artifact, see `docs/features/<FEATURE-ID>/10-release/deployment-checklist.md`.

Before deploy:
- [ ] All CI stages green on the staging branch
- [ ] Security review approved
- [ ] Smoke tests passing in staging
- [ ] DB migration tested on staging (with production data shape)
- [ ] Feature flag set to `false` in production config
- [ ] On-call notified; runbook linked
- [ ] Rollback plan documented and tested

During:
- [ ] Watch error rate dashboard throughout
- [ ] Keep rollback terminal open

After:
- [ ] Smoke tests on production
- [ ] Error rate back to baseline within 5 min
- [ ] Watch period: 24h minimum

---

## Rollback Policy

**Rollback is a normal operation, not a failure.** If error rate exceeds 1% or latency p95 exceeds 2× baseline for more than 5 minutes after deploy, rollback without hesitation.

**Code rollback:** redeploy the previous artifact (same jar, same frontend build).

**DB rollback:** Flyway migrations are forward-only. A code rollback is safe as long as schema changes were expand-only (additive) — the old artifact runs against the newer additive schema. Destructive changes are why the expand/contract pattern is mandatory; reversing them requires DBA involvement and is escalated.

**Feature flag kill switch:** Set `feature.nexus-<FEATURE-ID>.enabled=false` in all environments. This should take effect without a reboot for feature-toggled code paths.

Target: rollback completed in < 5 minutes.

---

## Hotfix Process

1. Branch from `main`: `hotfix/NEXUS-XXXX-description`.
2. Fix, test locally, get review (single approver acceptable for severity-1).
3. Merge to `main`. Auto-deploys to dev.
4. Manually promote to staging → verify smoke tests.
5. Deploy to prod with shortened approval (1 person + lead notification).
6. Open a follow-up ticket for a proper test if the hotfix skipped integration tests.

---

## Deployment Rules

- No deployments to production on Fridays (unless severity-1 hotfix).
- No deployments during business peak hours (08:00–10:00 and 17:00–19:00 local time) without sign-off.
- Two-person rule for production deployments: one deploys, one watches the dashboards.
- All production deployments create a Jira deployment record.
- Post-mortem required for any deployment that caused a production incident.

---

## Blameless Post-Mortems

When a deployment causes a production incident:
- Post-mortem within 48 hours.
- Focus on process and system improvement, not individual blame.
- Document: timeline, root cause, contributing factors, action items with owners and due dates.
- Share with the team.
