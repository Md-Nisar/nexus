---
description: Phase 9 — Generate technical and operational documentation.
argument-hint: <JIRA-ID>
---

Generate / update all documentation for feature `$1`.

Steps:

1. **Technical doc** — overview, design rationale, key decisions. Save to `docs/features/$1/09-technical.md`. Cross-link to the design doc.

2. **API documentation** — confirm OpenAPI annotations are in place on new controllers. Generate the spec:
   ```bash
   cd nexus-backend && ./mvnw spring-boot:run &
   # then fetch /v3/api-docs and save
   ```
   Save the resulting spec to `docs/features/$1/api-spec.json`.

3. **ADR** — if any non-trivial architectural decision was made, create an Architecture Decision Record. Save to `docs/adr/NNNN-<title>.md` using the standard template (Context / Decision / Consequences / Status).

4. **Deployment guide** — env vars added, config changes, migration order, feature flag default. Save to `docs/features/$1/deployment.md`.

5. **Rollback plan** — code rollback, data rollback (and what's irreversible), feature flag kill switch, cache invalidation. Save to `docs/features/$1/rollback.md`.

6. **Monitoring guide** — dashboards, key metrics with baselines, alert thresholds, log queries for new code paths. Save to `docs/features/$1/monitoring.md`.

7. **Runbook** — common operational scenarios (e.g., "feature appears slow", "users report X"), with diagnostic steps. Save to `docs/features/$1/runbook.md`.

8. **Update `CHANGELOG.md`** at repo root.

9. **Update `CLAUDE.md`** if any new convention emerged that future work should follow.

Print to chat: list of documents created or updated.
