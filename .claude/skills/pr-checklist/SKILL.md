---
name: pr-checklist
description: Use before opening or merging a pull request on Nexus, or whenever asked to run pre-PR / pre-merge checks. The executable runbook of local quality gates (the same gates CI enforces) plus the Definition of Done. Invoked by /pre-pr-check.
---

# Pre-PR Checklist (executable gate runbook)

Run the gates for whichever side changed. These mirror CI — passing here means CI should pass. The policy behind them lives in `CONTRIBUTING.md` (process) and `TESTING.md`/`SECURITY.md` (standards); this skill is the *how to run*.

## Determine scope
```bash
git diff --name-only origin/main...HEAD
```
Backend changed → `nexus-backend/src/**`. Frontend changed → `nexus-frontend/src/**`.

## Backend gates
```bash
cd nexus-backend
./mvnw -q verify -DskipITs     # Checkstyle + unit/slice + ArchUnit + per-layer JaCoCo + SpotBugs
./mvnw -q verify               # add this when Docker is up (runs *IT Testcontainers tests)
./mvnw -q -Pquality verify     # optional: PMD
```
Pass criteria: BUILD SUCCESS; no Checkstyle/SpotBugs/ArchUnit violations; JaCoCo gate met.

## Frontend gates
```bash
cd nexus-frontend
npm run format:check
npm run lint
npm run test:ci                # Vitest + coverage
npm run build                  # production build (validates strict templates + budgets)
npm run e2e                    # if UI behavior changed (first run: npx playwright install chromium)
```

## Definition of Done (must all be true)
- [ ] Tests written/updated and green; coverage gates pass
- [ ] Lint + format clean both sides as applicable
- [ ] New/changed endpoints follow `api-design` standards; errors are RFC 7807
- [ ] Schema changes are append-only Flyway migrations (`ddl-auto=validate`)
- [ ] Security: authz checks present, no secrets, no PII in logs (see `SECURITY.md`)
- [ ] Observability: metrics/logs/audit events for new paths (see `docs/observability-standards.md`)
- [ ] Docs/ADR updated if the change constrains future work
- [ ] No TODO/FIXME, no commented-out code, no `console.log`/`System.out`
- [ ] PR title is a Conventional Commit; description has what/why/how-to-test

## Report
Summarize each gate as PASS/FAIL with the failing output. **Do not** recommend opening the PR while any gate is red.
