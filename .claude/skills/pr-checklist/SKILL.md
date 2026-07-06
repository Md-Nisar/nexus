---
name: pr-checklist
description: Use before opening or merging a pull request on Nexus, or whenever asked to run pre-PR / pre-merge checks. The executable runbook of local quality gates (the same gates CI enforces) plus the Definition of Done. Invoked by /pre-pr-check.
---

# Pre-PR Checklist (executable gate runbook)

Run the gates for whichever side changed. These mirror CI — passing here means CI should pass. The policy behind them lives in `CONTRIBUTING.md` (process) and `docs/TESTING.md`/`SECURITY.md` (standards); this skill is the *how to run*.

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

## Definition of Done

The canonical checklist is **`CONTRIBUTING.md` → Definition of Done** — read it and walk every item against the diff. This skill adds nothing to that list; it only automates the executable parts above.

## Report
Summarize each gate as PASS/FAIL with the failing output. **Do not** recommend opening the PR while any gate is red.
