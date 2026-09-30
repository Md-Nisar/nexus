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

## Feature artifacts & gate records

Identify the feature from the diff (`docs/features/<ID>/` paths) or the branch name. No feature ID → a quick fix; skip this section and say so in the report.

For a feature branch, every item below must be present — a missing one is a **FAIL**, not a warning:

| Artifact | Required content |
|---|---|
| `01-requirements.md` | `**Gate 1:** approved <YYYY-MM-DD>` |
| `03-design.md`, `03b-threat-model.md` | `**Gate 2:** approved <YYYY-MM-DD>` in `03-design.md` |
| `04-tasks.md` | `**Gate 3:** approved <YYYY-MM-DD>` |
| `06-code-review.md` | verdict `APPROVE` or `APPROVE WITH NITS` |
| `07-security-review.md` | no open Blocker |
| `08-test-audit.md` | present |
| `09-technical.md` | present |

```bash
ID=<FEATURE-ID>; d=docs/features/$ID
for n in 1:01-requirements 2:03-design 3:04-tasks; do
  grep -qE "\*\*Gate ${n%%:*}:\*\* approved [0-9]{4}-[0-9]{2}-[0-9]{2}" "$d/${n#*:}.md" || echo "FAIL: Gate ${n%%:*} record"
done
for f in 03b-threat-model 06-code-review 07-security-review 08-test-audit 09-technical; do
  [ -f "$d/$f.md" ] || echo "FAIL: missing $f.md"
done
```

If any record reads `by claude-agent:<name>` (an `/autonomous-feature` run), the PR body must contain the **Autonomous run (pilot)** gate table — otherwise **FAIL**: a PR must never imply human sign-off that did not happen.

Stories merged before this check existed (US-001–US-017) are not re-checked; it applies to the feature the current branch changes.

## Definition of Done

The canonical checklist is **`CONTRIBUTING.md` → Definition of Done** — read it and walk every item against the diff. This skill adds nothing to that list; it only automates the executable parts above.

## Report
Summarize each gate as PASS/FAIL with the failing output. **Do not** recommend opening the PR while any gate is red.
