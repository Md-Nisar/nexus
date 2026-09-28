---
description: PILOT — run the whole operating model (Phases 0–9) unattended and open one draft PR. Agents hold Gates 2–3 and task plans; a human answers Gate 1 questions and reviews the PR.
argument-hint: <FEATURE-ID>
---

Deliver feature **`$1`** end to end without a human at each gate. This is the **pilot** mode decided in the 2026-09 operating-model review; the human-gated `/new-feature` flow remains the default.

## Preconditions — refuse and stop if any fails

1. **Risk tier is low or medium.** Apply the `/new-feature` Step 0 tiering. A **high-risk** story (authn/authz, permission gates, tenant isolation, lockout/data-integrity logic, secrets, PII) is out of scope for this mode: say so and direct the user to `/new-feature $1`.
2. **Environment is complete.** Java 25 (`java -version`), `docker info` succeeds (Testcontainers ITs), and `nexus-frontend/node_modules` is installed. If not, stop and point to `docs/runbooks/cloud-agent-setup.md` — never ship a PR whose ITs silently did not run.
3. Branch: `feature/$1-<short-description>` from latest `main` (`CONTRIBUTING.md`). **Never** an `ai/` branch — that prefix triggers the Sonar-fix guardrails, not this flow.

## Gate owners in this mode

| Step | Command | Approved by | Pass condition |
|---|---|---|---|
| 0–1 Discovery + requirements | `/new-feature` Step 0, `/analyze-story $1` | **human only if open questions remain** | See *Stop-and-ask* |
| 2 Impact | `/impact-analysis $1` | — | — |
| 3 Design + threat model (Gate 2) | `/design $1` | `security-reviewer` | Required changes all closed by the Step C delta review; no open Blocker |
| 4 Breakdown (Gate 3) | `/breakdown $1` | `architect` | Threat → task and AC → task tables are complete; sizing rules in `/breakdown` met |
| 5 Implement, per task | `/implement $1 <TASK>` | `code-reviewer` approves each plan | Plan matches `03-design.md` and the standards skills; tests green after each task |
| 6–8 Review, security, tests | `/review`, `/security-review`, `/test-validate` | the phase agents | `APPROVE` / `APPROVE WITH NITS`; no Blocker; coverage gates green |
| 9 Docs | `/docs $1` | — | `09-technical.md` present |
| Pre-PR | `/pre-pr-check` | machine | every gate PASS |
| **Merge** | — | **human PR review** | branch protection |

`/release-prep` and `/retro` are not part of this run — they happen after human review, as today.

## Gate records — never impersonate a human

Write each agent approval as `**Gate N:** approved <YYYY-MM-DD> by claude-agent:<agent-name>` in the usual artifact (`01`/`03`/`04`). Gate 1 records the human who answered, or `claude-agent:business-analyst` when there were no open questions. `/implement`'s per-task plan approval is recorded in `04-tasks.md` under the task as `Plan approved by claude-agent:code-reviewer`.

## Stop-and-ask — the only way out of a blocker

Stop the run, commit the artifacts so far, and report to the user (what is blocked, what you need, how to resume) when:
- `01-requirements.md` has open questions, `[CONFIRM]` assumptions, or conflicting sources. **Never answer them yourself** — the business-analyst rule "never invent details" holds. Resume from Step 2 once answered.
- A gate still fails after **2** revision loops (Gate 2 delta reviews, code-review → fix cycles, or a red check you cannot fix).
- Any change would widen scope beyond `01-requirements.md`, add a dependency, or touch a protected path.

Do not weaken a test, gate, or rule to get past a blocker.

## Deliverable

1. Commit per task (Conventional Commits), push the branch, open a **draft** PR against `main`.
2. PR body follows `.github/PULL_REQUEST_TEMPLATE.md` and adds a section:

   ```markdown
   ## Autonomous run (pilot)
   | Gate | Approved by | Artifact |
   |---|---|---|
   | Gate 1 | <human or claude-agent:business-analyst> | docs/features/$1/01-requirements.md |
   | Gate 2 | claude-agent:security-reviewer | 03-design.md, 03b-threat-model.md |
   | Gate 3 | claude-agent:architect | 04-tasks.md |
   | Task plans | claude-agent:code-reviewer | 04-tasks.md |
   ```
   plus links to every `docs/features/$1/` artifact and the `/pre-pr-check` result.
3. Report to the user: PR link, tasks delivered, revision loops used per gate, and anything deferred.

## Pilot measurement

At the end, append to `docs/features/$1/09-technical.md` a short **Pilot metrics** section: task count, revision loops per gate, wall-clock start/end, and any stop-and-ask. The human reviewer later adds review findings and rework, which the retro compares against a human-gated baseline story of similar size.
