# .claude/ — Nexus Enterprise Workflow Configuration

This directory configures Claude Code for the Nexus project. Everything here is committed (except `settings.local.json`).

## Structure

```
.claude/
├── settings.json          # Permissions, hooks, env (committed team config)
├── settings.local.json    # Your local overrides — gitignored
├── agents/                # Sub-agents — each runs in its own context (review agents read-only)
│   ├── business-analyst.md   architect.md       backend-engineer.md   frontend-engineer.md
│   └── code-reviewer.md      security-reviewer.md  qa-engineer.md     release-manager.md
├── commands/              # Slash commands
│   ├── new-feature.md     # /new-feature <ID>      ← canonical front door (plan half + gates)
│   ├── pre-pr-check.md    # /pre-pr-check          ← run all local gates + DoD before a PR
│   ├── security-review.md # /security-review [ID]  ← ad-hoc diff security audit
│   ├── analyze-story.md  impact-analysis.md  design.md  breakdown.md   # plan phases 1–4
│   ├── implement.md  review.md  test-validate.md  docs.md  release-prep.md  retro.md  # action phases 5–11
│   ├── security-scan.md   # /security-scan <ID>    ← story-bound Phase 7 (writes 07-security-review.md)
│   └── userstory-plan.md  userstory-action.md      # batch runners for each half
├── skills/                # Standards skills + workflow skills
│   ├── spring-boot-standards/  angular-standards/  api-design/   # standards (auto-loaded by topic)
│   └── feature-discovery/      pr-checklist/                     # workflow procedures
└── hooks/                 # Cross-platform Node hooks wired into settings.json
    ├── _hooklib.mjs            # shared helpers
    ├── block-prod-commands.mjs # PreToolUse(Bash) — block destructive/prod commands
    ├── secret-scan.mjs         # PreToolUse(Write|Edit) — block secrets & prod-file writes
    ├── format.mjs              # PostToolUse(Write|Edit) — Prettier on frontend files
    └── run-tests.mjs           # Stop — run affected unit tests before the session ends
```

## Setup

`settings.json` is committed and loaded automatically — no setup needed for Claude sessions. The hooks are Node (`.mjs`), invoked via `node`, so they run on Windows, macOS, and Linux without `chmod`.

For human developers, enable the matching local git gate once:

```bash
git config core.hooksPath .githooks    # runs format/lint/tests before push
```

`.claude/settings.local.json` is gitignored (see root `.gitignore`). Optionally connect MCP servers (Jira, Confluence, GitHub) so commands like `/analyze-story` can pull data directly:

```bash
claude mcp add atlassian npx -- @atlassian/mcp-server
claude mcp add github npx -- @modelcontextprotocol/server-github
```

## The Workflow

The full operating model (gates, agents, requirements) lives in **`DEVELOPMENT_GUIDE.md` → The Operating Model** — the single source of truth. Start with `/new-feature <FEATURE-ID>`. Quick reference:

```
/new-feature JIRA-1234       → discovery + plan half (phases 1–4) with gates
  ├ /analyze-story  → Phase 1: requirements      → 01-requirements.md   [Gate 1]
  ├ /impact-analysis→ Phase 2: codebase impact   → 02-impact.md
  ├ /design         → Phase 3: design + threat   → 03-design.md, 03b-threat-model.md [Gate 2]
  └ /breakdown      → Phase 4: tasks             → 04-tasks.md          [Gate 3]
/implement JIRA-1234 T-001   → Phase 5: per task, test-first, plan-mode-first
/review JIRA-1234            → Phase 6: code review      → 06-code-review.md
/security-review [JIRA-1234] → Phase 7: security audit   → 07-security-review.md
/test-validate JIRA-1234     → Phase 8: coverage audit   → 08-test-audit.md
/docs JIRA-1234              → Phase 9: documentation    → 09-technical.md
/release-prep JIRA-1234      → Phase 10: release         → 10-release/
/retro JIRA-1234             → Phase 11: post-deploy retrospective
/pre-pr-check                → run all local gates + Definition of Done before the PR
```

All artifacts land in `docs/features/<FEATURE-ID>/` using the **numbered convention** above (`docs/README.md` → Feature documentation). `/userstory-plan` and `/userstory-action` run each half as a batch.

## Cost & context tips

- Each sub-agent has its own context — heavy exploration in a sub-agent keeps your main thread clean.
- Run `/context` to check usage. Run `/compact` between major tasks if creeping toward limits.
- The `architect` and `security-reviewer` agents are set to `opus` (highest quality reasoning). Engineers are `sonnet` (good code/speed balance). Reviewers and QA are `sonnet`. Override per task with `--model` if needed.
- For a quick fix that doesn't need the full workflow: just talk to Claude directly. The workflow is for substantial features.

## Maintaining this directory

- After every feature, run `/retro <FEATURE-ID>`. If new conventions emerged, update the relevant agent or skill files.
- Treat agent and skill files as code: PR them, review them, keep them in sync with reality.
- If a hook fires too often or not enough, tune it — hooks are leverage; bad hooks are friction.
