# .claude/ — Enterprise Workflow Configuration

This directory configures Claude Code for the Nexus project. Everything here is committed (except `settings.local.json`).
The slash commands under commands/ are the authoritative workflow definition. This README is an orientation guide only.

## Structure

```
.claude/
├── settings.json          # Permissions, hooks, env
├── settings.local.json    # Your local overrides — gitignored
├── agents/                # Sub-agents — each runs in its own context
│   ├── business-analyst.md
│   ├── architect.md
│   ├── backend-engineer.md
│   ├── frontend-engineer.md
│   ├── code-reviewer.md
│   ├── security-reviewer.md
│   ├── qa-engineer.md
│   └── release-manager.md
├── commands/              # Slash commands — one per workflow phase
│   ├── analyze-story.md   # /analyze-story <FEATURE_ID>
│   ├── impact-analysis.md # /impact-analysis <FEATURE_ID>
│   ├── design.md          # /design <FEATURE_ID>
│   ├── breakdown.md       # /breakdown <FEATURE_ID>
│   ├── implement.md       # /implement <FEATURE_ID> <TASK-ID>
│   ├── review.md          # /review <FEATURE_ID>
│   ├── security-scan.md   # /security-scan <FEATURE_ID>
│   ├── test-validate.md   # /test-validate <FEATURE_ID>
│   ├── docs.md            # /docs <FEATURE_ID>
│   ├── release-prep.md    # /release-prep <FEATURE_ID>
│   └── retro.md           # /retro <FEATURE_ID>
├── skills/                # Reusable standards docs
│   ├── spring-boot-standards/SKILL.md
│   ├── angular-standards/SKILL.md
│   └── api-design/SKILL.md
└── hooks/                 # Shell scripts wired into settings.json
    ├── block-prod-commands.sh
    ├── secret-scan.sh
    ├── format-and-lint.sh
    └── run-tests.sh
```

## Setup

After cloning:

```bash
chmod +x .claude/hooks/*.sh
```

Add to `.gitignore`:

```
.claude/settings.local.json
```

Optionally connect MCP servers (Jira, Confluence, GitHub) so commands like `/analyze-story` can pull data directly:

```bash
claude mcp add atlassian npx -- @atlassian/mcp-server
claude mcp add github npx -- @modelcontextprotocol/server-github
```

## The Workflow

Each phase is one slash command. Approval gates between phases.

```
/analyze-story FEATURE_ID     → Phase 1: requirements
/impact-analysis FEATURE_ID   → Phase 2: codebase impact
/design FEATURE_ID            → Phase 3: TDD + threat model
/breakdown FEATURE_ID         → Phase 4: tasks
/implement FEATURE_ID T-001   → Phase 5: per task, test-first, plan-mode-first
/implement FEATURE_ID T-002
... (repeat per task)
/review FEATURE_ID            → Phase 6: code review (fresh-context sub-agent)
/security-scan FEATURE_ID     → Phase 7: security audit
/test-validate FEATURE_ID     → Phase 8: coverage audit
/docs FEATURE_ID              → Phase 9: documentation
/release-prep FEATURE_ID      → Phase 10: release readiness
/retro FEATURE_ID             → Phase 11: post-deploy retrospective
```

All artifacts land in `docs/features/<FEATURE_ID>-<FEATURE_NAME>/` with naming convention `<FEATURE_ID>.<ARTIFACT>.md`.

## Cost & context tips

- Each sub-agent has its own context — heavy exploration in a sub-agent keeps your main thread clean.
- Run `/context` to check usage. Run `/compact` between major tasks if creeping toward limits.
- The `architect` and `security-reviewer` agents are set to `opus` (highest quality reasoning). Engineers are `sonnet` (good code/speed balance). Reviewers and QA are `sonnet`. Override per task with `--model` if needed.
- For a quick fix that doesn't need the full workflow: just talk to Claude directly. The workflow is for substantial features.

## Maintaining this directory

- After every feature, run `/retro <FEATURE_ID>`. If new conventions emerged, update the relevant agent or skill files.
- Treat agent and skill files as code: PR them, review them, keep them in sync with reality.
- If a hook fires too often or not enough, tune it — hooks are leverage; bad hooks are friction.
