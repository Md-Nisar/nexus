<!-- PR title MUST be a Conventional Commit: <type>(<scope>): <summary>
     types: feat, fix, docs, test, refactor, chore, perf, security, build, ci
     The PR Title check enforces this. -->

## What

<!-- One sentence: what does this PR change? -->

## Why

<!-- Link the ticket: NEXUS-XXXX. Context a reviewer needs. -->

## How to test

<!-- Commands or steps. Screenshots for UI changes. -->

## Definition of Done

<!-- Run `/pre-pr-check` (or the pr-checklist skill) to verify these. -->

- [ ] `/pre-pr-check` green — tests, coverage gates, lint, format, build (the gates CI enforces)
- [ ] New/changed endpoints follow API standards; errors are RFC 7807
- [ ] Schema changes are append-only Flyway migrations (`ddl-auto=validate`)
- [ ] Security: authz present, no secrets, no PII in logs (see `SECURITY.md`)
- [ ] Observability: metrics/logs/audit events for new code paths
- [ ] No TODO/FIXME, no commented-out code, no `console.log`/`System.out`
- [ ] Docs/ADR updated if this constrains future work

<!-- For substantial features, link the docs/features/<ID>/ artifacts and confirm reviews passed. -->
