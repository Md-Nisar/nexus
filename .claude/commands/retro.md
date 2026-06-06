---
description: Phase 11 — Post-deployment validation and retrospective.
argument-hint: <FEATURE_ID>
---

Post-deployment phase for feature `$1`. Run 24–48h after the feature has shipped.

Steps:

1. **Observability validation.** Walk through `docs/features/$1/monitoring.md` and confirm:
   - All declared metrics are flowing
   - All declared log fields are present
   - Dashboards render correctly
   - Alerts have fired (or not) as expected

2. **Production health check.** Compare against baseline:
   - Error rate
   - p95 / p99 latency
   - Throughput
   - Resource utilization
   List any deviations.

3. **Feature flag status.** Confirm rollout matches the plan in the design doc.

4. **Lessons learned.** Save to `docs/features/$1/retrospective.md`:
   - What went well
   - What went poorly
   - Surprises in production
   - Workflow improvements (which phase needed more time, which less)
   - Convention updates for `CLAUDE.md`
   - Sub-agent prompt updates

5. **Apply improvements.** If new conventions emerged, update:
   - `CLAUDE.md`
   - Relevant `.claude/agents/*.md` files
   - Relevant `.claude/skills/*/SKILL.md` files

Print to chat: top 3 lessons and any production deviations from baseline.
