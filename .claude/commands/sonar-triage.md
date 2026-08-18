---
description: Fetch and prioritise open SonarQube issues on main
---

Use the `sonar-triage` skill.

Fetch open, unresolved issues for `Md-Nisar_nexus` on branch `main` from
SonarQube Cloud. Separate quality-gate-blocking New Code issues from legacy
debt, cluster by rule key, rank with the prioritisation rubric, and present the
ranked tables.

Scope: $ARGUMENTS (leave empty for everything; may name a rule key, a severity,
or `backend`/`frontend`).

This is read-only. Do not modify any file. End by asking which cluster I want
to act on.
