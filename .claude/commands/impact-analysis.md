---
description: Phase 2 — Codebase impact analysis. Produces 02-impact.md.
argument-hint: <FEATURE-ID>
---

Use the **architect** sub-agent in plan mode (read-only) to analyze codebase impact for `$1`.

Prerequisites:
- `docs/features/$1/01-requirements.md` must exist and be approved.

Steps:
1. Read `docs/features/$1/01-requirements.md`.
2. Explore the Nexus codebase (`nexus-backend/`, `nexus-frontend/`) — identify all modules, classes, components, routes, and DB tables likely affected.
3. Produce the Impact Analysis Document per the architect agent's spec.
4. Save to `docs/features/$1/02-impact.md`.
5. Print to chat: modules affected (with file paths), DB changes summary, breaking changes (if any), top 3 risks.

Do not modify any code. This is an approval gate before `/design $1`.
