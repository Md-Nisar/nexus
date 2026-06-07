---
description: Phase 3 — Solution design + threat model. Produces 03-design.md and 03b-threat-model.md.
argument-hint: <FEATURE-ID>
---

Phase 3 has two steps. Run them sequentially.

## Step A — Design (architect agent)

Use the **architect** sub-agent in plan mode.

Prerequisites:
- `docs/features/$1/01-requirements.md` (approved)
- `docs/features/$1/02-impact.md` (approved)

1. Read both prerequisites.
2. Produce the Technical Design Document per the architect agent's spec — including mermaid diagrams, API contracts, DB design, error handling, observability plan, feature flag, rollout plan.
3. Save to `docs/features/$1/03-design.md`.

## Step B — Threat Model (security-reviewer agent)

Use the **security-reviewer** sub-agent.

1. Read `docs/features/$1/03-design.md`.
2. Apply STRIDE to each component and trust boundary.
3. Identify threats, existing mitigations, required mitigations, residual risk.
4. Save to `docs/features/$1/03b-threat-model.md`.
5. Flag any threats that require design changes back to the architect — surface these to chat.

Approval gate before `/breakdown $1`. Do not write implementation code in this phase.
