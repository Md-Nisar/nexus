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
6. **Re-verify only what's new or changed.** For a fact a prior story in this epic already verified in code (cite it), trust it unless `git log -- <path>` shows the file changed since that verification — don't re-derive it from scratch. This bounds review cost without lowering rigor on anything actually new.

## Step C — Revision loop, if Step B raises required changes

1. Dispatch the **architect** sub-agent with the specific required-change list (not "re-read the threat model and figure out what to do") — extract the concrete asks yourself first so the agent isn't re-deriving them.
2. The architect revises `03-design.md` **in place with `Edit`**, not a full rewrite, and amends the relevant ADR's mutable sections (e.g. "does not close" / follow-on rules) the same way.
3. Send the revision back to **security-reviewer** for a **delta review**: confirm each required change landed correctly and flag any new regression — not a fresh full STRIDE pass. Reserve the full pass for the next new story.

Approval gate before `/breakdown $1`. Do not write implementation code in this phase.
