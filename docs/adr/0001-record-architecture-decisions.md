# ADR 0001 — Record Architecture Decisions

**Status:** Accepted
**Date:** 2025-11-01
**Author:** Engineering Team

## Context

Architecture decisions accumulate in Slack threads, PR descriptions, and tribal knowledge. New team members lack context for why things are the way they are, and old decisions get revisited unnecessarily. We need a lightweight, discoverable record of significant choices.

## Decision

We will record significant architecture decisions as Architecture Decision Records (ADRs), stored in `docs/adr/` and committed alongside the code.

**Format:** Nygard-style ADR with the following sections:
- **Status:** Proposed / Accepted / Deprecated / Superseded by ADR-NNNN
- **Date:** ISO 8601
- **Author:** Name or team
- **Context:** The situation that forced a decision
- **Decision:** What we decided and why
- **Alternatives considered:** What we evaluated and ruled out, with brief rationale
- **Consequences:** Positive outcomes, negative trade-offs, risks, follow-on work

**Numbering:** Sequential 4-digit prefix — `0001`, `0002`, etc.

**Lifecycle:**
- ADRs are **append-only**. Never edit an accepted ADR's decision.
- To change a decision: write a new ADR that supersedes the old one. Update the old ADR's Status to "Superseded by ADR-NNNN".

**When to write one:** See `docs/architecture.md → When to Write an ADR`.

## Alternatives Considered

- **Confluence pages:** Drifts out of sync with code. Not versioned alongside the decisions it documents.
- **PR descriptions:** Not discoverable. Lost over time.
- **No formal record:** The status quo — expensive tribal knowledge, repeated debates.

## Consequences

Positive:
- New engineers understand the "why" behind the codebase faster.
- Debates about settled decisions are resolved by reading the ADR rather than re-litigating.
- Decision-making process becomes explicit and reviewable.

Negative:
- Requires discipline to write ADRs as decisions are made, not after.
- Risk of ADRs going stale if not updated when decisions change.

Follow-on: Create a "check for ADR needed" item in the Phase 3 design template (done — see `/design` slash command).
