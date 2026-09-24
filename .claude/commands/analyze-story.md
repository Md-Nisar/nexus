---
description: Phase 1 — Requirement analysis on a Jira story. Produces 01-requirements.md.
argument-hint: <FEATURE-ID>
---

Use the **business-analyst** sub-agent to analyze the requirements for `$1`.

Steps (1–2 run in the main session — the sub-agent has no MCP tools):
1. Pull the Jira story `$1` (use the Atlassian MCP if connected; else `docs/story/`; otherwise ask the user to paste it).
2. Pull any linked Confluence pages — BRD, mockup links, acceptance criteria. Pass the full source text to the sub-agent.
3. The sub-agent reads any relevant existing code in `nexus-backend/` and `nexus-frontend/` to ground the analysis.
4. Produce the full Requirement Analysis Document per the agent's deliverable spec.
5. Save to `docs/features/$1/01-requirements.md`.
6. Print a summary of risks (High/Critical only) and open questions to chat.

Do not design or write code. This is a discovery phase.

After completion, remind the user this is an approval gate before proceeding to `/impact-analysis $1`.
