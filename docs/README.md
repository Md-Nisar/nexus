# Nexus Documentation

Engineering reference for the Nexus platform. Every Claude agent and human contributor reads these — keep them accurate. **Each topic has exactly one home** (single source of truth).

## Where things live

| Topic | Canonical doc |
|-------|---------------|
| Project map & entry point | [`/README.md`](../README.md) |
| Architecture, layering, non-negotiables | [`/ARCHITECTURE.md`](./ARCHITECTURE.md) |
| Operating model & local dev | [`/DEVELOPMENT_GUIDE.md`](./DEVELOPMENT_GUIDE.md) |
| Testing strategy & coverage gates | [`/TESTING.md`](./TESTING.md) |
| Security baseline & standards | [`/SECURITY.md`](../SECURITY.md) |
| Branching, commits, PRs | [`/CONTRIBUTING.md`](../CONTRIBUTING.md) |
| Agent map & critical conventions | [`/CLAUDE.md`](../CLAUDE.md) |

## Deep reference (this folder)

| Doc | What it governs |
|-----|-----------------|
| [Coding Standards](./coding-standards.md) | Naming, formatting, error handling, logging, forbidden patterns |
| [Observability Standards](./observability-standards.md) | Logs, metrics, traces, dashboards, alerts, audit log |
| [Deployment Process](./deployment-process.md) | Environments, pipeline, Flyway, feature flags, rollback |
| [ADRs](./adr/) | Architecture Decision Records (append-only) |

> Architecture, Security, and Testing standards previously duplicated here now live in the root docs above — this folder no longer carries a second copy.

## Architecture Decision Records

| ID | Title | Status |
|----|-------|--------|
| [0001](./adr/0001-record-architecture-decisions.md) | Record Architecture Decisions | Accepted |
| [0002](./adr/0002-hexagonal-architecture.md) | Hexagonal Architecture | Accepted |
| [0003](./adr/0003-flyway-schema-migrations.md) | Flyway Owns the Database Schema | Accepted |

ADRs are append-only — supersede an old decision with a new ADR; never edit an accepted one.

## Feature documentation

Epic and story source texts live in `docs/story/<SERIAL_NO-EPIC_NAME>/` at the repo root — they are the *inputs* to `/new-feature`. Each feature run through the operating model (see ./DEVELOPMENT_GUIDE.md) creates `docs/features/<FEATURE-ID>/` with **numbered, phase-ordered artifacts**:

```
docs/features/<FEATURE-ID>/
├── 01-requirements.md       # /new-feature → analyze (business-analyst)
├── 02-impact.md             # impact analysis (architect)
├── 03-design.md             # solution + API + DB design (architect)
├── 03b-threat-model.md      # STRIDE threat model (security-reviewer)
├── 04-tasks.md              # task breakdown (architect + engineers + qa)
├── 06-code-review.md        # /review (code-reviewer)
├── 07-security-review.md    # /security-review (security-reviewer)
├── 08-test-audit.md         # /test-validate (qa-engineer)
├── 09-technical.md          # /docs
└── 10-release/              # /release-prep (release-manager)
```

## Keeping docs current

- After a feature retro, update the relevant standard if a convention changed.
- Standards changes are reviewed by a lead (see `.github/CODEOWNERS`).
- A doc and the code/config it describes must never disagree — if they do, the doc is a bug.
