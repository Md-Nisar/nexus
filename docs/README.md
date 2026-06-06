# Nexus Documentation

Engineering reference for the Nexus platform. Keep these docs accurate — they are the source of truth for conventions, and every Claude agent reads them.

## Standards

| Doc | What it governs |
|-----|-----------------|
| [Architecture](./architecture.md) | System structure, hexagonal layering, bounded contexts, dependency rules |
| [Coding Standards](./coding-standards.md) | Naming, formatting, commits, PRs, error handling, logging |
| [Security Guidelines](./security-guidelines.md) | Auth, crypto, PII, secrets, OWASP controls |
| [Testing Standards](./testing-standards.md) | Pyramid, coverage targets, tools, conventions |
| [Observability Standards](./observability-standards.md) | Logs, metrics, traces, dashboards, alerts |
| [Deployment Process](./deployment-process.md) | Environments, pipeline, feature flags, rollback |

## Architecture Decision Records

ADRs live in [`docs/adr/`](./adr/). See [0001-record-architecture-decisions.md](./adr/0001-record-architecture-decisions.md) for format and process.

| ID | Title | Status |
|----|-------|--------|
| 0001 | Record Architecture Decisions | Accepted |
| 0002 | Hexagonal Architecture | Accepted |

## Feature Documentation

Each feature produced by the enterprise workflow creates a folder under `docs/features/<FEATURE_ID>-<FEATURE_NAME>/`.

Artifact naming convention: `{FEATURE_ID}.{artifact}.md` — all files are flat in the feature folder.

Example for `US001-tenant-management`:

```
docs/features/US001-tenant-management/
│
│  ── Plan Workflow artifacts (produced by plan-workflow.md) ──────────────
│
├── US001.story.md                    # Source of truth — user story (you provide this)
│
├── US001.business-analysis.md        # Phase 1  /analyze-story
│                                     #   Requirements, NFRs, business rules,
│                                     #   gap analysis, clarification questions,
│                                     #   success metrics
│
├── US001.impact-analysis.md          # Phase 2  /impact-analysis
│                                     #   Existing components, reuse vs modify,
│                                     #   dependency analysis, DB change flags
│
├── US001.domain-design.md            # Phase 3A /design (architect)
│                                     #   DDD: aggregates, entities, value objects,
│                                     #   domain services, domain events,
│                                     #   repository boundaries, bounded context diagram
│
├── US001.solution-architecture.md    # Phase 3A /design (architect)
│                                     #   Hexagonal layer design, sequence diagrams,
│                                     #   component diagrams, observability plan,
│                                     #   feature flag strategy, scalability,
│                                     #   future compatibility review
│
├── US001.api-design.md               # Phase 3A /design (architect)
│                                     #   REST endpoints, request/response DTOs,
│                                     #   validation rules, error codes,
│                                     #   pagination, versioning, OpenAPI contracts
│
├── US001.database-design.md          # Phase 3A /design (architect)
│                                     #   Tables, columns, constraints, indexes,
│                                     #   FK relationships, ERD, data dictionary,
│                                     #   migration strategy
│
├── US001.security-threat-model.md    # Phase 3B /design (security-reviewer)
│                                     #   STRIDE analysis, threats with severity,
│                                     #   required mitigations, residual risks
│
├── US001.frontend-design.md          # Phase 3C /design (frontend-engineer)
│                                     #   UX flows, component hierarchy, routes,
│                                     #   state machines, guards, permissions,
│                                     #   API integration strategy
│
├── US001.task-breakdown.md           # Phase 4  /breakdown
│                                     #   Sequenced tasks (T-001…T-NNN) with
│                                     #   dependencies, effort, risks, acceptance
│                                     #   criteria; sequencing diagram
│
│  ── Action Workflow artifacts (produced by action-workflow.md) ──────────
│
├── US001.review-report.md            # Phase /review (code-reviewer)
│                                     #   Architecture compliance, correctness,
│                                     #   performance, test quality findings;
│                                     #   verdict: APPROVE / CHANGES REQUESTED
│
├── US001.security-review.md          # Phase /security-scan (security-reviewer)
│                                     #   OWASP Top 10 audit, threat model
│                                     #   coverage verification, dependency scan
│                                     #   results; verdict: APPROVED / BLOCKED
│
├── US001.test-validation.md          # Phase /test-validate (qa-engineer)
│                                     #   Coverage by layer, gaps identified
│                                     #   and closed, run results, load test
│                                     #   results, flaky test report
│
├── US001.implementation-docs.md      # Phase /docs
│                                     #   Technical overview, API reference,
│                                     #   deployment guide, rollback plan,
│                                     #   monitoring guide, runbook
│
├── US001.release-preparation.md      # Phase /release-prep (release-manager)
│                                     #   Deployment checklist, rollback checklist,
│                                     #   smoke test checklist, monitoring checklist,
│                                     #   production readiness verdict
│
└── US001.retrospective.md            # Phase /retro (24–48h post-deploy)
                                      #   Observability validation, production
                                      #   health vs baseline, lessons learned,
                                      #   convention updates applied
```

### Artifact ownership at a glance

| Artifact | Workflow | Agent |
|----------|----------|-------|
| `{ID}.business-analysis.md` | Plan | `business-analyst` |
| `{ID}.impact-analysis.md` | Plan | `architect` |
| `{ID}.domain-design.md` | Plan | `architect` |
| `{ID}.solution-architecture.md` | Plan | `architect` |
| `{ID}.api-design.md` | Plan | `architect` |
| `{ID}.database-design.md` | Plan | `architect` |
| `{ID}.security-threat-model.md` | Plan | `security-reviewer` |
| `{ID}.frontend-design.md` | Plan | `frontend-engineer` |
| `{ID}.task-breakdown.md` | Plan | `architect` + engineers + `qa-engineer` |
| `{ID}.review-report.md` | Action | `code-reviewer` |
| `{ID}.security-review.md` | Action | `security-reviewer` |
| `{ID}.test-validation.md` | Action | `qa-engineer` |
| `{ID}.implementation-docs.md` | Action | *(main context)* |
| `{ID}.release-preparation.md` | Action | `release-manager` |
| `{ID}.retrospective.md` | Action | *(main context)* |

### Gates and approvals

| Gate | After | Trigger |
|------|-------|---------|
| Gate 1 — Business Analysis | `business-analysis.md` | Reply `APPROVED` |
| Gate 2 — Architecture | All Phase 3 artifacts | Reply `APPROVED` |
| Gate 3 — Task Breakdown | `task-breakdown.md` | Reply `APPROVED` |
| Per-task plan gate | Each `/implement` task | Reply `Approved. Proceed.` |
| Release gate | `release-preparation.md` | Verdict must be `READY` |

## Keeping docs current

- After every feature retro (`/retro {FEATURE_ID}`), update standards if conventions changed.
- Any change to coding, security, or testing standards requires a PR reviewed by a senior engineer.
- ADRs are append-only — amend by adding a new ADR that supersedes the old one.
- The story file (`{ID}.story.md`) is the source of truth and is never modified after Gate 1.
