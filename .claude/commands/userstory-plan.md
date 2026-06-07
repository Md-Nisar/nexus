# Execute Nexus Plan Workflow for {FEATURE_ID} - {FEATURE_NAME}

## Objective

Analyze, design, and plan the feature. Produce all architecture and design artifacts
required for implementation approval.

No implementation code. No migrations. No frontend development.
Analysis, design, architecture, and planning only.

Feature Story (source of truth):

{FEATURE_STORY_PATH}

Output all artifacts under:

{FEATURE_OUTPUT_PATH}

Naming convention: `{FEATURE_ID}.{artifact}.md`

---

# Global Rules

* Follow the workflow defined in `.claude/README.md` exactly.
* Use agents from `.claude/agents/` and skills from `.claude/skills/`.
* Do not skip phases.
* Do not generate implementation code, migrations, or frontend development code.
* Every phase produces exactly its named output artifact before proceeding.
* Approval gates are hard stops — do not continue without explicit user confirmation.

---

# Phase 1: /analyze-story

**Agent:** `business-analyst`

Read the complete feature story at `{FEATURE_STORY_PATH}`. This is the source of truth.
Also read `.claude/skills/api-design/SKILL.md` and any relevant existing docs under `docs/`.

## Requirements Analysis

Document:

* Functional Requirements — numbered, atomic, testable. Each must be verifiable.
* Non-Functional Requirements — performance (RPS, p95 latency), availability (SLO), security, accessibility, i18n, observability.
* Business Rules — explicit, not inferred.
* Constraints — technical, legal, time, resource.
* Dependencies — upstream systems, downstream consumers, shared services.
* Assumptions — every assumption flagged `[CONFIRM]` for stakeholder sign-off.

## Gap Analysis

Identify:

* Missing requirements — what the story is silent about.
* Ambiguities — where two interpretations are possible; flag both.
* Future risks — decisions now that constrain the platform later.
* Scalability concerns — assumptions that break under load.
* Security concerns — PII, auth surface, trust boundaries introduced.

## Clarification Questions

List open questions addressed to specific stakeholder roles (PM, Architect, Security, Legal).
Generate questions only where the gap cannot be resolved from existing docs.

## Success Metrics

How will we know this feature is working correctly in production?

---

**Output:** `{FEATURE_ID}.business-analysis.md`

---

## ⛔ Gate 1 — Business Analysis Approval

Present the following to the user and wait for explicit confirmation before proceeding:

* Summary of functional requirements (numbered list)
* All `[CONFIRM]` assumptions
* High / Critical gaps
* All clarification questions

**Do not proceed to Phase 2 until the user confirms.**

---

# Phase 2: /impact-analysis

**Agent:** `architect`

Prerequisites: `{FEATURE_ID}.business-analysis.md` (approved)

Read the approved business analysis and explore the full codebase
(`nexus-backend/`, `nexus-frontend/`, `docs/`). Do not rely on memory — read the actual files.

## Existing Components

Identify all relevant:

* Backend modules, services, entities, repositories, domain exceptions
* REST controllers, DTOs, validators
* Frontend components, services, routes, guards
* Database tables, relationships, indexes
* Shared utilities, infrastructure adapters

For each component: file path, current responsibility, relevance to this feature.

## Impact Assessment

For each affected component determine:

* Reuse as-is
* Modify (describe what changes)
* Extend (describe the extension point)
* Replace (describe why and what replaces it)
* New (describe what needs to be created)

Document: technical debt implications, architectural risks, backward-compatibility concerns.

## Dependency Analysis

* Upstream dependencies (what this feature consumes)
* Downstream dependencies (what consumes this feature)
* Cross-module impacts (side effects on unrelated functionality)
* Database changes: flag any non-additive change (rename, drop, type change, NOT NULL on existing column) — these require an explicit migration strategy

---

**Output:** `{FEATURE_ID}.impact-analysis.md`

---

# Phase 3: /design

Phase 3 runs in three sequential steps. Each step reads the output of the previous one.
Do not run all steps simultaneously.

---

## Step A — Architect: Domain + Solution + API + Database Design

**Agent:** `architect`

Prerequisites:
* `{FEATURE_ID}.business-analysis.md` (approved)
* `{FEATURE_ID}.impact-analysis.md`

Read both. Read `.claude/skills/spring-boot-standards/SKILL.md` and `.claude/skills/api-design/SKILL.md`.

### Domain-Driven Design

Identify using the hexagonal architecture pattern from `docs/architecture.md`:

* Aggregates — with boundaries and invariants they enforce
* Entities — mutable, with identity
* Value Objects — immutable, no identity (prefer Java records)
* Domain Services — multi-entity logic that doesn't belong to one aggregate
* Domain Events — significant state changes (name in past tense: `PasswordResetRequested`)
* Repository Boundaries — one repository per aggregate root

Generate:

* Domain model diagram (mermaid)
* Aggregate design table (aggregate | entities | value objects | invariants)
* Domain event catalog (event | trigger | consumers | payload)

**Output section:** included in `{FEATURE_ID}.domain-design.md`

### Solution Architecture

Design:

* Application architecture — hexagonal layers (domain / application / infrastructure / interfaces)
* Service design — use-case classes, port interfaces, adapter implementations
* Integration architecture — how this feature touches external systems or shared services
* Sequence diagrams — one mermaid `sequenceDiagram` per key flow
* Component diagram — mermaid `graph` showing component relationships
* Observability plan — metrics (names, types, labels), log fields, audit events, dashboards
* Feature flag strategy — flag name, default per environment, rollout plan
* Scalability strategy — horizontal scaling, stateless design, hot-path analysis
* Reliability strategy — error handling, retry policy, idempotency, circuit breakers

### Future Compatibility Review

Assess compatibility with future platform capabilities:

* Authentication / Authorization / User Management / Role Management
* AI Platform / Analytics / Dashboards / Reports
* Files / Integrations / Notifications / Billing / Future Modules

Identify future risks and recommendations. Include in `{FEATURE_ID}.solution-architecture.md`.

**Output:** `{FEATURE_ID}.solution-architecture.md` (including future compatibility review)

### API Design

Read `.claude/skills/api-design/SKILL.md` before designing.

Design:

* REST endpoints — method, path, purpose, auth requirement
* Request DTOs — fields, types, validation rules, constraints
* Response DTOs — fields, types, never domain entities
* Error handling — error codes (SCREAMING_SNAKE_CASE), HTTP status mapping, standard error shape
* Pagination — cursor or offset; document the choice
* Filtering and sorting — query param conventions
* Versioning — breaking vs non-breaking change strategy
* Idempotency — which endpoints need `Idempotency-Key`

Generate OpenAPI-style contracts for every endpoint.

**Output:** `{FEATURE_ID}.api-design.md`

### Database Design

Design:

* Tables — name (snake_case, plural), purpose
* Columns — name, type, constraints (NOT NULL, DEFAULT, UNIQUE)
* Primary keys — ULID (CHAR(26)) preferred for new tables
* Relationships — FK constraints with explicit names (`fk_<from>_<to>`)
* Indexes — on every column used in WHERE / ORDER BY / JOIN (`idx_<table>_<columns>`)
* Audit requirements — `created_at`, `updated_at`, soft-delete if needed
* Migration strategy — additive (ddl-auto=update handles it) vs non-additive (flag for explicit migration)

Generate ERD (mermaid `erDiagram`) and data dictionary table.

**Output:** `{FEATURE_ID}.database-design.md`

---

## Step B — Security Reviewer: Threat Model

**Agent:** `security-reviewer` (Mode A — design threat model)

Prerequisites: `{FEATURE_ID}.solution-architecture.md`, `{FEATURE_ID}.api-design.md` (from Step A)

Apply STRIDE to every component and trust boundary in the design.
Read `docs/security-guidelines.md` before starting.

For each threat document:

* Threat ID (T-01, T-02, …)
* STRIDE category
* Affected component / trust boundary
* Attack scenario
* Likelihood (Low / Medium / High)
* Impact (Low / Medium / High / Critical)
* Required mitigation — concrete, actionable
* Residual risk after mitigation

Flag any threat that requires a design change back to the architect — surface these explicitly.

**Output:** `{FEATURE_ID}.security-threat-model.md`

If any threats require design changes, return to Step A for architect to revise before proceeding to Step C.

---

## Step C — Frontend Engineer: Frontend Design

**Agent:** `frontend-engineer`

Prerequisites:
* `{FEATURE_ID}.api-design.md` (from Step A — API contracts must be settled)
* `{FEATURE_ID}.security-threat-model.md` (from Step B — no security surprises)

Read `.claude/skills/angular-standards/SKILL.md` and the existing `nexus-frontend/` codebase before designing.

Design:

### User Experience

* User flows — step-by-step, including error paths and empty states
* Navigation — routes, breadcrumbs, back-navigation
* Information architecture — how this feature fits existing nav structure
* Accessibility — WCAG 2.1 AA requirements for new UI
* Responsive behavior — mobile, tablet, desktop breakpoints

### User Interface

Design using existing design system and UI component library.
No new UI frameworks. Reuse existing components wherever possible.

Describe:

* Page layout per route
* Component hierarchy per page
* State representations: loading, success, empty, error — for every async operation
* Form validation: field-level and form-level, error message copy
* User feedback: success toasts, error banners, progress indicators

### Frontend Architecture

Design (standalone components, signals-first):

* Routes — paths, lazy-loading strategy, route guards
* Pages — one component per route, responsibilities
* Reusable components — extracted from pages, props via `input()`, events via `output()`
* State management — `signal()` and `computed()` for local/service state; justify any cross-feature shared state
* State machines — discriminated union types for every async view state
* Guards — functional `CanActivateFn`, what they check, redirect targets
* Permission checks — what roles can access which routes/actions
* API integration — service method signatures, error transformation to `AppError`
* TypeScript types — DTO types in `src/app/api/types/`, domain types at service boundary

**Output:** `{FEATURE_ID}.frontend-design.md`

---

## ⛔ Gate 2 — Architecture Approval Gate

**STOP. Do not proceed to Phase 4 until the user explicitly approves.**

Present the following in chat:

### Executive Summary
One paragraph: what is being built, the key architectural choices, and the main trade-offs.

### Key Architectural Decisions
Numbered list. Each decision: choice made, alternatives considered, reason for this choice.

### Trade-off Analysis
What this design optimises for and what it accepts as a cost.

### Risks
Any unresolved risk that could affect the implementation or production stability.

### Open Questions
Anything that needs a human decision before implementation begins.

### Implementation Readiness Assessment

```
[ ] Business analysis complete and approved
[ ] Domain design complete
[ ] Solution architecture complete
[ ] Security threat model complete — no unresolved design-change flags
[ ] API design complete with OpenAPI contracts
[ ] Database design complete — migration strategy documented
[ ] Frontend design complete
[ ] All risks identified
[ ] All open questions resolved or explicitly deferred
```

**Explicitly ask: "Do you approve this architecture? Reply APPROVED to continue."**

**Do not continue to Phase 4 without the word APPROVED.**

---

# Phase 4: /breakdown

**Agents:** `architect`, `backend-engineer`, `frontend-engineer`, `qa-engineer`

Prerequisites: All Phase 3 artifacts and architecture approval.

Read all design artifacts before producing tasks.

Organize as: Epic → Story → Task

Tasks must be sequenced — list dependencies explicitly. A task with no dependencies can start immediately; a task with dependencies cannot start until those are complete.

---

## Task Structure

For every task provide:

* **ID** — sequential (T-001, T-002, …)
* **Title**
* **Agent** — which engineer agent implements this
* **Description** — what to build and why
* **Dependencies** — other task IDs that must complete first
* **Files** — existing files to modify + new files to create (with full paths)
* **Effort** — S (< 2h) / M (2–4h) / L (4–8h)
* **Risk** — Low / Medium / High, with explanation
* **Testing requirements** — specific test cases to write (named)
* **Acceptance Criteria** — verifiable, not vague

---

## Task Groups

### Database Tasks
Schema changes, entity definitions. These run first.

### Backend Tasks
Organize by layer in order:
* Domain (entities, value objects, domain exceptions)
* Application (use-case services, port interfaces)
* Infrastructure (JPA repositories, external adapters)
* Interfaces (controllers, request/response DTOs)

### Frontend Tasks
Organize by dependency:
* Services and API types
* Shared/reusable components
* Page components and routes

### Security Tasks
Threat model required mitigations not already covered in backend/frontend tasks.

### Testing Tasks
Load test scenarios, E2E flows, additional integration test coverage.

### Cross-Cutting Tasks
Feature flag wiring, observability instrumentation, cleanup jobs.

### Documentation Tasks
Technical docs, ADR (if applicable), runbook, monitoring guide.

---

Include a sequencing diagram (mermaid `graph LR`) showing task dependencies.

Provide a total effort estimate and a suggested implementation order for a single engineer.

---

**Output:** `{FEATURE_ID}.task-breakdown.md`

---

## ⛔ Gate 3 — Task Breakdown Approval

Present in chat:

* Total task count by group
* Total estimated effort
* Top 3 risks with mitigation notes
* Suggested first 3 tasks to begin implementation

**Ask: "Do you approve this task breakdown? Reply APPROVED to hand off to the action workflow."**

**Do not proceed further. The action workflow is a separate execution.**

---

# STOP

Do not execute:

* `/implement`
* `/review`
* `/security-scan`
* `/test-validate`
* `/docs`
* `/release-prep`
* `/retro`

Those phases are executed by the action workflow after explicit approval.

---

# Final Deliverables

This workflow produces exactly:

* `{FEATURE_ID}.business-analysis.md`
* `{FEATURE_ID}.impact-analysis.md`
* `{FEATURE_ID}.domain-design.md`
* `{FEATURE_ID}.solution-architecture.md`
* `{FEATURE_ID}.security-threat-model.md`
* `{FEATURE_ID}.api-design.md`
* `{FEATURE_ID}.database-design.md`
* `{FEATURE_ID}.frontend-design.md`
* `{FEATURE_ID}.task-breakdown.md`

Nothing else. No code. No migrations. No implementation.
