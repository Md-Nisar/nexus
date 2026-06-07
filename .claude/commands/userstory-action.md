# Execute Nexus Action Workflow for US001 - Tenant Management

## Objective

Implement the approved design, validate it, document it, and prepare it for release.

Feature: Tenant Management
Feature ID: US001
Artifacts location: docs/features/US001-tenant-management/

---

# Preconditions

Before starting, verify every artifact exists and is marked approved:

* `US001.business-analysis.md`
* `US001.impact-analysis.md`
* `US001.domain-design.md`
* `US001.solution-architecture.md`
* `US001.security-threat-model.md`
* `US001.api-design.md`
* `US001.database-design.md`
* `US001.frontend-design.md`
* `US001.task-breakdown.md`

If any artifact is missing: stop. Do not continue. List which artifacts are missing and instruct the user to run the plan workflow first.

Also read:
* `docs/coding-standards.md`
* `docs/security-guidelines.md`
* `docs/testing-standards.md`
* `docs/observability-standards.md`
* `.claude/skills/spring-boot-standards/SKILL.md`
* `.claude/skills/angular-standards/SKILL.md`
* `.claude/skills/api-design/SKILL.md`

These are non-negotiable standards. Every implementation decision is measured against them.

---

# Phase: /implement

**Agents:** `backend-engineer` (backend tasks), `frontend-engineer` (frontend tasks)

Work through tasks in the order defined in `US001.task-breakdown.md`.
Implement exactly one task per invocation. Do not slide into the next task.

**Read the relevant design artifact(s) before implementing each task:**

* DB tasks → `US001.database-design.md`
* Backend tasks → `US001.domain-design.md`, `US001.solution-architecture.md`, `US001.api-design.md`
* Frontend tasks → `US001.frontend-design.md`, `US001.api-design.md`
* Security tasks → `US001.security-threat-model.md`

---

## Per-Task Workflow (mandatory for every task)

### Step 1 — Plan (before writing any code)

Engineer agent enters plan mode and produces:

* Files to create (full paths)
* Files to modify (full paths, describe what changes)
* Order of operations
* **Test cases to write first** — specific method names (`should_<expected>_when_<condition>`)
* Risks or blockers

**STOP. Present the plan to the user. Do not write any code until explicitly approved.**

### Step 2 — Test First

Write the failing test(s) before writing implementation code.

Run the test to confirm it fails for the right reason.

### Step 3 — Implement

Write implementation code to make the failing tests pass.

Rules:
* Follow the approved design exactly — no improvisation
* Follow `docs/coding-standards.md` and the relevant skill files
* Reuse existing components; do not rewrite what exists
* Avoid unnecessary abstractions
* No placeholder code, no `TODO`, no `FIXME`
* Structured logging at every boundary (use MDC fields)
* For any `@Async` method: copy MDC context to the async thread (use `MDCTaskDecorator`)
* Explicit error handling — no silent swallowing
* Apply the feature flag from the design doc to all new entry points

### Step 4 — Verify

Run the full test suite for the affected module:

* Backend: `./mvnw test` (or `mvnw.cmd test` on Windows)
* Frontend: `npm test -- --run`

**Do not declare a task done with red tests.**

Run `npm run build` for any frontend task — confirm zero strict-template errors.

### Step 5 — Report

Print to chat:

* Task ID and title
* Files created and modified (with line counts)
* Test results (pass/fail counts)
* Any deviations from the approved design (with justification)

---

## Implementation Rules

* One task per invocation. Stop at the task boundary.
* If a task requires a decision not covered by the approved design, stop and ask — do not invent.
* If blocked by a missing dependency task, stop and report.
* Never declare done with red tests or TypeScript compilation errors.
* Never log raw tokens, passwords, PII, or secrets.
* Never return JPA entities from REST controllers — always map to response DTOs.
* Never use H2 in tests — Testcontainers MySQL only.
* Never use `any` in TypeScript.

---

# Phase: /review

**Agent:** `code-reviewer` — run in a fresh sub-agent context with no memory of the implementation

The code reviewer did not write this code. This is an independent review.

Before reviewing, read:
* `US001.solution-architecture.md` — does the code match the design?
* `US001.security-threat-model.md` — are all required mitigations present?
* `docs/coding-standards.md`

Determine the diff scope:

```bash
git diff origin/main...HEAD
```

Review every changed file against:

### Architecture Compliance
Does the code follow hexagonal layering? No business logic in controllers? No domain entities returned from REST? `@Transactional` only in application layer?

### Correctness
Logic errors, off-by-one, null handling, wrong conditions, wrong HTTP status codes, missing error paths.

### Coding Standards
Naming, constructor injection only, no field `@Autowired`, no `System.out.println`, no `*ngIf`/`*ngFor`, no `any`.

### Performance
N+1 queries, missing indexes, blocking I/O on hot paths, unnecessary allocations, unbounded collections.

### Concurrency
Shared mutable state, missing transactions, wrong isolation level, race conditions.

### Test Quality
Tests that pass trivially, missing edge cases, brittle assertions, tests that depend on ordering or timing, missing boundary values.

### Security (surface scan — deep audit is Phase /security-scan)
Obvious auth bypass, hardcoded credentials, PII in logs, unsanitised input rendered in UI.

---

For every finding use this format:

```
[SEVERITY] Title
File: path/to/file.java:LINE
Problem: what is wrong
Why it matters: consequence if not fixed
Fix: concrete change (code snippet if useful)
```

Severity: **Blocker** / **High** / **Medium** / **Low** / **Nit** / **Praise**

End with a **Summary**:
* Count by severity
* Verdict: `APPROVE` / `APPROVE WITH NITS` / `CHANGES REQUESTED`

If `CHANGES REQUESTED`: list Blockers and Highs inline so the user can triage immediately.

---

**Output:** `US001.review-report.md`

If verdict is `CHANGES REQUESTED`: fix Blocker and High findings, then re-run `/review` before proceeding.

---

# Phase: /security-scan

**Agent:** `security-reviewer` (Mode B — code audit)

Prerequisites:
* `/review` verdict is `APPROVE` or `APPROVE WITH NITS`
* `US001.security-threat-model.md` — cross-reference every required mitigation

Determine the diff:

```bash
git diff origin/main...HEAD
```

Walk every changed file. Apply the full OWASP Top 10 checklist from `docs/security-guidelines.md`.

### Cross-Reference Threat Model

For every threat in `US001.security-threat-model.md` marked as "required mitigation":
verify the mitigation is present in code. Flag any that are missing.

### Detailed Review Areas

* **Authentication** — token validation, expiry, replay protection, session invalidation
* **Authorization** — every endpoint has explicit auth; object-level checks; tenant isolation
* **Input validation** — bean validation on DTOs; size limits; sanitisation
* **Injection** — parameterised queries only; no string concatenation into JPQL or SQL
* **Sensitive data** — no PII / tokens in logs, error messages, DTOs, URLs, or query params
* **Secrets** — no hardcoded credentials; config from env vars only
* **Cryptography** — algorithm, key length, randomness source (`SecureRandom`, not `Math.random`)
* **Rate limiting** — unauthenticated endpoints have throttling applied before controller code
* **Frontend** — no `innerHTML` with user content, `DomSanitizer` usage, dependency vulns

### Dependency Scans (run both, include output in report)

```bash
cd nexus-backend && ./mvnw dependency:check
cd nexus-frontend && npm audit --audit-level=moderate
```

---

For every finding use the same format as `/review`.
Add: `OWASP category` (e.g., A01, A03) for security-specific findings.

End with a verdict: `APPROVED` / `APPROVED WITH FOLLOW-UP` / `BLOCKED`

A **Blocker** finding is a release-stopper. Fix and re-run `/security-scan` before proceeding.

---

**Output:** `US001.security-review.md`

---

# Phase: /test-validate

**Agent:** `qa-engineer`

Prerequisites:
* `/review` verdict: `APPROVE` or `APPROVE WITH NITS`
* `/security-scan` verdict: `APPROVED` or `APPROVED WITH FOLLOW-UP`

Read `docs/testing-standards.md` before starting.

## Audit Existing Tests

Map every test to the source file it covers. Identify coverage by layer.

## Coverage Targets

| Layer | Target |
|-------|--------|
| `domain/` | ≥ 90% |
| `application/` | ≥ 85% |
| `infrastructure/` | ≥ 70% |
| `interfaces/rest/` | ≥ 80% |
| Angular components | ≥ 80% |
| Angular services | ≥ 85% |

## Gap Analysis

For each gap identify severity (High / Medium / Low) and add a test to close it.

Required coverage areas:

### Backend
* Unit tests (JUnit 5 + Mockito, no Spring context): every use-case service, domain logic
* Slice tests (`@WebMvcTest` for controllers, `@DataJpaTest` for repositories)
* Integration tests (`@SpringBootTest` + Testcontainers MySQL — **never H2**): full flows, error paths, concurrency (where applicable)
* Security tests: each role × each endpoint; IDOR checks; auth boundary tests
* Timing parity tests: where enumeration prevention is in scope

### Frontend (Vitest)
* Every component state: loading, success, empty, error
* Every state machine transition
* Every form validation path (valid, invalid, boundary values)
* Service error transformation

### Regression Tests
Verify pre-existing critical flows still pass:
* Login / logout
* Any flow that touches the same tables or services as this feature

### Load Tests
For any endpoint expected to handle > 10 RPS, add a k6 or Gatling scenario to `nexus-backend/src/test/load/`.

Targets:
* Read endpoints: p95 < 200 ms at 100 RPS
* Write endpoints: p95 < 500 ms at 50 RPS
* Error rate < 0.1%

### Run the full suite

```bash
cd nexus-backend && ./mvnw test
cd nexus-frontend && npm test -- --run
```

Paste results. **Do not declare done with red tests.**

## Output Format

```
## Coverage Audit — US001

### Existing tests (before this phase)
### Gaps identified (severity + resolution)
### Tests added (list of new test methods)
### Run results (pass/total for backend and frontend)
### Load test results (p50/p95/p99/error rate per endpoint)
### Flaky tests (if any — with explanation)
```

---

**Output:** `US001.test-validation.md`

---

# Phase: /docs

No specific agent required — use the main context, reading the design artifacts.

Read all design artifacts for this feature before generating documentation.

Generate:

### Technical Overview
What was built, why, key design decisions, cross-references to design docs.

### API Documentation
Verify OpenAPI annotations (`@Operation`, `@ApiResponse`, `@Schema`) are on every new controller and DTO. Document each endpoint: method, path, auth, request, response, error codes.

### Architecture Updates
If any architectural decision was made that wasn't in the original design, write an ADR in `docs/adr/NNNN-<title>.md` using the standard format (Context / Decision / Alternatives Considered / Consequences).

### Deployment Guide
* Environment variables added (name, source, required/optional, default)
* Config property changes
* Schema changes (additive: confirm ddl-auto handles it; non-additive: migration steps)
* Feature flag name, default per environment, rollout plan

### Rollback Plan
* Code rollback: previous artifact identifier
* DB rollback: what is reversible, what is not
* Feature flag kill switch: how to disable without redeployment
* Cache invalidation (if applicable)

### Monitoring Guide
* Dashboards to watch (links)
* Key metrics with baselines and alert thresholds
* Log queries for new code paths
* Audit events emitted

### Runbook
Operational scenarios the on-call engineer will encounter:

For each scenario:
* Symptom
* Likely causes
* Diagnostic steps
* Resolution

Minimum scenarios: feature appears slow, users report errors, email/notification not delivered (if applicable).

### Update CHANGELOG.md
Add entry under `[Unreleased]` with a summary of the feature.

---

**Output:** `US001.implementation-docs.md` (plus any new ADR and CHANGELOG update)

---

# Phase: /release-prep

**Agent:** `release-manager`

Prerequisites — all of these must exist with green status:
* `US001.review-report.md` — verdict `APPROVE` or `APPROVE WITH NITS`
* `US001.security-review.md` — verdict `APPROVED` or `APPROVED WITH FOLLOW-UP`, no unresolved Blockers
* `US001.test-validation.md` — all tests passing, coverage targets met
* `US001.implementation-docs.md` — complete

Read `docs/deployment-process.md` before producing checklists.

Produce four sections, all in `US001.release-preparation.md`:

### 1. Deployment Checklist

Pre-deploy → During → Post-deploy.
Every item has an owner (use `[ASSIGN: <role>]` where not yet known).
Concrete steps only — no vague "verify things look good."

Include:
* CI all-green confirmation
* DB schema changes verified in staging
* Feature flag confirmed OFF in production config
* Secrets / env vars added (names only, not values)
* On-call notified, runbook linked
* Rollback tested in staging
* Communication sent to stakeholders

### 2. Rollback Checklist

* Trigger conditions — specific metrics or error thresholds that mandate rollback, no deliberation
* Decision owner
* Code rollback steps (previous artifact ID)
* DB rollback strategy (and what is irreversible)
* Feature flag kill switch instructions
* Cache invalidation (if applicable)
* Communication plan
* Post-rollback: incident ticket, post-mortem owner

Target: rollback complete in < 10 minutes.

### 3. Smoke Test Checklist

Manual + automated tests run immediately after deploy:
* Healthcheck endpoint
* Pre-rollout: feature flag OFF, existing flows unaffected
* Post-rollout: happy-path user journey for the new feature
* Error and empty state paths
* Metrics and audit events flowing in Grafana
* Confirmation no raw tokens / PII visible in logs

### 4. Production Readiness Verdict

Answer every question:

* SLOs defined (availability, latency, error rate)?
* Load test results meet SLO targets?
* Rollback tested in staging?
* Security review signed off?
* All threat model mitigations verified in code?
* Feature flag defaulting to OFF in production?
* Dashboards and alerts configured?
* Runbook written?
* On-call rotation aware of the feature?
* Privacy / accessibility / i18n complete (where applicable)?

**Conclude with a single verdict:**

`READY` / `READY WITH CAVEATS` / `NOT READY`

With explicit reasoning. If `NOT READY`, list blockers and stop. Do not proceed to deployment.

---

**Output:** `US001.release-preparation.md`

---

# Phase: /retro

**Run 24–48 hours after the feature reaches 100% production rollout.**

No specific agent required.

## Observability Validation

Walk through the monitoring guide in `US001.implementation-docs.md` and confirm:
* All declared metrics are flowing (check `/actuator/prometheus`)
* All audit events are in the audit log
* Dashboards render correctly
* Alerts have behaved as expected (fired when they should, not when they shouldn't)

## Production Health

Compare against pre-deploy baseline:
* Error rate — overall and feature-specific
* p95 / p99 latency — overall and feature-specific
* Throughput
* Resource utilisation (DB pool, memory, CPU)
* Feature-specific success metrics from `US001.business-analysis.md`

Note any deviations and whether they are within acceptable bounds.

## Lessons Learned

Document:

* What went well — specific, not generic
* What went poorly — with root cause
* Surprises in production — anything not predicted by the design or load tests
* Workflow phase that needed more time
* Workflow phase that was over-engineered

## Convention Updates

If new patterns or anti-patterns were discovered, update:
* `docs/coding-standards.md`
* `docs/security-guidelines.md`
* `docs/testing-standards.md`
* `docs/architecture.md`
* `.claude/agents/*.md` (if an agent prompt needs correction)
* `.claude/skills/*/SKILL.md` (if a skill doc needs updating)
* `CLAUDE.md` (if a project-wide convention changed)

List every file updated.

---

**Output:** `US001.retrospective.md`

---

# Completion Gate

Implementation is not complete until every item is checked:

```
[ ] All tasks in US001.task-breakdown.md implemented
[ ] All tests passing — backend and frontend
[ ] Coverage targets met for all layers
[ ] /review verdict: APPROVE or APPROVE WITH NITS (all nits resolved)
[ ] /security-scan verdict: APPROVED or APPROVED WITH FOLLOW-UP (no unresolved Blockers)
[ ] /test-validate: load test results meet SLO targets
[ ] /docs: all documents complete, CHANGELOG updated
[ ] /release-prep verdict: READY or READY WITH CAVEATS (caveats tracked in tickets)
[ ] /retro: production health confirmed, convention updates applied
```

---

# Final Deliverables

This workflow produces:

* `US001.review-report.md`
* `US001.security-review.md`
* `US001.test-validation.md`
* `US001.implementation-docs.md`
* `US001.release-preparation.md`
* `US001.retrospective.md`

Plus (if applicable):
* `docs/adr/NNNN-<title>.md`
* `CHANGELOG.md` (updated)
