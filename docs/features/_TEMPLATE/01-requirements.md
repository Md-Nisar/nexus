<!-- Feature artifact template. Copy this folder to docs/features/<FEATURE-ID>/ when starting a
     feature, or let `/new-feature <FEATURE-ID>` create the artifacts. Numbered convention:
       01-requirements.md  02-impact.md  03-design.md  03b-threat-model.md  04-tasks.md
       06-code-review.md   07-security-review.md  08-test-audit.md  09-technical.md  10-release/
     Produced and gated per docs/DEVELOPMENT_GUIDE.md → The Operating Model. -->

# <FEATURE-ID> — <Feature name>: Requirements

**Status:** Draft · **Owner:** <name> · **Gate 1:** _pending approval_
<!-- On approval, replace the Gate 1 value with: approved <YYYY-MM-DD> by <approver>
     (checked by /pre-pr-check). -->

## Problem statement
<!-- One or two sentences: user outcome + business rule. -->

## Bounded context
<!-- Existing or new context (see docs/ARCHITECTURE.md). -->

## Non-goals
<!-- What this feature explicitly will not do. -->

## Reuse-first findings (from feature-discovery)
<!-- What already exists that we can reuse / extend, vs must create. -->

## Functional requirements
- FR1 …

## Non-functional requirements
- Security / PII / tenancy:
- Performance / scale — expected and peak RPS, p95 latency budget, data volume and growth:
- Hot path (peak > 10 RPS, or on every request)? yes/no — **yes** requires a load test in the owning slice in `04-tasks.md`:
- Observability (metrics, logs, audit events):

## Business rules & constraints

## Dependencies & assumptions

## Open questions (resolve before Gate 1 approval)
- Q1 …
