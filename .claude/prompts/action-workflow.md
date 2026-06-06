# Execute Nexus Action Workflow for {FEATURE_ID} - {FEATURE_NAME}

## Objective

Implement the approved design using the Nexus workflow.

Inputs:

* Approved Design Documents
* Approved Architecture
* Approved Task Breakdown

Feature:

{FEATURE_NAME}

Feature ID:

{FEATURE_ID}

---

# Preconditions

Verify all required artifacts exist:

* {FEATURE_ID}.business-analysis.md
* {FEATURE_ID}.impact-analysis.md
* {FEATURE_ID}.domain-design.md
* {FEATURE_ID}.solution-architecture.md
* {FEATURE_ID}.security-threat-model.md
* {FEATURE_ID}.api-design.md
* {FEATURE_ID}.database-design.md
* {FEATURE_ID}.frontend-design.md
* {FEATURE_ID}.task-breakdown.md

If any are missing, stop.

---

# Phase: /implement

Use:

* backend-engineer
* frontend-engineer

Implement tasks from:

{FEATURE_ID}.task-breakdown.md

Rules:

* Implement one task at a time
* Follow approved architecture
* Follow approved API design
* Follow approved database design
* Follow approved frontend design
* Follow all coding standards
* Reuse existing components
* Avoid unnecessary abstractions
* Avoid introducing technical debt

For every task:

Provide:

* Files modified
* Purpose
* Design alignment
* Risks

Run tests after each completed task.

---

# Phase: /review

Use:

* code-reviewer

Perform independent review.

Review:

* Architecture compliance
* Coding standards
* SOLID principles
* Maintainability
* Readability
* Reusability
* Performance
* Scalability

Produce:

{FEATURE_ID}.review-report.md

---

# Phase: /security-scan

Use:

* security-reviewer

Review:

* Authentication
* Authorization
* Input Validation
* Data Exposure
* Secrets Handling
* API Security
* OWASP Risks
* Multi-Tenant Risks

Produce:

{FEATURE_ID}.security-review.md

---

# Phase: /test-validate

Use:

* qa-engineer

Validate:

## Unit Tests

## Integration Tests

## API Tests

## UI Tests

## Security Tests

## Regression Tests

## Performance Tests

Verify acceptance criteria.

Produce:

{FEATURE_ID}.test-validation.md

---

# Phase: /docs

Generate:

* Technical Documentation
* API Documentation
* Architecture Updates
* Operational Notes

Produce:

{FEATURE_ID}.implementation-docs.md

---

# Phase: /release-prep

Use:

* release-manager

Prepare:

## Deployment Plan

## Rollback Plan

## Migration Plan

## Monitoring Plan

## Release Checklist

Produce:

{FEATURE_ID}.release-preparation.md

---

# Final Deliverables

Generate:

* {FEATURE_ID}.review-report.md
* {FEATURE_ID}.security-review.md
* {FEATURE_ID}.test-validation.md
* {FEATURE_ID}.implementation-docs.md
* {FEATURE_ID}.release-preparation.md

Implementation must not be considered complete until:

* All tasks completed
* All tests passing
* Security review passed
* Code review passed
* Documentation updated
* Release plan completed
