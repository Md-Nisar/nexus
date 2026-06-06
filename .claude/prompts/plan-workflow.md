# Execute Nexus Claude Workflow for {FEATURE_ID} - {FEATURE_NAME}

## Objective

Execute the Nexus workflow for the provided feature.

Follow the workflow defined in:

* .claude/README.md

Feature Story:

{FEATURE_STORY_PATH}

This story is the source of truth.

---

# Feature Context

Analyze the feature from:

* Business perspective
* Product perspective
* Architecture perspective
* Security perspective
* Scalability perspective
* Operational perspective

Consider both current requirements and future platform evolution.

All architecture decisions must support enterprise-grade scalability, maintainability, extensibility, and security.

---

# Workflow Execution Rules

* Follow the Nexus workflow exactly.
* Use the appropriate agents defined in `.claude/agents`.
* Follow all standards defined in `.claude/skills`.
* Do not skip workflow phases.
* Do not generate implementation code.
* Do not create migrations.
* Do not create frontend code.
* Focus only on analysis, design, architecture, planning, and readiness.

Generate artifacts under:

{FEATURE_OUTPUT_PATH}

Naming convention:

{FEATURE_ID}.{artifact}.md

---

# Phase: /analyze-story

Use:

* business-analyst

Review the complete feature story.

## Requirements Analysis

Document:

* Functional Requirements
* Non-Functional Requirements
* Business Rules
* Constraints
* Dependencies
* Assumptions

## Domain Analysis

Identify:

* Core Domain
* Supporting Domains
* Generic Subdomains
* Bounded Contexts
* Aggregates
* Domain Events

## Gap Analysis

Identify:

* Missing requirements
* Ambiguities
* Future risks
* Scalability concerns
* Security concerns

## Clarification Questions

Generate questions only if required.

Output:

{FEATURE_ID}.business-analysis.md

---

# Phase: /impact-analysis

Use:

* architect

Analyze the entire codebase.

Identify:

## Existing Components

Relevant modules, services, entities, APIs, UI components, integrations, infrastructure components, and reusable assets.

## Impact Assessment

Determine:

* Components to reuse
* Components requiring modification
* Components requiring extension
* Technical debt implications
* Architectural risks

## Dependency Analysis

Identify:

* Upstream dependencies
* Downstream dependencies
* Cross-module impacts

Output:

{FEATURE_ID}.impact-analysis.md

---

# Phase: /design

Use:

* architect
* security-reviewer
* backend-engineer
* frontend-engineer

Produce complete enterprise-grade design.

---

## Domain-Driven Design

Identify:

* Aggregates
* Entities
* Value Objects
* Domain Services
* Domain Events
* Repository Boundaries

Ensure aggregate boundaries enforce business rules and prevent data leakage.

Generate:

* Domain Model
* Aggregate Design
* Bounded Context Diagram
* Domain Event Catalog

Output:

{FEATURE_ID}.domain-design.md

---

## Solution Architecture

Design:

* Application Architecture
* Service Architecture
* Integration Architecture
* Deployment Considerations
* Scalability Strategy
* Reliability Strategy

Generate:

* Architecture Diagrams
* Component Diagrams
* Sequence Diagrams

Output:

{FEATURE_ID}.solution-architecture.md

---

## Security Threat Model

Analyze:

* Authentication Risks
* Authorization Risks
* Data Leakage Risks
* Privilege Escalation Risks
* API Abuse Risks
* Infrastructure Risks
* Multi-Tenant Risks (if applicable)

For each threat provide:

* Severity
* Impact
* Mitigation
* Residual Risk

Output:

{FEATURE_ID}.security-threat-model.md

---

## API Design

Design:

* REST APIs
* Request DTOs
* Response DTOs
* Validation Rules
* Error Handling
* Pagination
* Filtering
* Sorting
* Versioning

Generate:

* OpenAPI Design
* API Contracts

Output:

{FEATURE_ID}.api-design.md

---

## Database Design

Design:

* Tables
* Relationships
* Constraints
* Indexes
* Foreign Keys
* Audit Requirements
* Migration Strategy

Generate:

* ERD
* Data Dictionary

Output:

{FEATURE_ID}.database-design.md

---

## Frontend Design

Analyze existing frontend architecture.

Design:

### User Experience

* User Flows
* Navigation
* Information Architecture
* Accessibility
* Responsive Behavior

### User Interface

Design elegant, clean, modern, and consistent UI/UX using existing design systems and UI libraries wherever possible.

### Frontend Architecture

Design:

* Routes
* Pages
* Components
* State Management
* Guards
* Permissions
* API Integration Strategy

Output:

{FEATURE_ID}.frontend-design.md

---

## Future Compatibility Review

Validate architecture against future platform growth.

Assess compatibility with:

* Authentication
* Authorization
* User Management
* Role Management
* AI Platform
* Analytics
* Dashboards
* Reports
* Files
* Integrations
* Notifications
* Billing
* Future Modules

Identify future risks and recommendations.

Include in:

{FEATURE_ID}.solution-architecture.md

---

# Architecture Approval Gate

STOP.

Do not proceed until approval is received.

Provide:

## Executive Summary

## Key Architectural Decisions

## Tradeoff Analysis

## Risks

## Open Questions

## Implementation Readiness Assessment

Checklist:

* [ ] Requirements Complete
* [ ] Domain Design Complete
* [ ] Solution Architecture Complete
* [ ] Security Design Complete
* [ ] API Design Complete
* [ ] Database Design Complete
* [ ] Frontend Design Complete
* [ ] Risks Identified
* [ ] Open Questions Resolved

Explicitly request architecture approval.

Do not continue without approval.

---

# Phase: /breakdown

After architecture approval.

Use:

* architect
* backend-engineer
* frontend-engineer
* qa-engineer

Create implementation plan.

Organize work as:

Epic
→ Story
→ Task

---

## Backend Tasks

## Frontend Tasks

## Security Tasks

## Testing Tasks

## Documentation Tasks

For every task provide:

* Description
* Dependencies
* Estimated Effort
* Risk Level
* Acceptance Criteria

Output:

{FEATURE_ID}.task-breakdown.md

---

# STOP

Do not execute:

* /implement
* /review
* /security-scan
* /test-validate
* /docs
* /release-prep
* /retro

Those phases are executed separately after approval.

---

# Deliverables

Generate only:

* {FEATURE_ID}.business-analysis.md
* {FEATURE_ID}.impact-analysis.md
* {FEATURE_ID}.domain-design.md
* {FEATURE_ID}.solution-architecture.md
* {FEATURE_ID}.security-threat-model.md
* {FEATURE_ID}.api-design.md
* {FEATURE_ID}.database-design.md
* {FEATURE_ID}.frontend-design.md
* {FEATURE_ID}.task-breakdown.md

No implementation.

No code generation.

No migrations.

No frontend development.

Architecture, design, analysis, and planning only.
