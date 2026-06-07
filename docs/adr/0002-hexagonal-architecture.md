# ADR 0002 — Hexagonal Architecture for the Backend

**Status:** Accepted
**Date:** 2025-11-01
**Author:** Engineering Team

## Context

The Nexus backend started as a simple layered architecture (Controller → Service → Repository). As the codebase grew, business logic leaked into controllers, services became tightly coupled to Spring Data types, and testing required a full Spring context even for simple logic. We needed a more deliberate structure that kept the domain model pure, made testing easy, and isolated infrastructure concerns.

## Decision

We adopt **Hexagonal Architecture (Ports & Adapters)** for all bounded contexts in `nexus-backend`, with four layers:

```
interfaces/   → Handles HTTP (controllers, request/response DTOs)
application/  → Use cases, port definitions (interfaces), @Transactional
domain/       → Entities, value objects, domain services, domain exceptions
infrastructure/ → JPA implementations, external service adapters
```

The **dependency rule**: outer layers (`interfaces`, `infrastructure`) depend on inner layers (`application`, `domain`). The inner layers never import from outer layers.

Ports (interfaces) are defined in `application/`. Adapters (implementations) live in `infrastructure/` and are injected via Spring's IoC container. The application layer never imports a concrete JPA class.

## Alternatives Considered

**Traditional layered architecture (Controller → Service → Repository):**
- Simpler to start with.
- Tends to degenerate: business logic migrates to controllers or repositories. Domain objects become anemic. Infrastructure leaks upward.
- Ruled out because we already saw this happening.

**CQRS + Event Sourcing:**
- Powerful for audit trails and complex temporal queries.
- Adds significant operational and conceptual complexity.
- Nexus does not currently have requirements that justify this complexity.
- Ruled out: wrong tool for current scale. Revisit if audit requirements grow significantly.

**Microservices per bounded context:**
- Maximum isolation.
- Network latency, distributed transactions, operational overhead at current team size would be a net negative.
- Ruled out: monolith-first. The hexagonal structure keeps contexts loosely coupled within the monolith, so extraction is feasible later if needed.

## Consequences

Positive:
- Domain and application layers are testable without Spring context — fast unit tests.
- Infrastructure can be swapped (e.g., switch from JPA to JDBC) without touching the domain.
- Bounded contexts are isolated by package convention enforced in code review.
- Business logic is readable as use-case classes, not buried in service.java files.

Negative:
- More files for a simple CRUD feature — boilerplate for a port + adapter pair when a repository would suffice.
- Steeper learning curve for engineers unfamiliar with the pattern.
- Discipline is required — a single `@Autowired JpaUserRepository` in a domain class breaks the rule silently.

Mitigations:
- The `backend-engineer` agent enforces the pattern in every implementation.
- Code review (Phase 6) includes explicit convention-violation checks.
- A future ArchUnit test suite can enforce the dependency rule automatically.

Follow-on: Consider adding ArchUnit tests to `nexus-backend` to enforce import rules statically (ticket NEXUS-0042).
