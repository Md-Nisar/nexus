# Architecture

## System overview

Nexus is a **modular monolith**: one Spring Boot backend organized into isolated bounded contexts, one Angular SPA organized into lazy-loaded features. Contexts are isolated by package convention (enforced with ArchUnit), so a future extraction to microservices is a deployment decision, not a rewrite.

```
Browser ──> nexus-frontend (Angular 21, :2000)
                 │  /api/** (correlation id attached per request)
                 ▼
            nexus-backend (Spring Boot 4, :1000)
                 │  JPA / Flyway
                 ▼
              MySQL 8.4
```

## Backend: hexagonal architecture (ADR 0002)

Each bounded context follows ports & adapters:

```
com.example.nexus.<bounded-context>
├── domain/          # Entities, value objects, domain services, domain exceptions
├── application/     # Use-case services, port interfaces, @Transactional boundary
├── infrastructure/  # JPA adapters, external clients — implements the ports
└── interfaces/
    ├── rest/        # @RestController + request/response DTOs
    └── events/      # Event listeners / publishers
```

**Dependency rule:** `domain` and `application` never import from `infrastructure` or `interfaces`. This is enforced at build time by `HexagonalArchitectureTest` (ArchUnit) — a violation fails the build, not just review.

### Cross-cutting platform (`com.example.nexus.common`, `…nexus.config`)

| Component | Responsibility |
|-----------|----------------|
| `CorrelationIdFilter` | Accepts/generates `X-Correlation-Id`, exposes it as MDC `traceId`, echoes it on responses |
| `GlobalExceptionHandler` | Maps all exceptions to RFC 7807 Problem Details with `code` + `traceId` extensions |
| `DomainException` hierarchy | `ResourceNotFoundException` → 404, `ConflictException` → 409, other domain rules → 422 |
| `SecurityConfig` | Stateless, default-deny; only health/info/docs endpoints are public |
| `OpenApiConfig` | springdoc metadata; spec at `/v3/api-docs`, UI at `/swagger-ui.html` (non-prod only) |

### Error contract

Every non-2xx response is an RFC 7807 problem document:

```json
{
  "status": 404,
  "detail": "User does not exist or you do not have access.",
  "code": "USER_NOT_FOUND",
  "traceId": "abc123-def456",
  "details": [ { "field": "email", "message": "must be a valid email" } ]
}
```

`code` is stable and machine-readable; `traceId` matches the server logs; `details` appears only on validation failures. See `.claude/skills/api-design/SKILL.md` for the full API standards.

### Persistence

- **Flyway owns the schema** (ADR 0003): versioned migrations in `src/main/resources/db/migration`, `ddl-auto=validate`.
- `open-in-view=false` — lazy loading never crosses the transaction boundary.
- Optimistic locking (`@Version`) on concurrently-written entities.

### Concurrency model

Virtual threads (`spring.threads.virtual.enabled=true`) — thread-per-request programming model with reactive-class scalability. Don't pool blocking work; just block.

## Frontend: feature-based architecture

```
src/app/
├── core/          # Singletons: config token, logger, HTTP interceptors
├── shared/        # Stateless reusables: types (AppError, ViewState), future UI components
├── features/      # One lazy-loaded folder per bounded context (see features/README.md)
├── app.config.ts  # Providers: router (+component input binding), HttpClient (+interceptors)
└── app.routes.ts  # Top-level routes — loadChildren per feature
```

- **State:** signals (`signal`/`computed`); service-held state exposed read-only. RxJS only at HTTP/event boundaries.
- **HTTP:** `correlationIdInterceptor` (end-to-end tracing) and `apiErrorInterceptor` (normalizes every failure to `AppError`) wrap all calls. Components never see `HttpErrorResponse`.
- **Config:** `APP_CONFIG` injection token backed by `src/environments/` (file replacement per build configuration). Feature code never imports environment files or hardcodes URLs.
- **Async view state:** `ViewState<T>` discriminated union — the compiler forces handling of loading/error/success in every template.

## Observability

| Signal | Mechanism |
|--------|-----------|
| Logs | SLF4J key=value; ECS JSON structured logging in prod (`logging.structured.format.console=ecs`) |
| Correlation | `X-Correlation-Id` from browser → nginx → backend MDC → response → problem document |
| Metrics | Micrometer + `/actuator/prometheus` |
| Health | `/actuator/health` with liveness/readiness probes (k8s-ready) |
| Tracing | OpenTelemetry-ready: adopt `micrometer-tracing-bridge-otel` + OTLP exporter when a collector exists; MDC key is already `traceId` |

## Enterprise readiness posture

| Concern | Status |
|---------|--------|
| API versioning | `/api/v1/...` URI versioning (api-design skill) — apply from the first controller |
| Multi-tenancy | Not implemented; design rule: tenant id comes from the auth token, never from request body/path |
| AuthN/AuthZ | Baseline default-deny; JWT auth module is the first platform feature (SECURITY.md roadmap) |
| Auditing | `created_at`/`updated_at` column convention; Hibernate Envers or event-sourced audit when required |
| i18n | Backend error `code`s are translation keys by design; Angular `@angular/localize` when first locale lands |
| Feature toggles | Start with `@ConditionalOnProperty` + config; adopt a flag service (e.g. Unleash) before cross-team usage |
| Horizontal scaling | Stateless backend (no HTTP session), externalized config, containerized — scale-out ready |
| Microservice extraction | Bounded contexts + ArchUnit-enforced boundaries make per-context extraction feasible |

## Non-negotiables

The `code-reviewer` and `architect` agents enforce these; ArchUnit and CI enforce what's mechanizable:

1. Inner layers (`domain`, `application`) never import outer layers (`infrastructure`, `interfaces`). *(ArchUnit-enforced)*
2. Controllers contain no business logic.
3. Domain entities are never returned from REST endpoints — map to response DTOs.
4. `@Transactional` belongs in the application layer only.
5. Schema changes are append-only Flyway migrations; `ddl-auto=validate` (ADR 0003). *(startup-enforced)*
6. Secrets only via environment variables / Vault — never in code. *(hook + permission-enforced)*
7. Every endpoint declares explicit authentication and authorization.
8. Integration tests use Testcontainers MySQL — never H2.
9. No `any` in TypeScript; modern control flow (`@if`/`@for`), not `*ngIf`/`*ngFor`. *(ESLint-enforced)*

## When to write an ADR

Any decision that constrains future work: new infrastructure, a cross-context contract, a schema-strategy change, a caching/queue/event-store addition, or a deviation from these defaults. Format and lifecycle: ADR 0001.
