# Architecture — Nexus

## System Overview

```
┌─────────────────────────────────────────────────────────┐
│  Clients                                                │
│  Browser (Angular 21 SPA)  ·  Mobile (future)          │
└────────────────────────┬────────────────────────────────┘
                         │ HTTPS / JSON
┌────────────────────────▼────────────────────────────────┐
│  nexus-backend                                          │
│  Spring Boot 4 · Java 25 · port 1000                   │
│                                                         │
│  interfaces/rest   ← @RestController DTOs               │
│  application/      ← Use cases (services + ports)       │
│  domain/           ← Entities, value objects, rules     │
│  infrastructure/   ← JPA repos, external adapters       │
└────────────────────────┬────────────────────────────────┘
                         │ JDBC
┌────────────────────────▼────────────────────────────────┐
│  MySQL 8.x  (localhost:3306 / db: nexus)                │
└─────────────────────────────────────────────────────────┘
```

### Components

| Component | Tech | Port | Notes |
|-----------|------|------|-------|
| `nexus-frontend` | Angular 21, TypeScript 5.9, Vitest | 2000 | SPA, standalone components |
| `nexus-backend` | Spring Boot 4, Java 25, Maven | 1000 | REST API, auto-DDL |
| MySQL | MySQL 8.x | 3306 | dev: root/root, db: nexus |

---

## Hexagonal Architecture (Ports & Adapters)

The backend strictly follows hexagonal architecture. The dependency rule: **outer layers depend on inner layers; never the reverse.**

```
  ┌──────────────────────────────────────────────┐
  │  interfaces/ (HTTP, events)                  │  ← outer
  │   └── depends on → application/             │
  │  infrastructure/ (JPA, email, storage)       │  ← outer
  │   └── depends on → application/             │
  │  application/ (use cases, ports/interfaces)  │  ← middle
  │   └── depends on → domain/                  │
  │  domain/ (entities, value objects, rules)    │  ← inner — no deps
  └──────────────────────────────────────────────┘
```

### Layer responsibilities

**`domain/`**
- JPA `@Entity` classes (mutable, never returned from REST endpoints)
- Value objects (prefer Java records)
- Domain services for multi-entity logic
- Domain exceptions (`UserNotFoundException`, etc.)
- No Spring dependencies except JPA annotations

**`application/`**
- Use-case classes (e.g., `CreateUserUseCase`, `RequestPasswordResetUseCase`)
- Port interfaces (`UserRepository`, `EmailPort`) — defined here, implemented in infrastructure
- DTOs internal to use-case flows (command objects, results)
- `@Transactional` lives here, not in infrastructure or interfaces
- The layer that knows about business rules; does not know about HTTP or DB specifics

**`infrastructure/`**
- Spring Data JPA repository implementations
- Email adapters (JavaMail, SendGrid, etc.)
- File storage adapters
- Third-party API clients
- Implements ports declared in `application/`
- Uses Spring `@Component` / `@Service` / `@Repository`

**`interfaces/rest/`**
- `@RestController` classes
- Request / response DTOs (never return domain entities)
- Bean validation annotations on request DTOs
- Maps HTTP → application command → HTTP response
- No business logic

### Package naming

```
com.nexus.<bounded-context>.<layer>
e.g.:
com.nexus.users.domain.User
com.nexus.users.application.CreateUserUseCase
com.nexus.users.infrastructure.JpaUserRepository
com.nexus.users.interfaces.rest.UserController
com.nexus.users.interfaces.rest.dto.CreateUserRequest
```

---

## Bounded Contexts

| Context | Package root | Responsibility |
|---------|-------------|----------------|
| `auth` | `com.nexus.auth` | Login, JWT issuance, password reset, session management |
| `users` | `com.nexus.users` | User profiles, roles, preferences |
| `(future)` | `com.nexus.*` | Additional feature domains |

Contexts communicate through application-layer interfaces, not direct entity references. A `users` service never imports `com.nexus.auth.domain.*`.

---

## Cross-Cutting Concerns

| Concern | Mechanism | Location |
|---------|-----------|----------|
| Authentication | JWT (Bearer) validated by Spring Security filter | `infrastructure/security` |
| Authorization | `@PreAuthorize` on application services | `application/` |
| Error handling | `@RestControllerAdvice` → standard error shape | `interfaces/rest` |
| Logging | SLF4J + MDC fields (`traceId`, `userId`) | Throughout — inject logger |
| Tracing | W3C `traceparent`, propagated via filter | `infrastructure/web` |
| Validation | Bean validation on DTOs, `@Validated` on services | `interfaces/rest`, `application/` |
| Schema management | `ddl-auto=update` (additive only) | `nexus-backend/src/main/resources/` |

---

## Frontend Architecture

The Angular SPA communicates exclusively with the REST API. There is no server-side rendering.

```
nexus-frontend/src/app/
├── core/              # Singleton services, guards, interceptors, layout
├── shared/            # Reusable standalone components and pipes
├── features/          # Feature-scoped modules
│   ├── auth/          # Login, register, password reset
│   └── ...
└── api/
    └── types/         # Generated or hand-written API DTO types
```

**State management:** Signals (`signal()`, `computed()`, `effect()`). No NgRx unless a bounded context requires cross-feature shared state with complex derived state — justify with an ADR.

**HTTP:** `HttpClient` with interceptors for auth header injection and global error handling.

**Components:** Standalone only. `ChangeDetectionStrategy.OnPush` by default.

---

## API Contract

The frontend consumes the backend exclusively through the documented REST API. The source of truth is the OpenAPI spec generated by Springdoc at `/v3/api-docs`. The frontend uses typed DTOs that mirror the API spec; no `any`.

---

## Non-Negotiables

1. Inner layers never import outer layers.
2. Controllers never contain business logic.
3. Domain entities are never returned from REST endpoints.
4. `@Transactional` belongs in the application layer only.
5. Secrets never in code — only from environment variables or Vault.
6. All endpoints have explicit authentication and authorization declarations.
7. Tests use MySQL via Testcontainers — never H2.
8. No `any` in TypeScript.

---

## When to Write an ADR

Write an Architecture Decision Record whenever you:
- Introduce a new framework or significant library
- Deviate from hexagonal layering for a bounded context
- Choose between two meaningful architectural approaches
- Add a cross-cutting concern or middleware
- Change the schema migration strategy
- Decide to add a caching layer, message queue, or event store
