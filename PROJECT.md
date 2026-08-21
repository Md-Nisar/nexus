# PROJECT.md

Project structure, commands, and operating model for Nexus. See [CLAUDE.md](CLAUDE.md) for behavioral guidelines on how to work with Claude Code.

## Project Map

Nexus is a **modular monolith**:
- **`nexus-backend/`** — Spring Boot 4, Java 25, Maven, Spring Data JPA, MySQL, Flyway, hexagonal architecture.
- **`nexus-frontend/`** — Angular 22, TypeScript 6.0 (strict), standalone components, signals, Vitest, Playwright.
- **`docs/`** — standards (`coding-standards`, `observability-standards`, `deployment-process`), ADRs, and `features/<ID>/` artifacts.
- **`docs/story/`** — epic/story inputs (e.g. `docs/story/S1-authentication/`) that feed `/new-feature`.
- **`.claude/`** — agents, commands, skills, and enforcement hooks (see `.claude/README.md`).

## Documentation Index (Single Source of Truth per Topic)

| Need | Read |
|------|------|
| How to build/run/test, **the mandatory operating model**, enforcement | [DEVELOPMENT_GUIDE.md](docs/DEVELOPMENT_GUIDE.md) |
| System design, layering, non-negotiables | [ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| Test strategy & coverage gates | [TESTING.md](docs/TESTING.md) |
| Security baseline & standards | [SECURITY.md](SECURITY.md) |
| Branching, commits, PRs | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Naming, formatting, forbidden patterns | [docs/coding-standards.md](docs/coding-standards.md) |
| Code-level standards (auto-loaded skills) | `.claude/skills/{spring-boot-standards,angular-standards,api-design}` |

## Essential Commands

```bash
# Backend (nexus-backend/ — mvnw.cmd on Windows)
./mvnw spring-boot:run            # run on :1000
./mvnw verify -DskipITs           # all quality gates without Docker
./mvnw verify                     # + Testcontainers *IT (needs Docker)

# Frontend (nexus-frontend/)
npm start                         # dev server :2000
npm run test:ci                   # Vitest + coverage
npm run lint && npm run format:check

# DB: docker compose up -d   (MySQL :3306, db nexus, root/root)
```

## Operating Model (Do Not Skip for Features)

Full reference: **docs/DEVELOPMENT_GUIDE.md → The Operating Model**. Front door: **`/new-feature <FEATURE-ID>`** → discovery → Gate 1 (requirements) → impact → Gate 2 (design + threat model) → Gate 3 (tasks) → implement → review gates → `/pre-pr-check` before any PR. Quick fixes skip the full flow.

## Key Constraints (Full List: docs/ARCHITECTURE.md → Non-negotiables)

- **Layering**: Backend is `domain / application / infrastructure / interfaces`; inner layers never import outer (ArchUnit-enforced). Constructor injection only. Never return JPA entities from controllers.
- **Flyway owns the schema** — `ddl-auto=validate`, append-only migrations (ADR 0003).
- **Cross-context exceptions** live in `common.domain`, never in the originating context (allows `GlobalExceptionHandler` to import without layer violation).
- **Audit writes that must survive rollback** use `SecureEventService` with `@Transactional(propagation = REQUIRES_NEW)` (ADR 0009).
- **Anti-enumeration endpoints** (`/forgot`, `/resend-verification`) return the same HTTP status and body regardless of account existence; include a dummy operation to partially equalize timing. See `ForgotPasswordUseCase`.
- **Frontend permission gating is UX only** — backend's `@RequiresPermission` is the sole security boundary. `permissionGuard` must compose after `authGuard`, never alone.

## Enforcement

Quality gates are enforced locally via Claude hooks (`.claude/settings.json`), remotely via `.githooks/pre-push`, CI workflows, and branch protection. Full details: **docs/DEVELOPMENT_GUIDE.md → How gates are enforced**.
