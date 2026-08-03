# CLAUDE.md

Guidance for Claude Code (claude.ai/code) in this repository. This is a **map and index** — each topic below links to its single source of truth. Don't duplicate that content here.

## Project map

Nexus is a **modular monolith**:
- **`nexus-backend/`** — Spring Boot 4, Java 25, Maven, Spring Data JPA, MySQL, Flyway, hexagonal architecture.
- **`nexus-frontend/`** — Angular 21, TypeScript 5.9 (strict), standalone components, signals, Vitest, Playwright.
- **`docs/`** — standards (`coding-standards`, `observability-standards`, `deployment-process`), ADRs, and `features/<ID>/` artifacts.
- **`docs/story/`** — epic/story inputs (e.g. `docs/story/S1-authentication/`) that feed `/new-feature`.
- **`.claude/`** — agents, commands, skills, and enforcement hooks (see `.claude/README.md`).

## Documentation index (single source of truth per topic)

| Need | Read |
|------|------|
| How to build/run/test, **the mandatory operating model**, enforcement | [DEVELOPMENT_GUIDE.md](docs/DEVELOPMENT_GUIDE.md) |
| System design, layering, non-negotiables | [ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| Test strategy & coverage gates | [TESTING.md](docs/TESTING.md) |
| Security baseline & standards | [SECURITY.md](SECURITY.md) |
| Branching, commits, PRs | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Naming, formatting, forbidden patterns | [docs/coding-standards.md](docs/coding-standards.md) |
| Code-level standards (auto-loaded skills) | `.claude/skills/{spring-boot-standards,angular-standards,api-design}` |

## Essential commands

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

## Operating model (do not skip for features)

Full reference: **docs/DEVELOPMENT_GUIDE.md → The Operating Model**. Front door: **`/new-feature <FEATURE-ID>`** → discovery → requirements (Gate 1) → impact → design + API/DB + threat model (Gate 2) → tasks (Gate 3) → implement (test-first) → `/review` → `/security-review` → `/test-validate` → `/docs` → `/release-prep`. Run **`/pre-pr-check`** before any PR. Artifacts: numbered files in `docs/features/<ID>/` (see `docs/README.md`). A quick fix doesn't need the full model — substantial features do.

## Critical conventions (full list: docs/ARCHITECTURE.md → Non-negotiables)

- Backend package root is **`com.example.nexus.<context>`** with `domain / application / infrastructure / interfaces` layers; inner layers never import outer (ArchUnit-enforced). Constructor injection only; `@Transactional` on application services; never return JPA entities from controllers.
- **Cross-context domain exceptions** (e.g. `AccountLockedException`) live in **`common.domain`**, not in the originating bounded context, so `GlobalExceptionHandler` in `common.web` can import them without violating layer rules.
- **Writes that must survive outer TX rollback** (e.g. audit events, security counters) belong in `SecureEventService` methods annotated `@Transactional(propagation = REQUIRES_NEW)`. If that write touches an entity the outer session already mutated in memory, use a JPQL bulk `UPDATE` (bypassing `@Version`) instead of `findById + save` — see ADR 0009.
- **Flyway owns the schema** (`ddl-auto=validate`, ADR 0003) — append-only `V<N>__*.sql` migrations.
- Errors are **RFC 7807** problem documents with `code` + `traceId`; never leak internals.
- Frontend: standalone + signals + modern control flow (`@if`/`@for`); no `any`; HTTP only via interceptors (components see `AppError`, never `HttpErrorResponse`); config via `APP_CONFIG`.
- Integration tests (`*IT`) use **Testcontainers MySQL**, never H2; H2 serves only the no-Docker context smoke test (docs/TESTING.md).
- **Anti-enumeration endpoints** (e.g. `/forgot`, `/resend-verification`) must return the same HTTP status and body regardless of account existence. The not-found path must perform a dummy CPU-equivalent operation (e.g. `tokenGenerator.generate()`) to partially equalise timing; document any residual DB round-trip delta in an inline comment. See `ForgotPasswordUseCase` for the canonical pattern.
- **MySQL has no partial/filtered unique index** (no Postgres-style `CREATE UNIQUE INDEX ... WHERE ...`). For a "unique among active rows only" invariant, use a `STORED` generated column that evaluates to `NULL` for inactive rows and a deterministic value for active ones, then a plain `UNIQUE INDEX` on it — MySQL never treats two `NULL`s as duplicates. See ADR 0013 D2 / `user_roles.active_key`.
- **Hibernate rejects an `AttributeConverter` on `@IdClass` composite-key attributes**, even an explicit one. Use `@EmbeddedId` instead for any converter-backed (e.g. `UuidV7Converter`-mapped) composite key. See `rbac/domain/RolePermissionId.java`.
- **This project's pinned Hibernate version rejects HQL's `FUNCTION('now', N)` construct** at repository-proxy-creation time (`"Function now() has 0 parameters, but 1 arguments given"`) — its registered `now` function template takes no arguments, even though `FUNCTION('now', 6)` is valid MySQL. For a DB-side, microsecond-precision "now" in a JPQL bulk `UPDATE`, compute the timestamp app-side instead (e.g. `Instant.now()`, clamped against an already-loaded reference instant to satisfy any `CHECK` constraint ordering) and bind it as a parameter. See `rbac/infrastructure/persistence/JpaUserRoleRepository.java`'s `revokeById` (M6) and `RoleAssignmentService.revoke`'s `max(now, assignedAt)` clamp.
- **A JPA adapter that must synchronously translate a `DataIntegrityViolationException` into a domain exception** (e.g. a TOCTOU-guarded unique-constraint pre-check backed by an `INSERT`) needs `saveAndFlush()`, not `save()`. A plain `save()` only queues the INSERT in Hibernate's persistence context; if any later call in the same transaction (e.g. a re-read of the just-inserted row) triggers the auto-flush instead, the constraint violation surfaces one call frame away from the adapter's own `try/catch`, escaping translation entirely and producing an unhandled 500 instead of a clean 409. See `rbac/infrastructure/persistence/JpaUserRoleAssignmentAdapter.assign()`.

## Enforcement (gates fail automatically — docs/DEVELOPMENT_GUIDE.md → How gates are enforced)

`.claude/settings.json` wires cross-platform **Node hooks**: `block-prod-commands.mjs` (Bash), `secret-scan.mjs` (Write/Edit), `format.mjs` (PostToolUse), `run-tests.mjs` (Stop). Permissions deny `git push`, `rm -rf`, `sudo`, and reads/writes of `.env*` / `application-prod.*`. Beyond Claude: `.githooks/pre-push`, CI workflows, and branch protection (`scripts/setup-branch-protection.sh` + `.github/CODEOWNERS`).

## MCP integrations (optional)

```bash
claude mcp add atlassian npx -- @atlassian/mcp-server   # Jira/Confluence for /analyze-story
claude mcp add github    npx -- @modelcontextprotocol/server-github
```
