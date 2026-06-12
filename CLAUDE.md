# CLAUDE.md

Guidance for Claude Code (claude.ai/code) in this repository. This is a **map and index** — each topic below links to its single source of truth. Don't duplicate that content here.

## Project map

Nexus is a **modular monolith**:
- **`nexus-backend/`** — Spring Boot 4, Java 25, Maven, Spring Data JPA, MySQL, Flyway, hexagonal architecture.
- **`nexus-frontend/`** — Angular 21, TypeScript 5.9 (strict), standalone components, signals, Vitest, Playwright.
- **`docs/`** — standards (`coding-standards`, `observability-standards`, `deployment-process`), ADRs, and `features/<ID>/` artifacts.
- **`story/`** — epic/story inputs (e.g. `story/S1-authentication/`) that feed `/new-feature`.
- **`.claude/`** — agents, commands, skills, and enforcement hooks (see `.claude/README.md`).

## Documentation index (single source of truth per topic)

| Need | Read |
|------|------|
| How to build/run/test, **the mandatory operating model**, enforcement | [DEVELOPMENT_GUIDE.md](DEVELOPMENT_GUIDE.md) |
| System design, layering, non-negotiables | [ARCHITECTURE.md](ARCHITECTURE.md) |
| Test strategy & coverage gates | [TESTING.md](TESTING.md) |
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

Full reference: **DEVELOPMENT_GUIDE.md → The Operating Model**. Front door: **`/new-feature <FEATURE-ID>`** → discovery → requirements (Gate 1) → impact → design + API/DB + threat model (Gate 2) → tasks (Gate 3) → implement (test-first) → `/review` → `/security-review` → `/test-validate` → `/docs` → `/release-prep`. Run **`/pre-pr-check`** before any PR. Artifacts: numbered files in `docs/features/<ID>/` (see `docs/README.md`). A quick fix doesn't need the full model — substantial features do.

## Critical conventions (full list: ARCHITECTURE.md → Non-negotiables)

- Backend package root is **`com.example.nexus.<context>`** with `domain / application / infrastructure / interfaces` layers; inner layers never import outer (ArchUnit-enforced). Constructor injection only; `@Transactional` on application services; never return JPA entities from controllers.
- **Flyway owns the schema** (`ddl-auto=validate`, ADR 0003) — append-only `V<N>__*.sql` migrations.
- Errors are **RFC 7807** problem documents with `code` + `traceId`; never leak internals.
- Frontend: standalone + signals + modern control flow (`@if`/`@for`); no `any`; HTTP only via interceptors (components see `AppError`, never `HttpErrorResponse`); config via `APP_CONFIG`.
- Integration tests (`*IT`) use **Testcontainers MySQL**, never H2; H2 serves only the no-Docker context smoke test (TESTING.md).

## Enforcement (gates fail automatically — DEVELOPMENT_GUIDE.md → How gates are enforced)

`.claude/settings.json` wires cross-platform **Node hooks**: `block-prod-commands.mjs` (Bash), `secret-scan.mjs` (Write/Edit), `format.mjs` (PostToolUse), `run-tests.mjs` (Stop). Permissions deny `git push`, `rm -rf`, `sudo`, and reads/writes of `.env*` / `application-prod.*`. Beyond Claude: `.githooks/pre-push`, CI workflows, and branch protection (`scripts/setup-branch-protection.sh` + `.github/CODEOWNERS`).

## MCP integrations (optional)

```bash
claude mcp add atlassian npx -- @atlassian/mcp-server   # Jira/Confluence for /analyze-story
claude mcp add github    npx -- @modelcontextprotocol/server-github
```
