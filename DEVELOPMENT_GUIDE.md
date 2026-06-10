# Development Guide

## Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| JDK | 25 (LTS) | Enforced by maven-enforcer |
| Maven | 3.9+ | Or use the wrapper `./mvnw` |
| Node.js | 24 LTS | CI uses 24; odd versions are not for production |
| Docker | Desktop / Engine | MySQL via compose; Testcontainers for `*IT` tests |

## First-time setup

```bash
git clone <repo> && cd nexus
docker compose up -d                      # MySQL 8.4 → localhost:3306 (db: nexus)
cd nexus-backend && ./mvnw verify -DskipITs   # compiles, unit tests, quality gates
cd ../nexus-frontend && npm ci && npm run test:ci
```

## Backend (`nexus-backend/`)

### Configuration profiles

| Profile | Use | Notes |
|---------|-----|-------|
| `dev` (default) | Local development | SQL logging on, DEBUG for `com.example.nexus` |
| `test` | `@SpringBootTest` smoke tests | H2 in-memory, Flyway off |
| `prod` | Production | ECS JSON logs, springdoc off, credentials from env only |

All environment-specific values use `${ENV_VAR:default}` in `application.yml`. Production requires `DB_URL`, `DB_USERNAME`, `DB_PASSWORD` — there are no prod defaults by design.

### Commands

```bash
./mvnw spring-boot:run                  # run (dev profile, :1000)
./mvnw test                             # unit tests only — no Docker needed
./mvnw verify                           # + integration tests (*IT, Testcontainers) + coverage gate
./mvnw verify -DskipITs                 # full quality gates without Docker
./mvnw verify -Pquality                 # + PMD
./mvnw -Psecurity dependency-check:check  # CVE scan (slow; set NVD_API_KEY)
./mvnw test -Dtest=GlobalExceptionHandlerTest                       # one class
./mvnw test -Dtest='GlobalExceptionHandlerTest#should_return404*'   # one method
```

### Database migrations

Flyway, `src/main/resources/db/migration`, named `V<N>__<snake_case_description>.sql`.
Append-only: never edit an applied migration — write a new one. Non-additive changes (rename/drop/type change) need an expand→contract two-step plan reviewed at design time. Hibernate runs `ddl-auto=validate`; if startup fails with a schema mismatch, you forgot a migration.

### Adding a bounded context

Create `com.example.nexus.<context>` with `domain/`, `application/`, `infrastructure/`, `interfaces/` packages. The ArchUnit suite (`HexagonalArchitectureTest`) picks it up automatically and fails the build on dependency-rule violations. Conventions: `.claude/skills/spring-boot-standards/SKILL.md`.

## Frontend (`nexus-frontend/`)

### Commands

```bash
npm start                # dev server :2000 (proxies nothing — dev API URL points at :1000)
npm test                 # Vitest, watch mode
npm run test:ci          # single run + coverage
npm run lint             # ESLint (angular-eslint flat config)
npm run format           # Prettier write
npm run e2e              # Playwright (first time: npx playwright install chromium)
npm run build            # production build
```

### Environments

`src/environments/environment.ts` (production values) is replaced by `environment.development.ts` in dev builds. Consume via the `APP_CONFIG` injection token — never import environment files in feature code, never hardcode URLs.

### Adding a feature

Follow `src/app/features/README.md`: pages/components/services/models per feature, lazy route registration in `app.routes.ts`, no cross-feature imports. Conventions: `.claude/skills/angular-standards/SKILL.md`.

## Docker

```bash
docker compose up -d                   # MySQL only
docker compose --profile full up -d    # MySQL + backend + frontend images
docker compose down -v                 # reset including data volume
```

Both Dockerfiles are multi-stage; the frontend image serves through nginx with `/api/` proxied to the backend service.

## Quality gates (what CI enforces)

| Gate | Where | Threshold |
|------|-------|-----------|
| Checkstyle | every build (validate phase) | 0 errors |
| Unit + integration tests | surefire (`*Test`) / failsafe (`*IT`) | all green |
| JaCoCo line coverage | `mvn verify` | ≥ 80% (config classes excluded) |
| SpotBugs | `mvn verify` | 0 findings |
| ArchUnit | unit test phase | hexagonal rule, no field injection, no `System.out` |
| Prettier + ESLint | frontend CI | clean |
| Vitest + Playwright | frontend CI | all green |

## The Operating Model (mandatory for feature work)

Every non-trivial change follows this model. It is enforced by approval gates (human) and by automated quality gates (machine — see the next section). A quick fix or typo does not need the full model; substantial features do. The single front door is **`/new-feature <FEATURE-ID>`**.

### Plan half — design before code (no implementation until Gate 3 passes)

| # | Step | Command | Agent / skill | Output | Gate |
|---|------|---------|---------------|--------|------|
| 0 | Discovery | `/new-feature` | `feature-discovery` skill | reuse-first survey, impact map, open questions | — |
| 1 | Requirements | `/analyze-story` | business-analyst | `01-requirements.md` | **Gate 1: requirements approved** |
| 2 | Impact analysis | `/impact-analysis` | architect | `02-impact.md` | — |
| 3 | Design + API + DB + threat model | `/design` | architect + security-reviewer | `03-design.md`, `03b-threat-model.md` | **Gate 2: architecture approved** |
| 4 | Task breakdown | `/breakdown` | architect + engineers + qa | `04-tasks.md` | **Gate 3: plan approved** |

**Design review covers, against the standards skills:**
- **API design** (`api-design` skill): REST shape, status codes, RFC 7807 errors, versioning, pagination, idempotency.
- **DB design** (ADR 0003): Flyway migration plan; additive vs expand/contract; indexes; audit columns; naming (`docs/coding-standards.md`).
- **Security** (`SECURITY.md`): STRIDE threat model; each threat → a mitigation task; authz/PII/tenant concerns.
- **Frontend** (`angular-standards`): routes, smart/dumb components, signal state, guards.

### Action half — build, prove, ship

| # | Step | Command | Agent | Output | Gate |
|---|------|---------|-------|--------|------|
| 5 | Implement (per task, test-first) | `/implement <ID> <TASK>` | backend/frontend-engineer | code + tests | per-task plan-mode approval |
| 6 | Code review | `/review` | code-reviewer (read-only) | `06-code-review.md` | `APPROVE` |
| 7 | Security review | `/security-review` | security-reviewer (read-only) | `07-security-review.md` | no Blockers |
| 8 | Test validation | `/test-validate` | qa-engineer | `08-test-audit.md` | coverage gates green |
| 9 | Documentation | `/docs` | — | `09-technical.md` | — |
| 10 | Release prep | `/release-prep` | release-manager | `10-release/` | verdict `READY` |
| 11 | Retro (post-deploy) | `/retro` | — | `retrospective.md` | — |

`/userstory-plan` and `/userstory-action` run each half as a batch. Before any PR: **`/pre-pr-check`**.

### Requirements summary
- **Discovery/analysis before coding** — Steps 0–2, reuse-first.
- **Architecture + API/DB + security review before coding** — Step 3, Gate 2.
- **Testing** — test-first in Step 5; coverage gates in `TESTING.md` enforced at Step 8 and CI.
- **Documentation** — Step 9 + update standards/ADRs when conventions change.
- **PR requirements** — `/pre-pr-check` green + Definition of Done (`CONTRIBUTING.md`) + Conventional Commit title + ≥1 code-owner approval.

## How gates are enforced (4 layers)

Standards are not just documented — they fail builds and block merges:

1. **Claude hooks** (`.claude/settings.json`, cross-platform Node `.mjs`): block prod-command/prod-file/secret writes (PreToolUse), auto-format frontend (PostToolUse), run affected unit tests at session end (Stop).
2. **Local git hook** (`.githooks/pre-push`): runs format/lint/tests for changed sides before a human push. Enable once: `git config core.hooksPath .githooks` (also in setup below).
3. **CI** (`.github/workflows/`): `mvn verify` (Checkstyle, per-layer JaCoCo, SpotBugs, ArchUnit, Testcontainers ITs), frontend format/lint/test/build/e2e, weekly OWASP+Trivy, Conventional-Commit PR-title check.
4. **Branch protection** (`scripts/setup-branch-protection.sh` + `.github/CODEOWNERS`): required status checks, ≥1 code-owner approval, resolved conversations, no force-push. A repo admin runs the script once.

### One-time local setup
```bash
git config core.hooksPath .githooks     # enable the pre-push gate
# (Claude Code reads .claude/settings.json automatically; no setup needed.)
```

## AI-assisted workflow

This repo is configured for Claude Code (`.claude/`): the operating model above as slash commands, per-role sub-agents (review agents are read-only), standards/workflow skills, and the enforcement hooks in `.claude/settings.json`. Map and conventions: `CLAUDE.md`; full `.claude` layout: `.claude/README.md`.
