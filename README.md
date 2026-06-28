# Nexus

Nexus is a modern enterprise application platform designed to provide a scalable, maintainable, and secure foundation for business applications.

| Module | Stack | Port |
|--------|-------|------|
| [`nexus-backend`](nexus-backend/) | Spring Boot 4 · Java 25 · MySQL · Flyway | 1000 |
| [`nexus-frontend`](nexus-frontend/) | Angular 21 · TypeScript 5.9 · Vitest · Playwright | 2000 |

## Quickstart

```bash
# 1. Database
docker compose up -d            # MySQL 8.4 on :3306 (db: nexus, root/root)

# 2. Backend
cd nexus-backend
./mvnw spring-boot:run          # http://localhost:1000  (Swagger: /swagger-ui.html)

# 3. Frontend
cd nexus-frontend
npm ci && npm start             # http://localhost:2000
```

Full containerized stack: `docker compose --profile full up -d`.

> **Building a feature?** Start with `/new-feature <FEATURE-ID>` in Claude Code — the mandatory operating model (discovery → design gates → test-first build → reviews) is in [DEVELOPMENT_GUIDE.md → The Operating Model](DEVELOPMENT_GUIDE.md).

## Everyday commands

| Task | Backend (`nexus-backend/`) | Frontend (`nexus-frontend/`) |
|------|---------------------------|------------------------------|
| Run | `./mvnw spring-boot:run` | `npm start` |
| Unit tests | `./mvnw test` | `npm test` |
| Full verify | `./mvnw verify` (needs Docker) | `npm run test:ci` |
| Lint / style | `./mvnw checkstyle:check` | `npm run lint` · `npm run format:check` |
| Extra analysis | `./mvnw verify -Pquality` | — |
| E2E | — | `npm run e2e` |

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) — system design, layering, conventions
- [DEVELOPMENT_GUIDE.md](DEVELOPMENT_GUIDE.md) — setup, profiles, tooling, **the operating model**, gate enforcement
- [TESTING.md](TESTING.md) — test strategy and coverage requirements
- [SECURITY.md](SECURITY.md) — security baseline and roadmap
- [docs/QUALITY_GATES.md](docs/QUALITY_GATES.md) — comprehensive overview of local, CI/CD, and scheduled quality & security gates
- [CONTRIBUTING.md](CONTRIBUTING.md) — branching, commits, PRs
- [docs/adr/](docs/adr/) — architecture decision records
- [docs/coding-standards.md](docs/coding-standards.md) — naming, formatting, forbidden patterns

## CI

- **Backend CI** (`maven.yml`) — build, Checkstyle, unit + integration tests (Testcontainers), per-layer JaCoCo coverage gates (see [TESTING.md](TESTING.md)), SpotBugs, ArchUnit; optional SonarQube job
- **Frontend CI** (`node.yml`) — format check, ESLint, Vitest with coverage, production build, Playwright E2E
- **PR Title** (`commit-lint.yml`) — Conventional Commit title check
- **Security Scan** (`security.yml`, weekly) — OWASP Dependency-Check, npm audit, Trivy (vulns + secrets)

Merges to `main` additionally require ≥1 code-owner approval and green required checks — `scripts/setup-branch-protection.sh` (run once by a repo admin).
