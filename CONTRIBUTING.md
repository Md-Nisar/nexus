# Contributing

The authoritative style/standards reference is [docs/coding-standards.md](docs/coding-standards.md). This file covers process.

## Branches

```
feature/NEXUS-1234-short-description
bugfix/NEXUS-1235-what-was-broken
hotfix/NEXUS-1236-critical-thing
chore/NEXUS-1237-update-dependencies
```

`main` is protected: PRs only, checks green, ≥ 1 approval.

## Commits — Conventional Commits

```
<type>(<scope>): <short summary>

[optional body]
[footer: NEXUS-1234]
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `perf`, `security`.

## Pull requests

- One feature/bugfix per PR — no "while I was in there" changes.
- Description answers: what, why, how to test (screenshots for UI changes).
- All CI checks green **before** requesting review.
- Squash-merge features; merge commits only for release branches.

### Definition of done

- [ ] Tests written and green (`mvn verify` / `npm run test:ci`) — coverage gate passes
- [ ] Lint and format clean (`checkstyle` / `npm run lint && npm run format:check`)
- [ ] New endpoints follow the API standards (`.claude/skills/api-design/SKILL.md`)
- [ ] Schema changes are Flyway migrations (append-only)
- [ ] No secrets, no TODO/FIXME (open a ticket instead), no commented-out code
- [ ] Docs/ADR updated when the change constrains future work

## Review etiquette

Label comments: `[blocker]` · `[suggestion]` · `[nit]` · `[praise]`.
Reviewers and authors respond within one business day.

## Local quality loop

```bash
# Backend, before pushing
cd nexus-backend && ./mvnw verify -DskipITs

# Frontend, before pushing
cd nexus-frontend && npm run format && npm run lint && npm run test:ci
```
