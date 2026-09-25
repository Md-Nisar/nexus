# Forbidden paths

The agent must never modify any of these. This list is the policy; enforcement is partial:

- `nexus-scripts/check_guardrails.py` (CI, `ai/*` branches) blocks most of it. It does
  **not** currently block `**/angular.json`, `**/tsconfig*.json`, `**/*.env*` or
  `nexus-frontend/src/environments/**` — for those, this file is the only guard.
- `.claude/settings.json` denies local edits to the self-governance paths
  (`.github/`, `.githooks/`, `nexus-scripts/`, `.mcp.json`, `.claude/settings.json`,
  `.claude/hooks/`) and env/prod config — not the rest.

Obey the whole list regardless of whether a tool would stop you.

## Self-governance - the agent must not widen its own limits
```
.github/**
.githooks/**
.claude/**
.agents/**
.codex/**
.mcp.json
nexus-scripts/**
scripts/**
sonar-project.properties
CODEOWNERS
```

## Tests - immutable, they are the verification signal
```
nexus-backend/src/test/**
**/*Test.java
**/*Tests.java
**/*IT.java
nexus-frontend/src/**/*.spec.ts
**/*.spec.ts
**/*.test.ts
```

## Dependencies and build - supply-chain surface
```
**/pom.xml
**/package.json
**/package-lock.json
**/angular.json
**/tsconfig*.json
```

## Data and infrastructure - not reversible by a simple revert
```
nexus-database/**
nexus-backend/src/main/resources/db/**
**/*.tf
**/Dockerfile
**/docker-compose*.yml
**/*.env*
```

## Security-sensitive
```
nexus-backend/src/main/**/security/**
nexus-backend/src/main/**/config/**
nexus-frontend/src/environments/**
```

## Generated & Build Artifacts
```
**/generated/**
**/*.generated.ts
**/target/**
**/dist/**
**/node_modules/**
```
