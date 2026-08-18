# Forbidden paths

The agent must never modify these. Duplicated in `.claude/settings.json` (deny)
and `nexus-scripts/check_guardrails.py` (CI enforcement). This file is documentation;
CI is the enforcement. If they disagree, CI wins.

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
