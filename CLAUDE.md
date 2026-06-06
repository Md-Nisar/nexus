# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Nexus is a full-stack application with:
- **`nexus-backend`** — Spring Boot 4 REST API (Java 25, Maven, Spring Data JPA, MySQL)
- **`nexus-frontend`** — Angular 21 SPA (TypeScript 5.9, Vitest for testing)

## Backend Commands

All commands run from `nexus-backend/`:

```bash
# Run the application
./mvnw spring-boot:run

# Build (skip tests)
./mvnw clean package -DskipTests

# Run all tests
./mvnw test

# Run a single test class
./mvnw test -Dtest=SomeTestClassName
```

On Windows use `mvnw.cmd` instead of `./mvnw`.

**Prerequisites:** MySQL running on `localhost:3306` with database `nexus`, user `root`, password `root`. The app starts on **port 1000**.

## Frontend Commands

All commands run from `nexus-frontend/`:

```bash
npm start          # Dev server on port 2000 (ng serve)
npm run build      # Production build
npm test           # Run tests with Vitest
npm run watch      # Incremental dev build
```

## Architecture Notes

- **Backend** uses Spring Boot auto-DDL (`spring.jpa.hibernate.ddl-auto=update`) — schema is managed automatically from JPA entities. Active profile: `dev`.
- **Frontend** uses Angular standalone components (no NgModules). `App` is the root component; routing is configured in `app.routes.ts` and provided via `provideRouter` in `app.config.ts`.
- TypeScript strict mode is fully enabled including `strictTemplates` and `strictInjectionParameters`.
- Prettier is configured in `package.json` (100-char line width, single quotes, Angular HTML parser).
