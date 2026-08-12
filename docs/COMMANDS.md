# Project Commands Cheat Sheet

This document serves as a quick reference for all essential commands needed to build, run, test, and analyze the **Nexus** project locally.

## Backend (`nexus-backend/`)
*Note: On Windows, use `./mvnw.cmd`. On macOS/Linux, use `./mvnw`.*

| Task | Command | Description |
|---|---|---|
| **Run** | `./mvnw.cmd spring-boot:run` | Starts the Spring Boot backend on port 1000. |
| **Build** | `./mvnw.cmd clean package -DskipTests` | Compiles the code and builds the `.jar` without running tests. |
| **Test (Unit)** | `./mvnw.cmd test` | Runs only the unit tests (no Docker required). |
| **Test (Integration)** | `./mvnw.cmd verify` | Runs all tests including Integration Tests (`*IT`). **Requires Docker running** for Testcontainers. |
| **Fast Quality Gates** | `./mvnw.cmd verify -DskipITs` | Runs all static analysis and unit tests, skipping Docker-dependent integration tests. |
| **Run Sonar Scan** | `./mvnw.cmd verify sonar:sonar -Dsonar.projectKey=Md-Nisar_nexus -Dsonar.organization=md-nisar -Dsonar.host.url=https://sonarcloud.io -Dsonar.token=<TOKEN>` | Runs a local SonarQube analysis and pushes it to SonarCloud. |

---

## Frontend (`nexus-frontend/`)

| Task | Command | Description |
|---|---|---|
| **Install** | `npm install` | Installs all Node dependencies. |
| **Run** | `npm start` | Starts the Angular development server on port 2000. |
| **Test** | `npm run test:ci` | Runs Vitest tests and generates coverage reports. |
| **Lint** | `npm run lint` | Runs ESLint to identify code smells and style issues. |
| **Format Check** | `npm run format:check` | Verifies that Prettier formatting rules are met. |
| **Build** | `npm run build` | Builds the production-ready frontend bundle. |

---

## Database (Project Root)

| Task | Command | Description |
|---|---|---|
| **Start Database** | `docker compose up -d` | Starts the local MySQL database on port 3306 (database: `nexus`, root/root). |
| **Stop Database** | `docker compose down` | Stops and removes the database container. |

---

## Agent / Workflow Commands
When interacting with the AI agent, the following slash commands are available to streamline development workflows (as defined in `AGENTS.md`):

*   `/new-feature <FEATURE-ID>`: Bootstraps the discovery and requirements gates for a new feature.
*   `/pre-pr-check`: Runs the comprehensive pre-PR runbook of local quality gates before merging.
*   `/review`, `/security-review`, `/test-validate`: Specific review triggers for PR validation.
