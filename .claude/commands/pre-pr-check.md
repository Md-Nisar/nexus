---
description: Run all local quality gates + Definition of Done before opening a PR.
argument-hint: (none)
---

Run the **pr-checklist** skill against the current branch. This is the gate to clear before opening a pull request; it mirrors what CI enforces, so green here means green in CI.

1. Determine scope from `git diff --name-only origin/main...HEAD`.
2. Run the backend gates (`./mvnw verify -DskipITs`, and full `verify` if Docker is up) when `nexus-backend/src` changed.
3. Run the frontend gates (`format:check`, `lint`, `test:ci`, `build`, and `e2e` if UI changed) when `nexus-frontend/src` changed.
4. Walk the Definition of Done.
5. Report every gate as PASS/FAIL with failing output. If anything is red, list concrete fixes and **do not** advise opening the PR.

Do not modify code as part of this command — it reports. Fix failures in a separate step, then re-run.
