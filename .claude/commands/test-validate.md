---
description: Phase 8 — Test coverage audit and gap-fill.
argument-hint: <JIRA-ID>
---

Use the **qa-engineer** sub-agent to audit and improve test coverage for feature `$1`.

Steps:

1. Identify changed source files in the feature branch.

2. Audit existing tests covering those files. Map test → source.

3. Identify gaps across:
   - Happy path
   - Edge cases (empty, null, boundary values)
   - Error paths (each thrown exception, each error response)
   - Authorization (each role × each endpoint)
   - Concurrent access (where relevant)
   - Frontend: loading / error / empty states

4. Add missing tests, one logical addition at a time. Follow:
   - Backend: JUnit 5 + Mockito for unit; `@SpringBootTest` + Testcontainers MySQL for integration.
   - Frontend: Vitest + Angular TestBed.

5. Add load test scenarios (Gatling or k6) for endpoints expected to see >10 RPS. Save to `nexus-backend/src/test/load/`.

6. Run the full suite:
   ```bash
   cd nexus-backend && ./mvnw test
   cd nexus-frontend && npm test
   ```

7. Flag any flaky tests (timing-dependent, ordering-dependent, external-state-dependent).

8. Save the audit report to `docs/features/$1/08-test-audit.md` using the qa-engineer's output format.

9. Print to chat: gaps closed, current pass rate, flaky tests (if any).

Do not declare done with red tests.
