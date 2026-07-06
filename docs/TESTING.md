# Testing Strategy

Single source of truth for testing. The `qa-engineer` agent audits coverage against this document.

## The test pyramid

```
        E2E (~5%)          Playwright (Chromium)
      Integration (~25%)   @SpringBootTest + Testcontainers · Angular TestBed
   Unit (~70%)             JUnit 5 + Mockito / Vitest
```

## Coverage requirements (enforced)

Per-layer JaCoCo rules run in `mvn verify` and **fail the build** when missed (not just documented):

| Layer | Target | Element |
|-------|--------|---------|
| `*.domain` | ≥ 90% line | JaCoCo PACKAGE rule |
| `*.application` | ≥ 85% line | JaCoCo PACKAGE rule |
| `*.interfaces.rest` | ≥ 80% line | JaCoCo PACKAGE rule |
| `*.infrastructure` | ≥ 70% line | JaCoCo PACKAGE rule |
| whole module | ≥ 80% line | JaCoCo BUNDLE floor |
| Angular components | ≥ 80% statement | Vitest coverage |
| Angular services | ≥ 85% statement | Vitest coverage |

Config classes and the application bootstrap are excluded from measurement (still reviewed). Layer rules pass automatically while a layer has no classes, so they activate as bounded contexts are added.

## Backend (`nexus-backend/`)

| Layer | Tooling | Naming | Runs in |
|-------|---------|--------|---------|
| Unit | JUnit 5 + Mockito + AssertJ — no Spring context | `*Test` | `mvn test` (surefire) — no Docker |
| Slice | `@DataJpaTest`, `@WebMvcTest` | `*Test` | `mvn test` |
| Architecture | ArchUnit (`HexagonalArchitectureTest`) | `*Test` | `mvn test` |
| Integration | `@SpringBootTest` + **Testcontainers MySQL 8.4** | `*IT` | `mvn verify` (failsafe) — needs Docker |

Conventions:
- Test method names: `should_<expected>_when_<condition>`, readable as a sentence.
- **AAA** structure with blank lines (Arrange / Act / Assert). One logical assertion per test.
- Builders/factories for test data (`TestUsers.active(email)`), not inline `new` with every field.
- **No `Thread.sleep`** — inject a `Clock` and control time, or use Awaitility for async.
- **No H2 for integration tests** — MySQL semantics differ. The only H2 usage is the `test` profile context-smoke test (`NexusBackendApplicationTests`), kept so `mvn test` works without Docker.
- Integration tests get a real MySQL via `TestcontainersConfiguration` (`@ServiceConnection` — no property plumbing) and run Flyway migrations for real.
- No Docker locally? `mvn verify -DskipITs` runs every other gate; CI always runs the full suite.

Tooling: JUnit 5, Mockito, AssertJ, Spring Boot Test slices (`@WebMvcTest`, `@DataJpaTest`), Testcontainers (MySQL), WireMock (external HTTP), Awaitility (async).

## Frontend (`nexus-frontend/`)

| Layer | Tooling | Location |
|-------|---------|----------|
| Unit / component | Vitest + Angular TestBed | `*.spec.ts` next to the source |
| E2E | Playwright (Chromium) | `e2e/*.spec.ts` |

Conventions:
- Standalone component testing: `TestBed.configureTestingModule({ imports: [TheComponent] })`.
- HTTP: `provideHttpClientTesting()` + `HttpTestingController` — never hit a real network.
- Mocks via `vi.fn()` / `vi.spyOn`; fake timers via `vi.useFakeTimers()` — never sleep in tests.
- Stable selectors: `data-testid` attributes.
- Cover every variant of a `ViewState` machine — the discriminated union makes missed states a compile error in templates and a review error in specs.
- E2E boots the dev server automatically (`playwright.config.ts` → `webServer`). First run: `npx playwright install chromium`.

## Commands

```bash
# Backend
./mvnw test                        # unit + slice + architecture tests
./mvnw verify                      # + integration tests + coverage gate (Docker required)
./mvnw verify -DskipITs            # everything except *IT
./mvnw test -Dtest=SomeTest        # single class

# Frontend
npm test                           # watch mode
npm run test:ci                    # single run + coverage
npm run e2e                        # Playwright
npx vitest run src/app/core        # single folder
```

## Load testing

For any endpoint expected to handle > 10 RPS, add a k6 (preferred) or Gatling scenario under `nexus-backend/src/test/load/`. Targets: read p95 < 200 ms @ 100 RPS; write p95 < 500 ms @ 50 RPS; error rate < 0.1% under normal load. Run against staging with production-like data, not local.

## Flaky tests

A flaky test is worse than no test — it destroys trust in the suite. If a test fails intermittently: quarantine it (skip + ticket), fix within one sprint, else delete. Common causes: `Thread.sleep`, non-deterministic ordering, shared mutable state, real clocks, unstubbed randomness.

## What CI runs

- **Backend CI:** `mvn clean verify` — Checkstyle, unit + integration (Testcontainers works on GitHub runners), per-layer JaCoCo gate, SpotBugs, ArchUnit.
- **Frontend CI:** `format:check`, `lint`, `test:ci`, production build, then Playwright E2E as a separate job.
