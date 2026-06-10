# Testing

Moved — see the repository-level [TESTING.md](../TESTING.md) for the full strategy.

Backend quick reference:

```bash
./mvnw test              # unit + slice + ArchUnit — no Docker needed
./mvnw verify            # + *IT integration tests on Testcontainers MySQL (Docker required)
./mvnw verify -DskipITs  # all quality gates without Docker
```

- Unit/slice tests are named `*Test` and must not require Docker.
- Integration tests are named `*IT`, extend nothing, and import `TestcontainersConfiguration` for a real MySQL with Flyway applied.
- The H2 `test` profile exists only for the context-loading smoke test; never write integration tests against H2.
