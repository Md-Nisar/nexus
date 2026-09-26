# nexus-test

Test suites that exercise Nexus **from the outside**, as a running system over HTTP, and live
beside the application rather than inside a module. Unit, integration and E2E tests stay with
their modules (`nexus-backend/`, `nexus-frontend/`; see [docs/TESTING.md](../docs/TESTING.md)).

| Suite | Tool | What it answers |
|-------|------|-----------------|
| [`performance-test/`](performance-test/) | [k6](https://grafana.com/docs/k6/latest/) | How does the running system behave under traffic: latency, error rate, throughput, recovery? |

## Why performance testing lives here

Several stories already carry performance acceptance criteria (for example the load rows in
`docs/story/1-authentication/EPIC-001.md`), but until now there was nowhere to run them. This
suite provides that foundation early, while the application is small, so that:

- the same tests run on a laptop and in GitHub Actions today, and against a dedicated performance
  environment later, **without being rewritten**, because the target is just `BASE_URL`;
- performance regressions are caught by an automated gate, not by users.

Start with [performance-test/README.md](performance-test/README.md).
