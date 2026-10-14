# Capacity model (T3, T6)

Use this for any hot or transactional flow. **The numbers below are illustrative.** Use the story's own RPS and p95 budget from `01-requirements.md`, together with `docs/observability-standards.md` → SLOs.

## Virtual threads change the bound

`spring.threads.virtual.enabled=true` removes the thread pool as the limit on concurrent requests. The real limits become:
- the **DB connection pool**, which is HikariCP: 10 connections and a 30 s `connection-timeout` unless set explicitly;
- **CPU**;
- **memory** per in-flight request.

So any design that assumes "the thread pool caps concurrency" is wrong here.

## Connections per request

Write one line per flow in the design:

> Connections held per request: N (held during …) · Outbound calls inside the transaction: none / … · What bounds concurrency: …

**Nested connections deadlock.** Suppose an outer transaction holds connection 1 and then needs connection 2 (`REQUIRES_NEW`). With a pool of P connections, P concurrent requests each hold one connection and wait for a second. Nothing progresses until `connection-timeout`, and then they all fail.

To avoid this, do one of the following:
- keep one connection per request (record success events in the outer transaction; write failure events after rollback);
- bound concurrency upstream, below P/2, with a `Semaphore`;
- size the pool for the worst case, within MySQL `max_connections` ÷ the number of instances.

## Hold time sets throughput (Little's law)

Maximum transactions per second ≈ pool size ÷ connection hold time.

| Flow (illustrative) | Hold time | Pool 10 → max tx/s |
|---|---|---|
| Argon2 (~50 ms) inside the transaction | ~60 ms | ~165 |
| Argon2 outside the transaction | ~5 ms | ~2,000 |
| Redis call times out (2 s) inside the transaction | 2,000+ ms | ~5 |

Rules that follow from this:
- Keep CPU-heavy work (Argon2) and every outbound call (Redis, SMTP, HTTP) **outside** the transaction.
- Wrap only the DB work in `TransactionTemplate` or a narrower `@Transactional` method.

## Bound CPU and memory-heavy work

Put a `Semaphore` sized to the CPU core count around Argon2.
- Memory at peak is permits × Argon2 memory, which is 19 MiB per hash with the current settings.
- Without the semaphore, the connection pool is the only accidental bound, and raising the pool removes it.

## Fail-open paths need short timeouts

- When a dependency fails open (Redis cache, rate-limit store), the worst-case added latency is timeout × number of calls per request.
- Use 100–250 ms timeouts on fail-open paths, not the 2 s default.
- Add a simple "skip until T" breaker if the dependency is called on every request.

## Overload

Map pool or connection timeouts to **503 with `Retry-After`**, not to a generic 500. Clients and load balancers can then back off.

## Prove it

For a hot path, the `/breakdown` load test (k6) must run against the **shipped** pool configuration, not one enlarged for the test. It asserts the p95 budget from `01-requirements.md` at the stated RPS.
