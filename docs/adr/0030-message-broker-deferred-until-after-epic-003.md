# ADR 0030 — Adopt a Message Broker (RabbitMQ) After EPIC-003, Not During It

**Status:** Proposed 2026-10-27
**Date:** 2026-10-27
**Decided by:** Md Nisar Ahmed (product owner), 2026-10-27
**Feature:** Platform infrastructure (sequencing decision across EPIC-003)
**Related:** ADR 0011 (audit retry buffer; §6 names the outbox upgrade path), ADR 0016 (Redis; D5 scopes Redis Streams away from general job queuing), ADR 0009 (audit writes survive rollback), ADR 0020 D5 (DB-lease job runner), EPIC-003 US-028 / US-038 / US-039 / US-046

## Context

Nexus is a modular monolith. Its asynchronous work today is small and in-process:

| Concern | Mechanism | Durability |
|---|---|---|
| Verification, password-reset and account-exists email | Spring event, `@TransactionalEventListener(AFTER_COMMIT)` plus `@Async` (`MailEventListener`) | Lost if the process dies between commit and send; users recover by resending |
| Audit writes during a store outage | Two-lane bounded in-memory buffer, up to 1000 events (ADR 0011) | Lost on crash; accepted in ADR 0011 §5 and observable |
| Scheduled work | Audit buffer drain (`@Scheduled`) | n/a |

EPIC-003 adds more asynchronous work: invitation email (US-028), the shared job runner for retention (US-046), tenant export (US-038) and tenant purge and erasure (US-039). None of these needs a broker. The epic already plans a database-lease job runner (ADR 0020 D5) that US-038 and US-039 reuse, and invitation email can be resent (US-028 AC4).

Adding a broker during EPIC-003 would also:

- add a second stateful dependency before the first, Redis, has run in any real environment (no environment exists yet; ADR 0016 amendment of 2026-10-18; `application-prod.yml` still lacks two required lines);
- attach infrastructure to US-021, the largest and riskiest story, which blocks every other story in the epic.

The real durability gap is that events are not recorded atomically with the business write. A broker alone does not close it, because the publish itself can fail after commit. ADR 0011 §6 already names a transactional outbox as the upgrade path.

## Decision

### D1 — RabbitMQ is adopted after EPIC-003, not during it

EPIC-003 ships without a broker. Its scope and story order are unchanged. This ADR is Proposed until the prerequisites in D3 are met, and is then re-confirmed at its own Gate 1.

### D2 — First consumers, in order

1. **Email.** The `MailEventListener` events (verification, password reset, account-exists) and the invitation email from US-028.
2. **Audit.** The ADR 0011 retry buffer, only after a MySQL transactional outbox exists. The outbox write stays in the business transaction (ADR 0009 still applies: denial events that must survive rollback keep `REQUIRES_NEW`); the broker is only the transport from the outbox. The audit write must never depend on broker availability.

Out of scope for the broker: the RBAC permission epoch and cache, rate limiting (all Redis, ADR 0016) and the US-046 DB-lease job runner.

### D3 — Prerequisites before adoption

- Redis is deployed and running in a real environment (ADR 0016 production prerequisites met).
- US-046's job runner has shipped, so real backlog data exists.
- A measured need: email loss or backlog, a second consumer of one event, or one of the triggers in D5.
- The failure-mode policy for each capability is stated up front (fail open, fail closed or fall back to the DB), per the ADR 0016 follow-on rule.
- A hexagonal boundary rule is added with the first use: broker client types (`org.springframework.amqp..`, `com.rabbitmq..`) stay in `infrastructure/`, enforced by ArchUnit as in ADR 0016 D6.

### D4 — Design constraint on EPIC-003 stories (effective now)

- Email and event publishing stay behind the existing ports (`MailSenderPort` and application events). New code must not call `@Async` directly for cross-request work or add a new in-process queue.
- Tenant-aware job work runs on the US-046 job runner, with the tenant set explicitly per unit of work (NFR-ISO-5).
- New durable-delivery requirements are recorded as outbox candidates, so the later swap changes the transport, not the callers.

### D5 — Triggers to revisit sooner

- Outbound webhooks or integrations, where per-consumer retry, backoff and dead-lettering are needed. SCIM (US-043) is the likely first case.
- A second deployable, or a worker split from the API.
- A measured email backlog or loss that in-process async cannot absorb.
- Several independent consumers of one domain event.
- Export or purge jobs long enough that the DB-lease runner becomes the bottleneck.

## Consequences

**Benefits:**
- EPIC-003 scope and its critical path are unchanged.
- No second unproven stateful dependency while the first is still undeployed.
- The decision is explicit, so the question does not return each sprint.
- Ports stay in place, so adoption later is a transport change.

**Trade-offs:**
- Until adoption, invitation email can be lost on a crash (recoverable by resend) and the ADR 0011 §5 audit loss window stays.
- Two migrations are likely later (email, then audit through the outbox), each with its own design and threat model.

## Alternatives Considered

| Option | Rejected because |
|---|---|
| Adopt RabbitMQ with US-021 or during EPIC-003 | Unproven need; couples a new dependency to the riskiest story; Redis not yet deployed |
| Use Redis Streams as the general queue | ADR 0016 D5 scopes Streams to RBAC invalidation only; Redis is a cache and coordination layer, not a system of record |
| Transactional outbox only, no broker | Valid and cheaper; it is a prerequisite for D2 item 2 anyway, and the broker is adopted when D5 triggers or fan-out appear |
| Kafka | Streaming scale and operational cost with no evidence of need |
