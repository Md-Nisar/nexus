# US-009 — Monitoring Checklist

_Phase 10 (`/release-prep`) deliverable. Builds on `monitoring.md`. This story ships zero runtime code (`03-design.md` §7 — explicit N/A for controllers, use-cases, application services). Building a dashboard or alert set for a schema-only change would be theater — this checklist is deliberately short and says so explicitly rather than padding it with fabricated metrics._

---

## Dashboards to watch

- **None new.** No dashboard exists or is warranted for this story specifically. **Do not create one in isolation** — fold any RBAC-specific panels into the dashboard built for US-010/US-011, once real query volume and a permission-check hot path exist (`monitoring.md`).
- [ ] Confirm the platform's existing general application dashboard (whatever currently tracks boot health / error rate / restart events) is being watched through the deploy window, as a generic regression signal — **not** an RBAC-specific one. — **Owner: [ASSIGN: DevOps/SRE on-call]**

## Key metrics with baseline + alert thresholds

- **None apply to this story's own surface** — there is no RBAC request path to measure latency/error-rate/throughput against. Do not invent placeholder thresholds.
- The **one metric worth tracking generically** (not RBAC-specific): overall application error rate and boot-restart count in the hour surrounding this deploy, against the environment's existing baseline/alerting (whatever that already is for any deploy). — **Owner: [ASSIGN: DevOps/SRE on-call]**

## Log queries for the new code paths

- **N/A — no new code path executes.** No controllers, use-cases, or services in this diff emit any log line (`monitoring.md`). The only relevant log signal is Flyway's own migration-application log (`Successfully applied N migrations` / `FlywayException`), which is a **deploy-time** signal, not an ongoing log query. — **Owner: [ASSIGN: DevOps/DBA]** (check once, at deploy time, per `deployment-checklist.md`)

## On-call rotation contact

- [ ] Confirm the standard on-call rotation is aware a schema migration is landing (routine notification — no special RBAC-specific escalation path exists, since there's no runtime surface to page on). — **Owner: [ASSIGN: Release Manager]**
- **On-call contact:** [ASSIGN: on-call rotation — use whatever the standing platform on-call schedule is; no RBAC-specific contact exists yet]

## Watch period

- **24 hours**, aligned to the standard post-deploy watch window for any schema migration in this platform — not the typical 24–48h "new feature traffic" window, since there is no traffic to this feature. The watch during this period is generic (app stability, no restart loops, no unexpected error-rate change), not RBAC-specific. — **Owner: [ASSIGN: DevOps/SRE on-call]**

---

## The ONE thing actually worth confirming post-deploy (do this, not a fabricated metrics dashboard)

- [ ] **Tables exist.** `SHOW TABLES LIKE '%role%'` / `information_schema.tables` confirms all 4 (`permissions`, `roles`, `role_permissions`, `user_roles`) present in the target schema. — **Owner: [ASSIGN: QA Engineer / DevOps]**
- [ ] **Seed data is correct.** `SELECT COUNT(*) FROM permissions` = 7; `SELECT COUNT(*) FROM roles WHERE is_system_role = TRUE` = 2; `SELECT COUNT(*) FROM role_permissions` = 8; join query confirms `TENANT_ADMIN` → all 7 permissions, `MEMBER` → `user:read` only. — **Owner: [ASSIGN: QA Engineer / DevOps]**
- [ ] **Grants are correct.** `SHOW GRANTS FOR 'nexus_app'@'%'` matches the exact 9-line shape in `smoke-test-checklist.md` §6. This is the single highest-value check in this entire document — it's the only thing this story's own threat model rates as a real risk (T-E3, Critical-severity grant gap) and the only thing Testcontainers CI structurally cannot verify. — **Owner: [ASSIGN: QA Engineer / DevOps]**

**JaCoCo coverage gate note:** `rbac.domain` is enforced automatically on every `mvnw verify` (90% line-coverage rule, currently at 100% per `08-test-audit.md`) — no ongoing manual monitoring needed for this; it's a CI gate, not a runtime signal.

**Forward-looking, not this story's job:** a runtime DB-privilege self-check (warning if the live connection can `DELETE user_roles` or is `root`/`ALL PRIVILEGES`) is tracked as a US-010 obligation (`03b-threat-model.md` T-E3 residual) — do not attempt to backfill it into this story's monitoring.
