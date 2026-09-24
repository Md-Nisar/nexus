---
description: Phase 7 — Security audit of the implementation. Alias of /security-review with a required FEATURE-ID.
argument-hint: <FEATURE-ID>
---

Run `/security-review $1` exactly as defined in `.claude/commands/security-review.md`, with `$1` required.

That command is the single definition of the Phase 7 audit (dependency scans, OWASP walk, threat-model cross-check, and saving `docs/features/$1/07-security-review.md`). This alias exists only for backwards compatibility — do not add steps here.

If `$1` is missing, stop and ask for the FEATURE-ID.
