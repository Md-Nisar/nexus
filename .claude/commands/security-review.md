---
description: Ad-hoc, diff-based security audit of the current branch using the security-reviewer agent.
argument-hint: [FEATURE-ID]
---

Run a security audit of the current changes using the **security-reviewer** sub-agent (fresh, hostile-mindset context). This is the canonical, anytime security review — not tied to a Jira story. (The phase-bound `/security-scan <FEATURE-ID>` is the story-workflow equivalent that also writes `07-security-review.md`.)

Steps:

1. Scope the diff:
   ```bash
   git diff origin/main...HEAD
   ```
2. Hand the diff to the **security-reviewer** agent. It audits against `SECURITY.md` (the standards single-source-of-truth) and the OWASP Top 10 checklist there, with special attention to: authz/IDOR, secrets, PII in logs, injection, crypto, input validation, tenant isolation.
3. Run dependency scans:
   - `cd nexus-backend && ./mvnw -Psecurity dependency-check:check` (block CVSS ≥ 7)
   - `cd nexus-frontend && npm audit --omit=dev --audit-level=high`
4. If `$1` (a FEATURE-ID) is provided, cross-reference `docs/features/$1/03b-threat-model.md`: every threat marked "mitigated" must show a visible mitigation in the diff — flag any that don't, and save the report to `docs/features/$1/07-security-review.md`.
5. Output findings in the agent's format (Severity / File:line / Issue / Risk / Fix) and a verdict: `APPROVED` or `BLOCKED`. Never approve auth, crypto, or PII-handling code without explicitly stating those concerns were reviewed.

Review only — do not modify code in this command.
