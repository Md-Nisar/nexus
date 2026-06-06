---
description: Phase 7 — Security audit of the implementation.
argument-hint: <JIRA-ID>
---

Use the **security-reviewer** sub-agent in **Mode B (Code Audit)** for feature `$1`.

Steps:

1. Identify the diff scope:
   ```bash
   git diff origin/main...HEAD
   ```

2. Cross-reference against `docs/features/$1/03b-threat-model.md`. Every threat marked "mitigated" must have visible mitigation in code — flag any that don't.

3. Walk every changed file. Apply OWASP Top 10 + project security guidelines.

4. Run dependency scans:
   ```bash
   cd nexus-backend && ./mvnw dependency:tree
   cd nexus-frontend && npm audit --audit-level=moderate
   ```
   Include findings in the report.

5. Produce the security review report per the agent's output format. Save to `docs/features/$1/07-security-review.md`.

6. Print to chat: counts by severity + the final verdict. Any **Blocker** finding is a release-stopper.

This phase does not modify code. If Blocker / High findings exist, the user must triage them and either re-implement (back to `/implement`) or accept-with-mitigation (recorded in the report).
