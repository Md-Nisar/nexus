# Deferred from EPIC-003 (Tenant Management)

```
STATUS:        BACKLOG — not committed to any epic
MOVED:         2026-10-04, when EPIC-003 was reduced from 26 to 15 stories
SOURCE:        docs/story/3-tenant-management/EPIC-003.md (§5.2 lists the move)
```

These stories were "Later" or "Won't" in EPIC-003 and none is needed for the MVP. They are kept
here **unchanged** — acceptance criteria, dependencies and code anchors exactly as approved — so no
research or decision is lost. Each returns to an epic only through its own Gate 1, when a customer
or regulation requires it.

Notes carried from EPIC-003:

- Decisions that still apply: D1 (verified domains enable email-domain sign-in discovery), D4
  (organisations deferred until a feature consumes them), D9 (build OIDC on Spring Security; SAML
  and SCIM, or buying, are re-evaluated only on customer demand — so US-042's first scope is OIDC).
- Dependencies on EPIC-003 stories use the merged IDs: US-032 is now part of **US-031**, and the
  members directory is **US-030**.
- The epic-wide story conventions in EPIC-003 §5 (permission annotations, cross-tenant ITs, audit
  events, grants, retention class, ADR 0019 limit, `shared/ui` wrappers) apply to every story here.

| Story | Title | MoSCoW | Size | Depends on |
|---|---|---|---|---|
| US-033 | Brand colours | Could | M | US-031 |
| US-041 | Domain verification | Could | M | US-031 |
| US-042 | Tenant SSO (OIDC first, per D9) | Could | L | US-027, US-041 |
| US-043 | SCIM provisioning | Won't (in EPIC-003) | L | US-042 |
| US-044 | Organisations with membership | Could | L | US-030, D4 |

---

#### US-033 — Apply my tenant's brand colours

| Priority | Size | Phase | Pattern |
|---|---|---|---|
| Could | M | Later | Auth0 Organizations per-org branding; ADR 0004 token theming |

**As a** Tenant Admin, **I want** to set a primary brand colour for my tenant, **so that** Nexus
looks like part of our company's tooling.

**Acceptance criteria**
1. **Given** `tenant:write`, **when** a primary colour is saved, **then** it is validated as a hex
   colour and rejected if it fails WCAG 2.1 AA contrast against the `--nx-*` surface tokens.
2. **Given** a saved colour, **when** any member signs in, **then** the relevant `--nx-*` tokens are
   overridden at runtime for light and dark themes.
3. **Given** no colour, **when** rendered, **then** the default theme applies.

**Dependencies:** US-031 (absorbed US-032). **Code anchors:** `docs/adr/0004-angular-material-design-system.md`.

#### US-041 — Verify my company's email domain

| Priority | Size | Phase | Pattern |
|---|---|---|---|
| Could | M | Later | WorkOS Domain Verification (DNS TXT); Atlassian verified domains → managed accounts |

**As a** Tenant Admin, **I want** to prove my company owns its email domain, **so that** higher-trust
features such as SSO enforcement can be enabled for that domain.

**Acceptance criteria**
1. **Given** `tenant:write`, **when** a domain is added, **then** a unique DNS TXT token is issued and
   the domain is `PENDING`.
2. **Given** the TXT record is published, **when** verification runs, **then** the domain becomes
   `VERIFIED` and a `TENANT_DOMAIN_VERIFIED` event is written; a domain can be verified by only one
   tenant.
3. **Given** a verified domain, **when** the daily re-check no longer finds its TXT record, **then** the
   domain returns to `PENDING`, any SSO enforcement tied to it is paused, and tenant admins are
   emailed.

**Dependencies:** US-031. **Code anchors:** none yet — new capability.

#### US-042 — Let my users sign in with our identity provider

| Priority | Size | Phase | Pattern |
|---|---|---|---|
| Could | L | Later | Auth0 per-organization connections; Salesforce My Domain SSO; Shopify Plus SAML after domain verification |

**As a** Tenant Admin, **I want** to connect our OIDC or SAML identity provider, **so that** our
users sign in with company credentials and leavers lose access when IT disables them.

**Acceptance criteria**
1. **Given** a verified domain, **when** the admin configures an IdP, **then** users of that domain
   signing in at the tenant slug are redirected to it; the Nexus JWT is issued with the same claims
   contract (`tenant_id` from the tenant, never from the IdP assertion).
2. **Given** SSO is enforced, **when** a domain user tries password login, **then** it is refused.
3. **Given** an unknown IdP user, **when** they first sign in, **then** behaviour follows the admin's
   setting (JIT-create as `MEMBER` or refuse).

**Dependencies:** US-027, US-041. **Code anchors:** `identity/infrastructure/security/JwtRs256Service.java`
(claims contract). Decision D9 (build on Spring Security vs buy WorkOS/Auth0).

#### US-043 — Provision and deprovision users automatically from our directory

| Priority | Size | Phase | Pattern |
|---|---|---|---|
| Won't (this epic) | L | Later | SCIM 2.0 — Entra provisioning, Okta, Atlassian Guard, WorkOS Directory Sync |

**As a** Tenant Admin, **I want** our directory to create, update and deactivate Nexus users via
SCIM, **so that** onboarding and offboarding happen without manual steps in Nexus.

**Acceptance criteria**
1. **Given** a tenant SCIM token, **when** the IdP creates/updates/deactivates a user, **then** the
   member is created/updated/deactivated in that tenant only.
2. **Given** a SCIM token, **when** used against another tenant's resources, **then** 404 is returned.
3. **Given** SCIM manages a user, **when** a tenant admin edits that user's synced attributes in Nexus,
   **then** the edit is refused (Atlassian pattern).

**Dependencies:** US-042. **Code anchors:** none yet. Recorded for roadmap traceability; re-scope at its own Gate 1.

#### US-044 — Group my members into organisations

| Priority | Size | Phase | Pattern |
|---|---|---|---|
| Could | L | Later | Entra administrative units; Shopify Plus stores; Slack Grid workspaces |

**As a** Tenant Admin, **I want** to create organisations within my tenant and assign members to
them, **so that** future features can scope data and delegated administration to a business unit.

**Acceptance criteria**
1. **Given** `tenant:write`, **when** an organisation is created, **then** its name is unique per
   tenant and it is scoped to the caller's tenant only.
2. **Given** an organisation, **when** members are added or removed, **then** only members of the same
   tenant can be added (cross-tenant IT) and membership changes are audited.
3. **Given** an organisation with members, **when** it is deactivated, **then** membership rows are kept,
   the organisation is excluded from default lists, and new members cannot be added.

**Dependencies:** US-030; decision D4. Scheduling rule: build only together with the first feature
that scopes data by organisation, whose scoping rule then joins these criteria. Replaces the previous draft's US-023 organisation CRUD.
