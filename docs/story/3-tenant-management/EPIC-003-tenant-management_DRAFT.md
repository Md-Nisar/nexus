# EPIC-003: Tenant Management

```
EPIC ID:       EPIC-003
EPIC TITLE:    Tenant Management
PRIORITY:      P0
STORY POINTS:  29
BLOCKED BY:    EPIC-002 (US-011 permission enforcement, US-012 role assignment)
BLOCKS:        EPIC-004 User Lifecycle & Provisioning

Description:
  Delivers the two-tier tenant model (Tenant → Organisation), Platform Admin
  tenant lifecycle management, Tenant Admin self-service profile management,
  organisation CRUD with full Angular UI, suspension enforcement filter,
  Angular TenantContextService, and full audit of all tenant lifecycle events.
  Makes the platform commercially viable for B2B enterprise customers.

Business Goal:
  First enterprise customer onboardable within 1 week of GA.

Success Metrics:
  - Zero cross-tenant data leakage findings in pre-GA pen test
  - Tenant creation p95 < 2s
  - Suspension enforced within 5 min of Platform Admin action

Storage Providers (FileStorageService abstraction):
  - Local disk  → @Profile("dev", "test")
  - AWS S3      → @Profile("prod")
  - SFTP        → @Profile("sftp")
```

---

## Stories in this Epic

| Story | Title | Points | Priority | Sprint |
|---|---|---|---|---|
| US-020 | Tenant and organisation data model + migrations | 5 | P0 | 5 |
| US-021 | Platform Admin — tenant create + lifecycle management | 5 | P0 | 5 |
| US-022 | Tenant Admin — profile management (API + UI) | 5 | P0 | 6 |
| US-023 | Tenant Admin — organisation management (API + UI) | 8 | P0 | 6 |
| US-024 | Tenant suspension enforcement filter | 3 | P0 | 6 |
| US-025 | Angular TenantContextService + audit events | 3 | P1 | 7 |
| **Total** | | **29** | | |

---

## Open Decisions (all resolved)

| # | Decision | Resolution |
|---|---|---|
| OQ-001 | Storage provider | `FileStorageService` abstraction — Local (dev), S3 (prod), SFTP (enterprise) |
| OQ-002 | `organisation:read/write` placement | Seeded in V4 migration alongside tenant tables |
| OQ-003 | ADR-004 | Two-tier tenant model — approved |
| OQ-004 | Platform Admin role for MVP | `tenant:write` permission used; super-admin role deferred to ops epic |

---

## Recommended Sprint Order

| Sprint | Stories | Points | Notes |
|---|---|---|---|
| Sprint 5 | US-020, US-021 | 10 | Schema + Platform Admin create/lifecycle; V4 migration must merge first |
| Sprint 6 | US-022, US-023, US-024 | 16 | Tenant Admin profile + orgs (API + UI) + suspension filter |
| Sprint 7 | US-025 | 3 | Angular TenantContextService + audit event constants |

---

## Claude Code Session Breakdown

| Session | Story | Scope | Branch |
|---|---|---|---|
| 1 | US-020a | V4 migration SQL + TenantStatus enum + FileStorageService interface + implementations | `feature/US-020a-tenant-schema` |
| 2 | US-020b | JPA entities + repositories + Testcontainers migration test | `feature/US-020b-tenant-entities` |
| 3 | US-021 | TenantService + TenantAdminController + DTOs + exceptions + audit | `feature/US-021-tenant-admin-api` |
| 4 | US-022 | TenantProfileController (backend) + TenantProfileComponent + route (frontend) | `feature/US-022-tenant-profile` |
| 5 | US-023a | OrganisationService + OrganisationController + DTOs + exceptions (backend) | `feature/US-023a-org-api` |
| 6 | US-023b | OrganisationListComponent + OrganisationFormDialogComponent + route (frontend) | `feature/US-023b-org-ui` |
| 7 | US-024 | TenantStatusCacheService + TenantStatusFilter + SecurityConfig registration | `feature/US-024-suspension-filter` |
| 8 | US-025 | TenantContextService + AuthService update + AppShellComponent + audit constants | `feature/US-025-tenant-context` |

---

## Cross-Tenant Security Tests — Mandatory CI Gates

| Story | Test | Scenario |
|---|---|---|
| US-022 | T-5 | Tenant Admin cannot access another tenant's profile via JWT boundary |
| US-023 | T-4 | Tenant Admin cannot update org in a different tenant |
| US-024 | T-2, T-3 | SUSPENDED + DELETED tenant users blocked on all endpoints |

---

## Before Sprint 5 — Mandatory Gates

- [ ] ADR-004 (Two-tier tenant model) signed off before any dev starts
- [ ] Gate 1 review on US-020 complete — schema review, FK backfill risk assessed
- [ ] Orphaned `users.tenant_id` rows checked in any existing data before V4 migration
- [ ] S3 + SFTP credentials added to secrets vault before Sprint 6

---
---

## US-020 — Establish tenant and organisation data model with migrations

| TYPE | PRIORITY | STORY POINTS | EPIC LINK | SPRINT | ASSIGNEE |
|------|----------|--------------|-----------|--------|----------|
| Feature | P0 | 5 | EPIC-003: Tenant Management | Sprint 5 | _(Tech lead assigns)_ |

### User Story
As a platform development team,
I want a tenant and organisation schema with status history and FK enforcement,
So that all future features have a stable, two-tier tenant model to build on.

### Background / Context

Creates `tenants`, `organisations`, and `tenant_status_history` tables via
`V4__tenant_schema.sql`. Backfills the `users.tenant_id` raw column (from
US-001) with a real FK constraint. Seeds `organisation:read` and
`organisation:write` permissions and adds them to `TENANT_ADMIN` role.
Append-only trigger on `tenant_status_history`. Gate for all other Epic 3 stories.

**Target database:** MySQL 8.4 Community
**ID strategy:** UUIDv7 stored as `BINARY(16)` — ADR-001
**PII encryption:** reuse `AttributeEncryptor.java` from EPIC-001
**ADR required:** ADR-004 — Two-tier tenant model sign-off before merge

### Acceptance Criteria

| # | Criterion | Definition of Done | Priority |
|---|-----------|--------------------|----------|
| AC-1 | `tenants` table created | `V4__tenant_schema.sql` creates `tenants` with all columns and indexes per spec below | P0 |
| AC-2 | `organisations` table created | Created with `UNIQUE (tenant_id, name)` and status index | P0 |
| AC-3 | `tenant_status_history` append-only | Table created; `BEFORE UPDATE` / `BEFORE DELETE` triggers raise `SQLSTATE '45000'` | P0 |
| AC-4 | `users.tenant_id` FK enforced | Orphan pre-check + `ALTER TABLE users ADD CONSTRAINT fk_users_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)` | P0 |
| AC-5 | New permissions seeded | `organisation:read` and `organisation:write` added to `permissions` table and to `TENANT_ADMIN` role in `role_permissions` | P0 |
| AC-6 | PII fields encrypted | `billing_contact_name`, `billing_contact_email`, `contact_address` use `AttributeEncryptor` from EPIC-001 | P0 |
| AC-7 | Migration clean-forward in CI | Testcontainers: V1 → V2 → V3 → V4 chain succeeds; checksum stable | P1 |

### Schema Specification

#### `tenants`
```sql
CREATE TABLE tenants (
    id                     BINARY(16)    NOT NULL,
    name                   VARCHAR(255)  NOT NULL,
    domain                 VARCHAR(255)  NOT NULL,
    status                 ENUM('ACTIVE','INACTIVE','SUSPENDED','DELETED')
                                         NOT NULL DEFAULT 'INACTIVE',
    plan_tier              VARCHAR(64)   NOT NULL DEFAULT 'STARTER',
    logo_url               VARCHAR(512)  NULL,
    billing_contact_name   TEXT          NULL,  -- encrypted
    billing_contact_email  TEXT          NULL,  -- encrypted
    billing_contact_phone  VARCHAR(32)   NULL,
    contact_address        TEXT          NULL,  -- encrypted
    created_by             BINARY(16)    NOT NULL,
    created_at             TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at             TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP
                                         ON UPDATE CURRENT_TIMESTAMP,
    deleted_at             TIMESTAMP     NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_tenant_domain (domain),
    INDEX idx_tenant_status (status),
    INDEX idx_tenant_created_at (created_at),
    CONSTRAINT fk_tenant_created_by FOREIGN KEY (created_by) REFERENCES users(id)
);
```

#### `organisations`
```sql
CREATE TABLE organisations (
    id          BINARY(16)                  NOT NULL,
    tenant_id   BINARY(16)                  NOT NULL,
    name        VARCHAR(255)                NOT NULL,
    description VARCHAR(512)                NULL,
    status      ENUM('ACTIVE','INACTIVE')   NOT NULL DEFAULT 'ACTIVE',
    created_by  BINARY(16)                  NOT NULL,
    created_at  TIMESTAMP                   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP                   NOT NULL DEFAULT CURRENT_TIMESTAMP
                                            ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_org_tenant_name (tenant_id, name),
    INDEX idx_org_tenant_status (tenant_id, status),
    CONSTRAINT fk_org_tenant     FOREIGN KEY (tenant_id)  REFERENCES tenants(id),
    CONSTRAINT fk_org_created_by FOREIGN KEY (created_by) REFERENCES users(id)
);
```

#### `tenant_status_history`
```sql
CREATE TABLE tenant_status_history (
    id              BINARY(16)                                        NOT NULL,
    tenant_id       BINARY(16)                                        NOT NULL,
    previous_status ENUM('ACTIVE','INACTIVE','SUSPENDED','DELETED')   NULL,
    new_status      ENUM('ACTIVE','INACTIVE','SUSPENDED','DELETED')   NOT NULL,
    changed_by      BINARY(16)                                        NOT NULL,
    reason          VARCHAR(512)                                      NULL,
    created_at      TIMESTAMP                                         NOT NULL
                    DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    INDEX idx_tsh_tenant (tenant_id, created_at),
    CONSTRAINT fk_tsh_tenant     FOREIGN KEY (tenant_id)  REFERENCES tenants(id),
    CONSTRAINT fk_tsh_changed_by FOREIGN KEY (changed_by) REFERENCES users(id)
);

CREATE TRIGGER trg_tsh_no_update
    BEFORE UPDATE ON tenant_status_history FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'tenant_status_history is append-only';
END;

CREATE TRIGGER trg_tsh_no_delete
    BEFORE DELETE ON tenant_status_history FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'tenant_status_history is append-only';
END;
```

#### FK backfill on `users`
```sql
-- Orphan pre-check — fail migration if any orphaned rows exist
SET @orphaned = (
    SELECT COUNT(*) FROM users
    WHERE tenant_id IS NOT NULL
      AND tenant_id NOT IN (SELECT id FROM tenants)
);
IF @orphaned > 0 THEN
    SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'Orphaned users.tenant_id rows — resolve before adding FK';
END IF;

ALTER TABLE users
    ADD CONSTRAINT fk_users_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(id);
```

#### New permission seeds
```sql
INSERT INTO permissions (id, name, description) VALUES
    (UUID_TO_BIN(UUID()), 'organisation:read',  'View organisations within tenant'),
    (UUID_TO_BIN(UUID()), 'organisation:write', 'Manage organisations within tenant');

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.name = 'TENANT_ADMIN'
  AND p.name IN ('organisation:read', 'organisation:write');
```

### Claude Code — Implementation Tasks

#### Task 1 — Flyway migration
**File:** `src/main/resources/db/migration/V4__tenant_schema.sql`
- Create tables: `tenants` → `organisations` → `tenant_status_history`
- Add append-only triggers on `tenant_status_history`
- FK backfill on `users.tenant_id` with orphan pre-check
- Seed `organisation:read` / `organisation:write` + assign to `TENANT_ADMIN`

#### Task 2 — TenantStatus enum with transition map
**File:** `src/main/java/com/example/nexus/tenant/domain/TenantStatus.java`
```java
public enum TenantStatus {
    ACTIVE, INACTIVE, SUSPENDED, DELETED;

    private static final Map<TenantStatus, Set<TenantStatus>> ALLOWED = Map.of(
        INACTIVE,  Set.of(ACTIVE, DELETED),
        ACTIVE,    Set.of(INACTIVE, SUSPENDED, DELETED),
        SUSPENDED, Set.of(ACTIVE, DELETED),
        DELETED,   Set.of()
    );

    public boolean canTransitionTo(TenantStatus next) {
        return ALLOWED.getOrDefault(this, Set.of()).contains(next);
    }
}
```

#### Task 3 — JPA entities
**Package:** `com.example.nexus.tenant.domain`

| Class | Table | Notes |
|---|---|---|
| `Tenant.java` | `tenants` | `@Entity`; `@Convert(AttributeEncryptor)` on PII fields; `@Enumerated` for status |
| `Organisation.java` | `organisations` | `@Entity`; `@ManyToOne` to `Tenant` |
| `TenantStatusHistory.java` | `tenant_status_history` | `@Entity`; immutable — no setters |

Reuse `UuidBinaryConverter.java` + `AttributeEncryptor.java` from EPIC-001.

#### Task 4 — Repositories
**Package:** `com.example.nexus.tenant.repository`

```java
// TenantRepository.java
Optional<Tenant> findByDomain(String domain);
Page<Tenant> findAllByStatusNot(TenantStatus status, Pageable pageable);
Optional<Tenant> findByIdAndStatusNot(byte[] id, TenantStatus status);

// OrganisationRepository.java
List<Organisation> findAllByTenantIdAndStatus(byte[] tenantId, String status);
Optional<Organisation> findByIdAndTenantId(byte[] id, byte[] tenantId);

// TenantStatusHistoryRepository.java
List<TenantStatusHistory> findAllByTenantIdOrderByCreatedAtAsc(byte[] tenantId);
```

#### Task 5 — FileStorageService abstraction
**File:** `src/main/java/com/example/nexus/storage/FileStorageService.java`
```java
public interface FileStorageService {
    String store(String key, byte[] content, String mimeType);
    void delete(String key);
}
```

| Implementation | Profile | Backend |
|---|---|---|
| `LocalFileStorageService.java` | `dev`, `test` | Writes to `./storage/`; returns relative URL |
| `S3FileStorageService.java` | `prod` | AWS S3 via `software.amazon.awssdk:s3` |
| `SftpFileStorageService.java` | `sftp` | SFTP via Apache Commons VFS |

**application.yml:**
```yaml
app:
  storage:
    provider: local
    local:
      base-path: ./storage
      base-url: http://localhost:8080/files
    s3:
      bucket: nexus-files
      region: ap-south-1
      access-key: ${AWS_ACCESS_KEY}
      secret-key: ${AWS_SECRET_KEY}
    sftp:
      host: ${SFTP_HOST}
      port: 22
      username: ${SFTP_USER}
      password: ${SFTP_PASSWORD}
      base-path: /uploads
      base-url: ${SFTP_BASE_URL}
```

> In Epic 3 the `logo_url` is accepted as a plain string — `FileStorageService`
> is wired but not called from controllers. Full upload endpoint is Epic 5 scope.

#### Task 6 — Testcontainers migration test
**File:** `src/test/java/com/example/nexus/tenant/migration/V4MigrationTest.java`
- All 3 tables exist after migration
- Append-only triggers raise `DataIntegrityViolationException` on UPDATE + DELETE
- Duplicate domain raises `ConstraintViolationException`
- Duplicate org name in same tenant raises `ConstraintViolationException`
- Same org name in different tenant succeeds
- `organisation:read` + `organisation:write` present in `permissions`
- Both permissions in `TENANT_ADMIN` `role_permissions`
- FK backfill with orphaned user row causes migration to fail

### Test Scenarios

| # | Scenario | Type | Expected Result |
|---|----------|------|-----------------|
| T-1 | V1 → V2 → V3 → V4 migration chain | Integration | All tables, indexes, seed data present |
| T-2 | Duplicate domain on `tenants` | Integration | Unique constraint violation |
| T-3 | Duplicate org name same tenant | Integration | Unique constraint violation |
| T-4 | Same org name different tenant | Integration | Both rows persist |
| T-5 | UPDATE on `tenant_status_history` | Security | `SQLSTATE '45000'` |
| T-6 | DELETE on `tenant_status_history` | Security | `SQLSTATE '45000'` |
| T-7 | `organisation:read/write` in `TENANT_ADMIN` | Integration | Both permissions confirmed |
| T-8 | FK backfill with orphaned `users.tenant_id` | Integration | Migration fails with clear error |

### Definition of Done

- [ ] `V4__tenant_schema.sql` passes Flyway checksum in CI
- [ ] `TenantStatus.java` enum with transition map created
- [ ] All 3 JPA entities created with correct mappings
- [ ] All 3 repositories created with required query methods
- [ ] `FileStorageService` interface + 3 implementations created
- [ ] `V4MigrationTest.java` green in CI (Testcontainers MySQL 8.4)
- [ ] ADR-004 linked in PR description
- [ ] No Hibernate schema validation warnings on startup

### Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| FK constraint fails on orphaned user rows | Med | High | Pre-check in migration; fail fast with clear message |
| `organisation:read/write` not seeded before Epic 3 dev | Med | High | AC-5 is P0; all org endpoints fail without it |

---
---

## US-021 — Enable Platform Admin to create and manage tenant lifecycle

| TYPE | PRIORITY | STORY POINTS | EPIC LINK | SPRINT | ASSIGNEE |
|------|----------|--------------|-----------|--------|----------|
| Feature | P0 | 5 | EPIC-003: Tenant Management | Sprint 5 | _(Tech lead assigns)_ |

### User Story
As a Platform Admin,
I want to create tenants and control their lifecycle status,
So that I can onboard and manage enterprise customers on the platform.

### Background / Context

First Platform Admin capability on the platform. Tenant creation auto-assigns
the `TENANT_ADMIN` role to a specified user via `RoleAssignmentService` (US-012)
in the same transaction — if role assignment fails, tenant creation is rolled
back. Status transitions are validated against the `TenantStatus` state machine
(US-020) and every transition recorded in `tenant_status_history`. All actions
audited via `AuditEventPublisher` (US-008).

### Acceptance Criteria

| # | Criterion | Definition of Done | Priority |
|---|-----------|--------------------|----------|
| AC-1 | Create tenant | `POST /api/v1/admin/tenants` creates tenant with status=INACTIVE; auto-assigns `TENANT_ADMIN` to specified user; returns 201 within 2s p95 | P0 |
| AC-2 | Domain uniqueness enforced | Duplicate domain returns 409 + `TNT_002` | P0 |
| AC-3 | List all tenants paginated | `GET /api/v1/admin/tenants` returns paginated list; default page 20; status filter supported; DELETED excluded by default | P0 |
| AC-4 | View tenant detail | `GET /api/v1/admin/tenants/{tenantId}` returns full profile including decrypted billing info | P0 |
| AC-5 | Status transition validated | `PATCH /api/v1/admin/tenants/{tenantId}/status` enforces state machine; invalid transition returns 409 + `TNT_003` with `previousStatus` and `newStatus` in body | P0 |
| AC-6 | Status history recorded | Every status change writes row to `tenant_status_history` within 1s | P0 |
| AC-7 | Soft delete | `status=DELETED` sets `deleted_at`; excluded from list; data retained | P0 |
| AC-8 | All actions audited | `TENANT_CREATED`, `TENANT_STATUS_CHANGED` events in audit stream | P0 |

### API Specification

#### POST /api/v1/admin/tenants
**Permission:** `tenant:write`
**Request:**
```json
{
  "name": "Acme Corp",
  "domain": "acme.com",
  "planTier": "ENTERPRISE",
  "tenantAdminUserId": "018f4e2a-...",
  "billingContactName": "John Smith",
  "billingContactEmail": "billing@acme.com",
  "billingContactPhone": "+1-555-0100",
  "contactAddress": "123 Main St, San Francisco, CA 94105"
}
```

| Status | Code | Body |
|---|---|---|
| 201 | — | `TenantDetailDto` |
| 409 | `TNT_002` | Domain already registered |
| 404 | `USR_001` | `tenantAdminUserId` not found |

#### GET /api/v1/admin/tenants
**Permission:** `tenant:read` | **Query:** `?status=ACTIVE&page=0&size=20` | **Response:** `Page<TenantSummaryDto>`

#### GET /api/v1/admin/tenants/{tenantId}
**Permission:** `tenant:read` | **Response:** `TenantDetailDto`

#### PATCH /api/v1/admin/tenants/{tenantId}/status
**Permission:** `tenant:write`
**Request:** `{ "status": "SUSPENDED", "reason": "Non-payment" }`

| Status | Code | Body |
|---|---|---|
| 200 | — | `TenantDetailDto` |
| 409 | `TNT_003` | `{ "previousStatus": "DELETED", "newStatus": "ACTIVE", "message": "Invalid transition" }` |

### Claude Code — Implementation Tasks

#### Task 1 — TenantService
**File:** `src/main/java/com/example/nexus/tenant/service/TenantService.java`

```java
@Service
@RequiredArgsConstructor
@Transactional
public class TenantService {

    private final TenantRepository tenantRepository;
    private final TenantStatusHistoryRepository historyRepository;
    private final RoleAssignmentService roleAssignmentService; // US-012
    private final AuditEventPublisher auditEventPublisher;     // US-008
    private final TenantStatusCacheService statusCacheService; // US-024

    /**
     * Creates a tenant and auto-assigns TENANT_ADMIN to the specified user.
     * Both in a single @Transactional scope — rollback if assignment fails.
     */
    public TenantDetailDto create(CreateTenantRequest request, byte[] createdBy) { ... }

    /**
     * Validates via TenantStatus.canTransitionTo().
     * Writes tenant_status_history. Invalidates Redis cache. Publishes audit event.
     */
    public TenantDetailDto updateStatus(byte[] tenantId, TenantStatus newStatus,
                                        String reason, byte[] changedBy) { ... }

    public Page<TenantSummaryDto> listAll(TenantStatus statusFilter, Pageable pageable) { ... }

    public TenantDetailDto getById(byte[] tenantId) { ... }
}
```

#### Task 2 — TenantAdminController
**File:** `src/main/java/com/example/nexus/tenant/controller/TenantAdminController.java`

```java
@RestController
@RequestMapping("/api/v1/admin/tenants")
@RequiredArgsConstructor
public class TenantAdminController {

    @PostMapping
    @RequiresPermission("tenant:write")
    public ResponseEntity<TenantDetailDto> createTenant(
        @RequestBody @Valid CreateTenantRequest request,
        Authentication authentication) { ... }

    @GetMapping
    @RequiresPermission("tenant:read")
    public ResponseEntity<Page<TenantSummaryDto>> listTenants(
        @RequestParam(required = false) TenantStatus status,
        Pageable pageable) { ... }

    @GetMapping("/{tenantId}")
    @RequiresPermission("tenant:read")
    public ResponseEntity<TenantDetailDto> getTenant(@PathVariable UUID tenantId) { ... }

    @PatchMapping("/{tenantId}/status")
    @RequiresPermission("tenant:write")
    public ResponseEntity<TenantDetailDto> updateStatus(
        @PathVariable UUID tenantId,
        @RequestBody @Valid UpdateTenantStatusRequest request,
        Authentication authentication) { ... }
}
```

#### Task 3 — DTOs
**Package:** `com.example.nexus.tenant.dto`

```java
// CreateTenantRequest.java
public record CreateTenantRequest(
    @NotBlank String name, @NotBlank String domain, String planTier,
    @NotNull UUID tenantAdminUserId, String billingContactName,
    @Email String billingContactEmail, String billingContactPhone,
    String contactAddress
) {}

// UpdateTenantStatusRequest.java
public record UpdateTenantStatusRequest(@NotNull TenantStatus status, String reason) {}

// TenantSummaryDto.java
public record TenantSummaryDto(
    UUID id, String name, String domain,
    TenantStatus status, String planTier, Instant createdAt
) {}

// TenantDetailDto.java
public record TenantDetailDto(
    UUID id, String name, String domain, TenantStatus status, String planTier,
    String logoUrl, String billingContactName, String billingContactEmail,
    String billingContactPhone, String contactAddress,
    Instant createdAt, Instant updatedAt
) {}
```

#### Task 4 — Custom exceptions
```java
// DomainAlreadyExistsException.java   → 409 + TNT_002
// InvalidStatusTransitionException.java → 409 + TNT_003 (fields: previousStatus, newStatus)
```
Wire to `GlobalExceptionHandler.java` (US-011).

#### Task 5 — Audit events
```java
// In TenantService.create():
auditEventPublisher.publish(AuditEvent.builder()
    .eventType("TENANT_CREATED")
    .tenantId(tenant.getId()).userId(createdBy)
    .metadata(Map.of("name", tenant.getName(), "domain", tenant.getDomain(),
                     "plan_tier", tenant.getPlanTier()))
    .build());

// In TenantService.updateStatus():
auditEventPublisher.publish(AuditEvent.builder()
    .eventType("TENANT_STATUS_CHANGED")
    .tenantId(tenantId).userId(changedBy)
    .metadata(Map.of("previous_status", previous.name(),
                     "new_status", newStatus.name(),
                     "reason", reason != null ? reason : ""))
    .build());
```

### Test Scenarios

| # | Scenario | Type | Expected Result |
|---|----------|------|-----------------|
| T-1 | Create tenant → `TENANT_ADMIN` auto-assigned | Integration | 201; role assigned in same transaction |
| T-2 | Role assignment fails → tenant not created | Integration | Transaction rolled back; no tenant row |
| T-3 | Duplicate domain | Integration | 409 + `TNT_002` |
| T-4 | List tenants with `status=ACTIVE` filter | Integration | Only ACTIVE tenants returned |
| T-5 | Valid transition: `INACTIVE → ACTIVE` | Integration | 200; `tenant_status_history` row written |
| T-6 | Invalid transition: `DELETED → ACTIVE` | Integration | 409 + `TNT_003` with previousStatus + newStatus |
| T-7 | Soft delete: `status=DELETED` | Integration | `deleted_at` set; excluded from default list |
| T-8 | `TENANT_CREATED` audit event | Integration | Event in stream with correct metadata |
| T-9 | `TENANT_STATUS_CHANGED` audit event | Integration | Event with previous + new status |
| T-10 | List 1,000 tenants paginated | Performance | p95 < 500ms |

### Definition of Done

- [ ] `TenantService.java` — create, updateStatus, listAll, getById
- [ ] `TenantAdminController.java` — 4 endpoints
- [ ] All DTOs created
- [ ] Custom exceptions wired to `GlobalExceptionHandler`
- [ ] T-2 transaction rollback test — mandatory CI gate
- [ ] T-6 invalid transition test — mandatory CI gate
- [ ] Audit events T-8 and T-9 green
- [ ] Feature flag wired for `/api/v1/admin/**` endpoints

### Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| `TENANT_ADMIN` auto-assignment fails → orphaned tenant | Med | High | Single `@Transactional` scope; rollback on failure (T-2) |

---
---

## US-022 — Enable Tenant Admin to manage their own tenant profile (API + UI)

| TYPE | PRIORITY | STORY POINTS | EPIC LINK | SPRINT | ASSIGNEE |
|------|----------|--------------|-----------|--------|----------|
| Feature | P0 | 5 | EPIC-003: Tenant Management | Sprint 6 | _(Tech lead assigns)_ |

### User Story
As a Tenant Admin,
I want to view and update my tenant profile via a self-service UI,
So that I can keep our organisation details accurate without involving Platform Admins.

### Background / Context

Tenant Admins operate strictly within their own tenant boundary — `tenant_id`
is always derived from the JWT, never from the request body or path variable.
They cannot change `status` or `plan_tier` (Platform Admin only). All profile
updates are audited with field names only — no PII values. The Angular profile
page reads from `GET /api/v1/tenants/me` and submits via `PATCH /api/v1/tenants/me`.

### Acceptance Criteria

| # | Criterion | Definition of Done | Priority |
|---|-----------|--------------------|----------|
| AC-1 | View own tenant (API) | `GET /api/v1/tenants/me` returns full profile for caller's `tenant_id` from JWT; requires `tenant:read` | P0 |
| AC-2 | Update own tenant profile (API) | `PATCH /api/v1/tenants/me` updates name, domain, logo_url, billing contact, contact_address; requires `tenant:write` | P0 |
| AC-3 | Domain uniqueness on update | Changing domain to existing one returns 409 + `TNT_002` | P0 |
| AC-4 | Status and plan_tier not updatable | Fields excluded from DTO; attempts silently ignored | P1 |
| AC-5 | Cross-tenant access blocked | `tenant_id` always from JWT; no path variable accepted | P0 |
| AC-6 | Profile update audited | `TENANT_PROFILE_UPDATED` event with changed field names — no PII values | P0 |
| AC-7 | Tenant profile page renders | `/tenant/profile` route displays current data in editable form; requires `tenant:read` via `PermissionGuard` | P0 |
| AC-8 | Profile form saves successfully | Submit calls `PATCH /api/v1/tenants/me`; success toast shown; form reflects saved values | P0 |
| AC-9 | Domain conflict shown inline | 409 + `TNT_002` renders as inline field error on domain input | P0 |
| AC-10 | Form meets WCAG 2.1 AA | Keyboard-complete; labels associated; errors via `aria-describedby`; contrast ≥ 4.5:1 | P0 |

### Claude Code — Implementation Tasks

#### BACKEND

##### Task 1 — TenantProfileController
**File:** `src/main/java/com/example/nexus/tenant/controller/TenantProfileController.java`

```java
@RestController
@RequestMapping("/api/v1/tenants/me")
@RequiredArgsConstructor
public class TenantProfileController {

    @GetMapping
    @RequiresPermission("tenant:read")
    public ResponseEntity<TenantDetailDto> getMyTenant(Authentication authentication) {
        byte[] tenantId = jwtHelper.extractTenantId(authentication);
        return ResponseEntity.ok(tenantService.getById(tenantId));
    }

    @PatchMapping
    @RequiresPermission("tenant:write")
    public ResponseEntity<TenantDetailDto> updateMyTenant(
        @RequestBody TenantProfileUpdateRequest request,
        Authentication authentication) {
        byte[] tenantId = jwtHelper.extractTenantId(authentication);
        return ResponseEntity.ok(tenantService.updateProfile(tenantId, request));
    }
}
```

##### Task 2 — TenantProfileUpdateRequest DTO
**File:** `src/main/java/com/example/nexus/tenant/dto/TenantProfileUpdateRequest.java`

```java
// status and planTier deliberately excluded
public record TenantProfileUpdateRequest(
    String name, String domain, String logoUrl,
    String billingContactName, @Email String billingContactEmail,
    String billingContactPhone, String contactAddress
) {}
```

##### Task 3 — TenantService.updateProfile()
**File:** `src/main/java/com/example/nexus/tenant/service/TenantService.java` *(extend — US-021)*

```java
@Transactional
public TenantDetailDto updateProfile(byte[] tenantId, TenantProfileUpdateRequest request) {
    Tenant tenant = tenantRepository.findByIdAndStatusNot(tenantId, TenantStatus.DELETED)
        .orElseThrow(() -> new TenantNotFoundException(tenantId));

    List<String> changedFields = new ArrayList<>();

    if (request.name() != null && !request.name().equals(tenant.getName())) {
        tenant.setName(request.name()); changedFields.add("name");
    }
    if (request.domain() != null && !request.domain().equals(tenant.getDomain())) {
        if (tenantRepository.findByDomain(request.domain()).isPresent())
            throw new DomainAlreadyExistsException(request.domain());
        tenant.setDomain(request.domain()); changedFields.add("domain");
    }
    // Repeat for all updatable fields; PII re-encrypted by AttributeEncryptor on save

    auditEventPublisher.publish(AuditEvent.builder()
        .eventType("TENANT_PROFILE_UPDATED")
        .tenantId(tenantId)
        .metadata(Map.of("changed_fields", String.join(",", changedFields)))
        .build());

    return toDetailDto(tenantRepository.save(tenant));
}
```

#### FRONTEND

##### Task 4 — TenantProfileService
**File:** `src/app/features/tenant/services/tenant-profile.service.ts`

```typescript
@Injectable({ providedIn: 'root' })
export class TenantProfileService {
  constructor(private http: HttpClient) {}

  getProfile(): Observable<TenantDetailDto> {
    return this.http.get<TenantDetailDto>('/api/v1/tenants/me');
  }

  updateProfile(request: TenantProfileUpdateRequest): Observable<TenantDetailDto> {
    return this.http.patch<TenantDetailDto>('/api/v1/tenants/me', request);
  }
}
```

**Interfaces — `src/app/features/tenant/models/tenant.model.ts`:**
```typescript
export interface TenantDetailDto {
  id: string; name: string; domain: string; status: string; planTier: string;
  logoUrl: string | null; billingContactName: string | null;
  billingContactEmail: string | null; billingContactPhone: string | null;
  contactAddress: string | null;
}

export interface TenantProfileUpdateRequest {
  name?: string; domain?: string; logoUrl?: string;
  billingContactName?: string; billingContactEmail?: string;
  billingContactPhone?: string; contactAddress?: string;
}
```

##### Task 5 — TenantProfileComponent
**File:** `src/app/features/tenant/pages/tenant-profile/tenant-profile.component.ts`

```typescript
@Component({ selector: 'app-tenant-profile', templateUrl: './tenant-profile.component.html' })
export class TenantProfileComponent implements OnInit {

  profileForm!: FormGroup;
  loading = false;
  saving = false;
  domainError: string | null = null;

  constructor(
    private fb: FormBuilder,
    private tenantProfileService: TenantProfileService,
    private toastService: ToastService
  ) {}

  ngOnInit(): void {
    this.loading = true;
    this.tenantProfileService.getProfile().subscribe({
      next: profile => {
        this.profileForm = this.fb.group({
          name:                [profile.name,                Validators.required],
          domain:              [profile.domain,              Validators.required],
          logoUrl:             [profile.logoUrl],
          billingContactName:  [profile.billingContactName],
          billingContactEmail: [profile.billingContactEmail, Validators.email],
          billingContactPhone: [profile.billingContactPhone],
          contactAddress:      [profile.contactAddress]
        });
        this.loading = false;
      },
      error: () => this.loading = false
    });
  }

  onSubmit(): void {
    if (this.profileForm.invalid) return;
    this.saving = true;
    this.domainError = null;

    this.tenantProfileService.updateProfile(this.profileForm.value).subscribe({
      next: () => { this.saving = false; this.toastService.success('Profile updated successfully'); },
      error: (err) => {
        this.saving = false;
        if (err.status === 409 && err.error?.error_code === 'TNT_002') {
          this.domainError = 'This domain is already registered';
          this.profileForm.get('domain')?.setErrors({ domainTaken: true });
        }
      }
    });
  }
}
```

**Template — `tenant-profile.component.html`:**
```html
<main aria-labelledby="profile-heading">
  <h1 id="profile-heading">Tenant Profile</h1>
  <app-loading-state *ngIf="loading" />
  <form *ngIf="!loading && profileForm" [formGroup]="profileForm" (ngSubmit)="onSubmit()" novalidate>
    <section aria-labelledby="general-heading">
      <h2 id="general-heading">General</h2>
      <app-input label="Tenant Name" formControlName="name" [required]="true" />
      <app-input label="Domain" formControlName="domain" [required]="true" aria-describedby="domain-error" />
      <span id="domain-error" role="alert" *ngIf="domainError">{{ domainError }}</span>
    </section>
    <section aria-labelledby="billing-heading">
      <h2 id="billing-heading">Billing Contact</h2>
      <app-input label="Contact Name"  formControlName="billingContactName" />
      <app-input label="Contact Email" formControlName="billingContactEmail" type="email" />
      <app-input label="Contact Phone" formControlName="billingContactPhone" type="tel" />
      <app-input label="Address"       formControlName="contactAddress" />
    </section>
    <app-button type="submit" variant="primary"
      [disabled]="profileForm.invalid || saving" [loading]="saving">
      Save Changes
    </app-button>
  </form>
</main>
```

##### Task 6 — Route registration
**File:** `src/app/features/tenant/tenant.routes.ts`
```typescript
export const TENANT_ROUTES: Routes = [
  {
    path: 'profile',
    component: TenantProfileComponent,
    canActivate: [PermissionGuard],
    data: { permission: 'tenant:read' }
  }
];
```
Register in `app.routes.ts`:
```typescript
{ path: 'tenant', loadChildren: () => import('./features/tenant/tenant.routes').then(m => m.TENANT_ROUTES) }
```

### Test Scenarios

| # | Scenario | Type | Expected Result |
|---|----------|------|-----------------|
| T-1 | View own tenant (API) | Integration | 200 with full profile |
| T-2 | Update name and billing contact (API) | Integration | 200; PII re-encrypted |
| T-3 | Attempt status change via PATCH /me | Integration | 200; status unchanged |
| T-4 | Domain taken (API) | Integration | 409 + `TNT_002` |
| T-5 | Cross-tenant access | Security | 403 — **mandatory CI gate** |
| T-6 | Audit metadata — no PII values | Security | Field names only in metadata |
| T-7 | Profile page loads with current data | E2E | Form fields pre-populated |
| T-8 | Submit valid form | E2E | Success toast shown; values persisted |
| T-9 | Domain conflict shown inline | E2E | Field error on domain input; no full-page error |
| T-10 | Profile page — Axe accessibility scan | Accessibility | Zero critical issues |

### Definition of Done

**Backend**
- [ ] `TenantProfileController.java` — GET + PATCH
- [ ] `TenantProfileUpdateRequest.java` (status + planTier excluded)
- [ ] `TenantService.updateProfile()` with changed-fields tracking
- [ ] T-5 cross-tenant test — mandatory CI gate
- [ ] T-6 PII-free audit test green

**Frontend**
- [ ] `TenantProfileService.ts` + interfaces created
- [ ] `TenantProfileComponent` — form, loading state, inline error handling
- [ ] `/tenant/profile` route registered with `PermissionGuard`
- [ ] T-7, T-8, T-9 E2E tests green
- [ ] T-10 Axe scan zero critical issues

---
---

## US-023 — Enable Tenant Admin to manage organisations (API + UI)

| TYPE | PRIORITY | STORY POINTS | EPIC LINK | SPRINT | ASSIGNEE |
|------|----------|--------------|-----------|--------|----------|
| Feature | P0 | 8 | EPIC-003: Tenant Management | Sprint 6 | _(Tech lead assigns)_ |

### User Story
As a Tenant Admin,
I want to create, view, and manage organisations within my tenant via a UI,
So that I can group users into logical business units without needing developer support.

### Background / Context

Organisations are the second tier of the tenant hierarchy. All API operations
strictly scoped to the caller's `tenant_id` from JWT. `orgId` validated against
the caller's tenant before any read or write — cross-tenant access blocked at
service layer. The Angular UI provides a list view with create and edit dialogs,
consuming the existing `DialogComponent` and `TableComponent` from the EPIC-001
design system.

### Acceptance Criteria

| # | Criterion | Definition of Done | Priority |
|---|-----------|--------------------|----------|
| AC-1 | Create organisation (API) | `POST /api/v1/tenants/me/organisations` creates org; returns 201; requires `organisation:write` | P0 |
| AC-2 | Name unique per tenant | Duplicate name returns 409 + `ORG_001` | P0 |
| AC-3 | List organisations (API) | `GET /api/v1/tenants/me/organisations` active orgs default; `?includeInactive=true` for all; requires `organisation:read` | P0 |
| AC-4 | Update organisation (API) | `PATCH /api/v1/tenants/me/organisations/{orgId}` updates name + description; requires `organisation:write` | P0 |
| AC-5 | Cross-tenant isolation | `orgId` validated against caller's `tenant_id`; foreign org returns 403 | P0 |
| AC-6 | Deactivate organisation | PATCH with `status=INACTIVE`; excluded from default list | P1 |
| AC-7 | Events audited | `ORGANISATION_CREATED`, `ORGANISATION_UPDATED` in audit stream | P0 |
| AC-8 | Organisation list page renders | `/tenant/organisations` displays active orgs in `TableComponent`; requires `organisation:read` via `PermissionGuard` | P0 |
| AC-9 | Create org via dialog | "New Organisation" button opens dialog; submit creates org; table refreshes; success toast shown | P0 |
| AC-10 | Edit org via dialog | "Edit" action opens pre-filled dialog; submit updates org and refreshes table | P0 |
| AC-11 | Duplicate name shown inline | 409 + `ORG_001` renders as inline field error on name input inside dialog | P0 |
| AC-12 | Empty state handled | No organisations → `EmptyStateComponent` with "Create your first organisation" CTA | P0 |
| AC-13 | Page meets WCAG 2.1 AA | Table has `<caption>`; dialog traps focus; all actions keyboard-accessible | P0 |

### Claude Code — Implementation Tasks

#### BACKEND

##### Task 1 — OrganisationService
**File:** `src/main/java/com/example/nexus/tenant/service/OrganisationService.java`

```java
@Service
@RequiredArgsConstructor
@Transactional
public class OrganisationService {

    private final OrganisationRepository organisationRepository;
    private final AuditEventPublisher auditEventPublisher;

    public OrganisationDto create(byte[] tenantId, CreateOrganisationRequest request,
                                  byte[] createdBy) {
        if (organisationRepository.existsByTenantIdAndName(tenantId, request.name()))
            throw new OrganisationNameExistsException(request.name());
        // create + save + publish ORGANISATION_CREATED
    }

    public List<OrganisationDto> list(byte[] tenantId, boolean includeInactive) { ... }

    public OrganisationDto update(byte[] orgId, byte[] tenantId,
                                  UpdateOrganisationRequest request) {
        Organisation org = organisationRepository
            .findByIdAndTenantId(orgId, tenantId)
            .orElseThrow(() -> new AccessDeniedException("Organisation not in tenant"));
        // update + save + publish ORGANISATION_UPDATED
    }
}
```

##### Task 2 — OrganisationController
**File:** `src/main/java/com/example/nexus/tenant/controller/OrganisationController.java`

```java
@RestController
@RequestMapping("/api/v1/tenants/me/organisations")
@RequiredArgsConstructor
public class OrganisationController {

    @PostMapping
    @RequiresPermission("organisation:write")
    public ResponseEntity<OrganisationDto> create(
        @RequestBody @Valid CreateOrganisationRequest request,
        Authentication authentication) { ... }

    @GetMapping
    @RequiresPermission("organisation:read")
    public ResponseEntity<List<OrganisationDto>> list(
        @RequestParam(defaultValue = "false") boolean includeInactive,
        Authentication authentication) { ... }

    @PatchMapping("/{orgId}")
    @RequiresPermission("organisation:write")
    public ResponseEntity<OrganisationDto> update(
        @PathVariable UUID orgId,
        @RequestBody UpdateOrganisationRequest request,
        Authentication authentication) { ... }
}
```

##### Task 3 — DTOs + exception
```java
// CreateOrganisationRequest.java
public record CreateOrganisationRequest(@NotBlank String name, String description) {}

// UpdateOrganisationRequest.java
public record UpdateOrganisationRequest(String name, String description, String status) {}

// OrganisationDto.java
public record OrganisationDto(UUID id, UUID tenantId, String name,
    String description, String status, Instant createdAt) {}

// OrganisationNameExistsException.java → 409 + ORG_001
```
Wire `OrganisationNameExistsException` to `GlobalExceptionHandler.java`.

#### FRONTEND

##### Task 4 — OrganisationService (Angular)
**File:** `src/app/features/tenant/services/organisation.service.ts`

```typescript
@Injectable({ providedIn: 'root' })
export class OrganisationService {
  constructor(private http: HttpClient) {}

  list(includeInactive = false): Observable<OrganisationDto[]> {
    return this.http.get<OrganisationDto[]>('/api/v1/tenants/me/organisations',
      { params: { includeInactive: String(includeInactive) } });
  }

  create(request: CreateOrganisationRequest): Observable<OrganisationDto> {
    return this.http.post<OrganisationDto>('/api/v1/tenants/me/organisations', request);
  }

  update(orgId: string, request: UpdateOrganisationRequest): Observable<OrganisationDto> {
    return this.http.patch<OrganisationDto>(`/api/v1/tenants/me/organisations/${orgId}`, request);
  }
}
```

**Interfaces — `src/app/features/tenant/models/organisation.model.ts`:**
```typescript
export interface OrganisationDto {
  id: string; tenantId: string; name: string;
  description: string | null; status: 'ACTIVE' | 'INACTIVE'; createdAt: string;
}
export interface CreateOrganisationRequest { name: string; description?: string; }
export interface UpdateOrganisationRequest { name?: string; description?: string; status?: 'ACTIVE' | 'INACTIVE'; }
```

##### Task 5 — OrganisationListComponent
**File:** `src/app/features/tenant/pages/organisation-list/organisation-list.component.ts`

```typescript
@Component({ selector: 'app-organisation-list', templateUrl: './organisation-list.component.html' })
export class OrganisationListComponent implements OnInit {

  organisations: OrganisationDto[] = [];
  loading = false;
  columns = ['name', 'description', 'status', 'createdAt', 'actions'];

  constructor(
    private organisationService: OrganisationService,
    private dialog: DialogService,
    private toastService: ToastService
  ) {}

  ngOnInit(): void { this.load(); }

  load(): void {
    this.loading = true;
    this.organisationService.list().subscribe({
      next: orgs => { this.organisations = orgs; this.loading = false; },
      error: () => this.loading = false
    });
  }

  openCreateDialog(): void {
    this.dialog.open(OrganisationFormDialogComponent, { title: 'New Organisation' })
      .afterClosed().pipe(filter(Boolean))
      .subscribe(() => { this.load(); this.toastService.success('Organisation created'); });
  }

  openEditDialog(org: OrganisationDto): void {
    this.dialog.open(OrganisationFormDialogComponent, { title: 'Edit Organisation', data: org })
      .afterClosed().pipe(filter(Boolean))
      .subscribe(() => { this.load(); this.toastService.success('Organisation updated'); });
  }
}
```

**Template — `organisation-list.component.html`:**
```html
<main aria-labelledby="orgs-heading">
  <div class="page-header">
    <h1 id="orgs-heading">Organisations</h1>
    <app-button *appHasPermission="'organisation:write'" variant="primary" (onClick)="openCreateDialog()">
      New Organisation
    </app-button>
  </div>
  <app-loading-state *ngIf="loading" />
  <app-empty-state *ngIf="!loading && organisations.length === 0"
    icon="business" title="No organisations yet"
    description="Create your first organisation to start grouping users."
    actionLabel="Create Organisation" (action)="openCreateDialog()" />
  <app-table *ngIf="!loading && organisations.length > 0"
    [data]="organisations" [columns]="columns" caption="Organisations in your tenant">
    <ng-template appTableCell="actions" let-org>
      <app-button variant="ghost" size="sm" *appHasPermission="'organisation:write'" (onClick)="openEditDialog(org)">
        Edit
      </app-button>
    </ng-template>
  </app-table>
</main>
```

##### Task 6 — OrganisationFormDialogComponent
**File:** `src/app/features/tenant/components/organisation-form-dialog/organisation-form-dialog.component.ts`

```typescript
@Component({ selector: 'app-organisation-form-dialog' })
export class OrganisationFormDialogComponent implements OnInit {

  form!: FormGroup;
  saving = false;
  nameError: string | null = null;
  isEditMode = false;

  constructor(
    private fb: FormBuilder,
    private organisationService: OrganisationService,
    private dialogRef: DialogRef,
    @Optional() @Inject(DIALOG_DATA) public data: OrganisationDto | null
  ) {}

  ngOnInit(): void {
    this.isEditMode = !!this.data;
    this.form = this.fb.group({
      name:        [this.data?.name ?? '',        Validators.required],
      description: [this.data?.description ?? '']
    });
  }

  onSubmit(): void {
    if (this.form.invalid) return;
    this.saving = true;
    this.nameError = null;

    const request$ = this.isEditMode
      ? this.organisationService.update(this.data!.id, this.form.value)
      : this.organisationService.create(this.form.value);

    request$.subscribe({
      next: () => { this.saving = false; this.dialogRef.close(true); },
      error: (err) => {
        this.saving = false;
        if (err.status === 409 && err.error?.error_code === 'ORG_001') {
          this.nameError = 'An organisation with this name already exists';
          this.form.get('name')?.setErrors({ nameTaken: true });
        }
      }
    });
  }

  onCancel(): void { this.dialogRef.close(false); }
}
```

##### Task 7 — Route registration
**File:** `src/app/features/tenant/tenant.routes.ts` *(extend — US-022 Task 6)*
```typescript
{
  path: 'organisations',
  component: OrganisationListComponent,
  canActivate: [PermissionGuard],
  data: { permission: 'organisation:read' }
}
```

### Test Scenarios

| # | Scenario | Type | Expected Result |
|---|----------|------|-----------------|
| T-1 | Create organisation (API) | Integration | 201; scoped to caller's tenant |
| T-2 | Duplicate name same tenant (API) | Integration | 409 + `ORG_001` |
| T-3 | Same name different tenant (API) | Integration | Both rows persist |
| T-4 | Update org in different tenant (API) | Security | 403 — **mandatory CI gate** |
| T-5 | Deactivate org (API) | Integration | INACTIVE; excluded from default list |
| T-6 | Audit events (API) | Integration | `ORGANISATION_CREATED` + `ORGANISATION_UPDATED` |
| T-7 | Organisation list page renders | E2E | Table shows active orgs |
| T-8 | Empty state with CTA | E2E | `EmptyStateComponent` shown; CTA opens create dialog |
| T-9 | Create org via dialog — success | E2E | Dialog closes; table refreshes; toast shown |
| T-10 | Duplicate name — inline error | E2E | Name field error; dialog stays open |
| T-11 | Edit org — pre-filled dialog | E2E | Dialog opens with current values; save updates table |
| T-12 | Organisation list — Axe scan | Accessibility | Zero critical issues |

### Definition of Done

**Backend**
- [ ] `OrganisationService.java` — create, list, update
- [ ] `OrganisationController.java` — POST, GET, PATCH
- [ ] DTOs + `OrganisationNameExistsException` wired to `GlobalExceptionHandler`
- [ ] T-4 cross-tenant test — mandatory CI gate
- [ ] T-6 audit events green

**Frontend**
- [ ] `OrganisationService.ts` + interfaces created
- [ ] `OrganisationListComponent` — table, loading, empty state
- [ ] `OrganisationFormDialogComponent` — create + edit mode + inline error
- [ ] `/tenant/organisations` route registered with `PermissionGuard`
- [ ] T-7 through T-11 E2E tests green
- [ ] T-12 Axe scan zero critical issues

---
---

## US-024 — Implement tenant suspension enforcement filter

| TYPE | PRIORITY | STORY POINTS | EPIC LINK | SPRINT | ASSIGNEE |
|------|----------|--------------|-----------|--------|----------|
| Feature | P0 | 3 | EPIC-003: Tenant Management | Sprint 6 | _(Tech lead assigns)_ |

### User Story
As a Platform Admin,
I want suspended tenant users to be blocked from all API access,
So that suspending a tenant immediately cuts off their access to the platform.

### Background / Context

Enforcement at the infrastructure layer — not per-endpoint. Spring Security
filter reads tenant status from a Redis-cached lookup after JWT validation.
SUSPENDED or DELETED → 403 before any controller is reached. Cache TTL 5 min
— maximum lag between suspension and enforcement. Cache invalidated immediately
on status change via `TenantService.updateStatus()`.

### Acceptance Criteria

| # | Criterion | Definition of Done | Priority |
|---|-----------|--------------------|----------|
| AC-1 | Suspended tenant users blocked | Every API request from SUSPENDED tenant returns `403 + TENANT_001`; no controller reached | P0 |
| AC-2 | Deleted tenant users blocked | Same for DELETED status | P0 |
| AC-3 | Active tenant users unaffected | Filter adds < 10ms to p95 (cache hit) | P0 |
| AC-4 | Cache invalidated on suspension | Redis key `tenant:status:{tenantId}` deleted on status change | P0 |
| AC-5 | Filter position correct | Executes after `JwtAuthenticationFilter`, before controllers | P0 |
| AC-6 | Auth endpoints excluded | `/api/v1/auth/**` and `/.well-known/jwks.json` bypass filter | P1 |

### Claude Code — Implementation Tasks

#### Task 1 — TenantStatusCacheService
**File:** `src/main/java/com/example/nexus/tenant/service/TenantStatusCacheService.java`

```java
@Service
@RequiredArgsConstructor
public class TenantStatusCacheService {

    private final RedisTemplate<String, String> redisTemplate;
    private final TenantRepository tenantRepository;
    private static final Duration TTL = Duration.ofMinutes(5);

    public TenantStatus getStatus(byte[] tenantId) {
        String key = cacheKey(tenantId);
        String cached = redisTemplate.opsForValue().get(key);
        if (cached != null) return TenantStatus.valueOf(cached);

        TenantStatus status = tenantRepository.findById(tenantId)
            .map(Tenant::getStatus)
            .orElse(TenantStatus.DELETED); // unknown tenant treated as deleted

        redisTemplate.opsForValue().set(key, status.name(), TTL);
        return status;
    }

    public void invalidate(byte[] tenantId) {
        redisTemplate.delete(cacheKey(tenantId));
    }

    private String cacheKey(byte[] tenantId) {
        return "tenant:status:" + UuidUtils.toHex(tenantId);
    }
}
```

#### Task 2 — TenantStatusFilter
**File:** `src/main/java/com/example/nexus/tenant/filter/TenantStatusFilter.java`

```java
@Component
@RequiredArgsConstructor
public class TenantStatusFilter extends OncePerRequestFilter {

    private final TenantStatusCacheService statusCacheService;
    private final ObjectMapper objectMapper;

    private static final List<String> EXCLUDED_PATHS = List.of("/api/v1/auth/", "/.well-known/");

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws IOException, ServletException {

        if (EXCLUDED_PATHS.stream().anyMatch(request.getRequestURI()::startsWith)) {
            chain.doFilter(request, response);
            return;
        }

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            chain.doFilter(request, response);
            return;
        }

        byte[] tenantId = jwtHelper.extractTenantId(auth);
        TenantStatus status = statusCacheService.getStatus(tenantId);

        if (status == TenantStatus.SUSPENDED || status == TenantStatus.DELETED) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write(objectMapper.writeValueAsString(Map.of(
                "error_code", "TENANT_001",
                "message",    "Your account has been suspended. Contact your administrator."
            )));
            return;
        }

        chain.doFilter(request, response);
    }
}
```

#### Task 3 — Register in SecurityConfig
**File:** `src/main/java/com/example/nexus/config/SecurityConfig.java` *(modify — US-003 / US-011)*
```java
http.addFilterAfter(tenantStatusFilter, JwtAuthenticationFilter.class);
```

#### Task 4 — Cache invalidation in TenantService
**File:** `src/main/java/com/example/nexus/tenant/service/TenantService.java` *(modify — US-021)*
```java
// In updateStatus() after saving:
tenantStatusCacheService.invalidate(tenantId);
```

### Test Scenarios

| # | Scenario | Type | Expected Result |
|---|----------|------|-----------------|
| T-1 | Active tenant — any endpoint | Integration | Request proceeds normally |
| T-2 | Suspended tenant — any endpoint | Security | 403 + `TENANT_001`; no controller reached — **mandatory CI gate** |
| T-3 | Deleted tenant — any endpoint | Security | 403 + `TENANT_001` — **mandatory CI gate** |
| T-4 | Suspend → next request blocked | E2E | 403 within 5 min (cache TTL or immediate on invalidation) |
| T-5 | Reactivate → next request succeeds | E2E | 200 after cache invalidation |
| T-6 | Filter latency — cache hit | Performance | < 10ms added to p95 |
| T-7 | Suspended user hits `/api/v1/auth/login` | Integration | Login succeeds (auth endpoint excluded) |

### Definition of Done

- [ ] `TenantStatusCacheService.java` — Redis cache + DB fallback
- [ ] `TenantStatusFilter.java` — auth endpoints excluded; correct 403 response
- [ ] Filter registered after `JwtAuthenticationFilter` in `SecurityConfig`
- [ ] Cache invalidated from `TenantService.updateStatus()`
- [ ] T-2 + T-3 — mandatory CI gate
- [ ] T-6 performance < 10ms documented in PR description

---
---

## US-025 — Implement Angular TenantContextService and audit tenant events

| TYPE | PRIORITY | STORY POINTS | EPIC LINK | SPRINT | ASSIGNEE |
|------|----------|--------------|-----------|--------|----------|
| Feature | P1 | 3 | EPIC-003: Tenant Management | Sprint 7 | _(Tech lead assigns)_ |

### User Story
As a frontend developer and compliance team member,
I want a standard Angular service exposing the current tenant context and all
tenant lifecycle events audited,
So that feature UIs can display tenant-aware information and compliance
requirements are met from day one.

### Background / Context

Two concerns in one story — both are small and share the same dependency on
US-022 (`GET /api/v1/tenants/me`). `TenantContextService` is the Angular
equivalent of the backend `TenantStatusFilter` — it makes tenant profile data
(name, logo, plan) available to all future feature UIs without each component
making its own API call. Audit event constants are confirmed and wired, not
newly published — publishing happens in US-021 and US-022.

### Acceptance Criteria

| # | Criterion | Definition of Done | Priority |
|---|-----------|--------------------|----------|
| AC-1 | `TenantContextService` fetches on login | Calls `GET /api/v1/tenants/me` after login; stores result in `currentTenant$` observable | P0 |
| AC-2 | Tenant name + logo in app shell | `AppShellComponent` subscribes to `currentTenant$`; displays name and logo in header | P0 |
| AC-3 | Service resets on logout | `currentTenant$` emits null when `AuthService.logout()` called | P0 |
| AC-4 | `TENANT_CREATED` audited | Event in stream on `TenantService.create()` with tenant_id, created_by, plan_tier | P0 |
| AC-5 | `TENANT_STATUS_CHANGED` audited | Event on every status transition: previous_status, new_status, changed_by, reason | P0 |
| AC-6 | `TENANT_PROFILE_UPDATED` audited | Event on PATCH /tenants/me with changed field names — no PII values | P0 |

### Claude Code — Implementation Tasks

#### Task 1 — TenantContextService
**File:** `src/app/core/services/tenant-context.service.ts`

```typescript
export interface TenantProfile {
  tenantId: string;
  name: string;
  logoUrl: string | null;
  planTier: string;
}

@Injectable({ providedIn: 'root' })
export class TenantContextService {

  private currentTenantSubject = new BehaviorSubject<TenantProfile | null>(null);
  currentTenant$ = this.currentTenantSubject.asObservable();

  constructor(private http: HttpClient) {}

  loadTenantProfile(): Observable<TenantProfile> {
    return this.http.get<TenantProfile>('/api/v1/tenants/me').pipe(
      tap(profile => this.currentTenantSubject.next(profile))
    );
  }

  clear(): void {
    this.currentTenantSubject.next(null);
  }
}
```

#### Task 2 — AuthService integration
**File:** `src/app/core/services/auth.service.ts` *(modify — US-003)*

```typescript
login(credentials): Observable<void> {
  return this.http.post<TokenResponse>('/api/v1/auth/login', credentials).pipe(
    tap(tokens => this.storeTokens(tokens)),
    switchMap(() => this.tenantContextService.loadTenantProfile()),
    map(() => void 0)
  );
}

logout(): void {
  // ... existing cleanup
  this.tenantContextService.clear();
}
```

#### Task 3 — AppShellComponent
**File:** `src/app/core/components/app-shell/app-shell.component.ts` *(modify or create)*

```typescript
tenant$ = this.tenantContextService.currentTenant$;
```
```html
<img *ngIf="(tenant$ | async)?.logoUrl as logo" [src]="logo" alt="Tenant logo">
<span>{{ (tenant$ | async)?.name }}</span>
```

#### Task 4 — Backend audit event constants
**File:** `src/main/java/com/example/nexus/audit/model/AuditEventType.java` *(extend — US-008)*

```java
String TENANT_CREATED         = "TENANT_CREATED";
String TENANT_STATUS_CHANGED  = "TENANT_STATUS_CHANGED";
String TENANT_PROFILE_UPDATED = "TENANT_PROFILE_UPDATED";
```

Verify `TenantService` (US-021, US-022) publishes using these constants — no new publish calls needed.

### Test Scenarios

| # | Scenario | Type | Expected Result |
|---|----------|------|-----------------|
| T-1 | Login → `currentTenant$` populated | Unit | Observable emits `TenantProfile` |
| T-2 | Logout → `currentTenant$` cleared | Unit | Observable emits null |
| T-3 | App shell displays tenant name | E2E | Name visible in header after login |
| T-4 | `TENANT_CREATED` audit event | Integration | Event with correct metadata fields |
| T-5 | `TENANT_STATUS_CHANGED` audit event | Integration | Event with previous + new status |
| T-6 | `TENANT_PROFILE_UPDATED` — no PII | Security | Metadata contains field names only |

### Definition of Done

- [ ] `TenantContextService.ts` — `currentTenant$` observable, `loadTenantProfile()`, `clear()`
- [ ] `AuthService` updated — load on login, clear on logout
- [ ] `AppShellComponent` displays tenant name and logo from `currentTenant$`
- [ ] Audit event type constants confirmed in `AuditEventType.java`
- [ ] T-6 PII-free metadata test green
- [ ] No regression on US-003 login tests
