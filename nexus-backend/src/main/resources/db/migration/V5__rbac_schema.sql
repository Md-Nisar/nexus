-- V5__rbac_schema.sql
-- RBAC bounded context (EPIC-002 / US-009): permissions, roles, role_permissions, user_roles.
-- UUIDv7 primary keys stored as BINARY(16) (ADR-0005). Temporal columns DATETIME(6), matching V2-V4.
-- Append-only migration (ADR 0003) -- never edit after first apply.
--
-- Seeded PK literals are format-valid UUIDv7 (version nibble 7, variant 10xx) -- Gate-1 OQ-2 / ADR-0013:
--   tenant:read  019f6839-1800-7000-8000-000000000001   role:read   019f6839-1804-7000-8000-000000000005
--   tenant:write 019f6839-1801-7000-8000-000000000002   role:write  019f6839-1805-7000-8000-000000000006
--   user:read    019f6839-1802-7000-8000-000000000003   audit:read  019f6839-1806-7000-8000-000000000007
--   user:write   019f6839-1803-7000-8000-000000000004
--   TENANT_ADMIN 019f6839-1810-7000-8000-00000000000a   MEMBER      019f6839-1811-7000-8000-00000000000b
-- Bootstrap tenant (ADR-0014 D5): 00000000-0000-7000-8000-000000000001  == application.yml default-tenant-id fallback.
-- UUID_TO_BIN default swap_flag=0 => big-endian, byte-identical to UuidV7Converter (ADR-0005).

-- ---------------------------------------------------------------------------
-- permissions (code-/migration-defined only; read-only at runtime -- ADR-0013 D1)
-- ---------------------------------------------------------------------------
CREATE TABLE permissions (
    id          BINARY(16)   NOT NULL,
    name        VARCHAR(64)  NOT NULL,
    description VARCHAR(255) NOT NULL,
    created_at  DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT pk_permissions       PRIMARY KEY (id),
    CONSTRAINT uq_permissions_name  UNIQUE (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------------
-- roles (tenant-scoped; no FK on tenant_id -- no tenants table exists yet, cf. users.tenant_id)
-- ---------------------------------------------------------------------------
CREATE TABLE roles (
    id             BINARY(16)   NOT NULL,
    tenant_id      BINARY(16)   NOT NULL,
    name           VARCHAR(64)  NOT NULL,
    description    VARCHAR(255) NULL,
    is_system_role BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at     DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at     DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    CONSTRAINT pk_roles             PRIMARY KEY (id),
    CONSTRAINT uq_roles_tenant_name UNIQUE (tenant_id, name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------------
-- role_permissions (join table WITH created_at -> first-class entity, not @ManyToMany)
-- ---------------------------------------------------------------------------
CREATE TABLE role_permissions (
    role_id       BINARY(16)  NOT NULL,
    permission_id BINARY(16)  NOT NULL,
    created_at    DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT pk_role_permissions             PRIMARY KEY (role_id, permission_id),
    CONSTRAINT fk_role_permissions_role        FOREIGN KEY (role_id)       REFERENCES roles (id),
    CONSTRAINT fk_role_permissions_permission  FOREIGN KEY (permission_id) REFERENCES permissions (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
-- NOTE: InnoDB auto-creates an index on permission_id for fk_role_permissions_permission
-- (the composite PK's leftmost column is role_id, so permission_id alone is not covered by it,
-- and InnoDB requires an index on every FK column to support fast constraint checking).
-- This means the "which roles grant permission X" reverse lookup IS in fact indexed -- correcting
-- the impact doc's performance note (02-impact.md §7) that assumed a table scan. No manual index needed.

-- ---------------------------------------------------------------------------
-- user_roles (soft-delete via revoked_at; hard delete blocked by trigger below)
-- active_key: STORED generated column giving DB-level "one active assignment per (user,role)" (ADR-0013 D2)
-- ---------------------------------------------------------------------------
CREATE TABLE user_roles (
    id          BINARY(16)  NOT NULL,
    user_id     BINARY(16)  NOT NULL,
    role_id     BINARY(16)  NOT NULL,
    tenant_id   BINARY(16)  NOT NULL,
    assigned_by BINARY(16)  NOT NULL,
    assigned_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    revoked_at  DATETIME(6) NULL,
    active_key  BINARY(32)  GENERATED ALWAYS AS (
                    CASE WHEN revoked_at IS NULL THEN CONCAT(user_id, role_id) ELSE NULL END
                ) STORED,
    CONSTRAINT pk_user_roles          PRIMARY KEY (id),
    CONSTRAINT fk_user_roles_user     FOREIGN KEY (user_id)     REFERENCES users (id),
    CONSTRAINT fk_user_roles_role     FOREIGN KEY (role_id)     REFERENCES roles (id),
    CONSTRAINT fk_user_roles_assigner FOREIGN KEY (assigned_by) REFERENCES users (id),
    -- Invariant (threat model T-T2): revocation is always immediate/past-dated, never scheduled.
    -- active_key's "active = revoked_at IS NULL" definition depends on this; a future feature
    -- wanting scheduled/future-dated revocation MUST revisit active_key's definition, not just
    -- relax this constraint.
    CONSTRAINT chk_user_roles_revoked_not_before_assigned
        CHECK (revoked_at IS NULL OR revoked_at >= assigned_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- MySQL never treats two NULLs as duplicate in a unique index -> any number of revoked rows
-- (active_key NULL) coexist; two ACTIVE rows for the same (user_id, role_id) compute the same
-- non-null value and collide on insert (ADR-0013 D2). InnoDB auto-indexes the three FK columns.
CREATE UNIQUE INDEX uq_user_role_active ON user_roles (active_key);

-- ---------------------------------------------------------------------------
-- Append-only enforcement: DELETE ONLY (deliberate divergence from auth_events, which also blocks
-- UPDATE). revoked_at is set via UPDATE and MUST remain permitted. BEGIN/END wrapper is mandatory
-- on MySQL 8.4 via JDBC (see V2:94-96). Do NOT add a BEFORE UPDATE trigger here.
-- ---------------------------------------------------------------------------
CREATE TRIGGER trg_user_roles_no_delete
    BEFORE DELETE ON user_roles
    FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'user_roles is append-only; use revoked_at to soft-delete';
END;

-- ---------------------------------------------------------------------------
-- Seed: 7 permissions
-- ---------------------------------------------------------------------------
INSERT INTO permissions (id, name, description) VALUES
    (UUID_TO_BIN('019f6839-1800-7000-8000-000000000001'), 'tenant:read',  'Read tenant configuration and metadata'),
    (UUID_TO_BIN('019f6839-1801-7000-8000-000000000002'), 'tenant:write', 'Create and modify tenant configuration'),
    (UUID_TO_BIN('019f6839-1802-7000-8000-000000000003'), 'user:read',    'Read user accounts and profiles'),
    (UUID_TO_BIN('019f6839-1803-7000-8000-000000000004'), 'user:write',   'Create and modify user accounts'),
    (UUID_TO_BIN('019f6839-1804-7000-8000-000000000005'), 'role:read',    'Read roles and their permission assignments'),
    (UUID_TO_BIN('019f6839-1805-7000-8000-000000000006'), 'role:write',   'Create roles and manage role-permission assignments'),
    (UUID_TO_BIN('019f6839-1806-7000-8000-000000000007'), 'audit:read',   'Read the authentication and audit event trail');

-- ---------------------------------------------------------------------------
-- Seed: 2 system roles, scoped to the bootstrap default tenant (ADR-0014 D5)
-- ---------------------------------------------------------------------------
INSERT INTO roles (id, tenant_id, name, description, is_system_role) VALUES
    (UUID_TO_BIN('019f6839-1810-7000-8000-00000000000a'),
     UUID_TO_BIN('00000000-0000-7000-8000-000000000001'),
     'TENANT_ADMIN', 'Full administrative control within the tenant', TRUE),
    (UUID_TO_BIN('019f6839-1811-7000-8000-00000000000b'),
     UUID_TO_BIN('00000000-0000-7000-8000-000000000001'),
     'MEMBER', 'Standard member with read access to users', TRUE);

-- ---------------------------------------------------------------------------
-- Seed: role_permissions -- TENANT_ADMIN gets all 7; MEMBER gets user:read only
-- ---------------------------------------------------------------------------
INSERT INTO role_permissions (role_id, permission_id)
SELECT UUID_TO_BIN('019f6839-1810-7000-8000-00000000000a'), id
FROM permissions;   -- TENANT_ADMIN x all 7 (self-documenting: whatever permissions exist above)

INSERT INTO role_permissions (role_id, permission_id) VALUES
    (UUID_TO_BIN('019f6839-1811-7000-8000-00000000000b'),
     UUID_TO_BIN('019f6839-1802-7000-8000-000000000003'));   -- MEMBER x user:read
