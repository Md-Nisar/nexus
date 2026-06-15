-- V2__identity_schema.sql
-- Identity bounded context: tenant-aware user identity + token + audit tables.
-- UUIDv7 primary keys stored as BINARY(16) (ADR-0005).
-- email_cipher: AES-256-GCM at rest (ADR-0006).
-- email_hmac:   HMAC-SHA256 blind index for per-tenant email uniqueness and lookup.
-- auth_events:  append-only, enforced by BEFORE UPDATE/DELETE triggers (NFR-009).
-- Append-only migration (ADR 0003) — never edit after first apply.

-- ---------------------------------------------------------------------------
-- users
-- ---------------------------------------------------------------------------
CREATE TABLE users (
    id                   BINARY(16)                                           NOT NULL,
    tenant_id            BINARY(16)                                           NOT NULL,
    email_cipher         TEXT                                                 NOT NULL,
    email_hmac           VARCHAR(64)                                          NOT NULL,
    status               ENUM('PENDING','ACTIVE','LOCKED','DISABLED')         NOT NULL DEFAULT 'PENDING',
    token_version        INT                                                  NOT NULL DEFAULT 0,
    email_verified_at    DATETIME(6)                                          NULL,
    failed_attempt_count INT                                                  NOT NULL DEFAULT 0,
    locked_until         DATETIME(6)                                          NULL,
    consent_accepted_at  DATETIME(6)                                          NULL,
    version              BIGINT                                               NOT NULL DEFAULT 0,
    created_at           DATETIME(6)                                          NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at           DATETIME(6)                                          NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    CONSTRAINT pk_users PRIMARY KEY (id),
    CONSTRAINT uq_users_tenant_id_email_hmac UNIQUE (tenant_id, email_hmac)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE INDEX idx_users_tenant_id_status ON users (tenant_id, status);

-- ---------------------------------------------------------------------------
-- refresh_tokens
-- ---------------------------------------------------------------------------
CREATE TABLE refresh_tokens (
    id          BINARY(16)  NOT NULL,
    user_id     BINARY(16)  NOT NULL,
    token_hash  VARCHAR(64) NOT NULL,
    family_id   BINARY(16)  NOT NULL,
    expires_at  DATETIME(6) NOT NULL,
    revoked_at  DATETIME(6) NULL,
    version     BIGINT      NOT NULL DEFAULT 0,
    created_at  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    CONSTRAINT pk_refresh_tokens             PRIMARY KEY (id),
    CONSTRAINT uq_refresh_tokens_token_hash  UNIQUE (token_hash),
    CONSTRAINT fk_refresh_tokens_users       FOREIGN KEY (user_id) REFERENCES users (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE INDEX idx_refresh_tokens_user_id_revoked_at ON refresh_tokens (user_id, revoked_at);
CREATE INDEX idx_refresh_tokens_family_id           ON refresh_tokens (family_id);

-- ---------------------------------------------------------------------------
-- auth_tokens (email verification + password reset)
-- ---------------------------------------------------------------------------
CREATE TABLE auth_tokens (
    id          BINARY(16)                  NOT NULL,
    user_id     BINARY(16)                  NOT NULL,
    type        ENUM('VERIFICATION','RESET') NOT NULL,
    token_hash  VARCHAR(64)                 NOT NULL,
    expires_at  DATETIME(6)                 NOT NULL,
    consumed_at DATETIME(6)                 NULL,
    version     BIGINT                      NOT NULL DEFAULT 0,
    created_at  DATETIME(6)                 NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at  DATETIME(6)                 NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    CONSTRAINT pk_auth_tokens             PRIMARY KEY (id),
    CONSTRAINT uq_auth_tokens_token_hash  UNIQUE (token_hash),
    CONSTRAINT fk_auth_tokens_users       FOREIGN KEY (user_id) REFERENCES users (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE INDEX idx_auth_tokens_user_id_type_consumed_at ON auth_tokens (user_id, type, consumed_at);

-- ---------------------------------------------------------------------------
-- auth_events (append-only audit trail — no updated_at, no FK)
-- ---------------------------------------------------------------------------
CREATE TABLE auth_events (
    id         BINARY(16)  NOT NULL,
    user_id    BINARY(16)  NULL,
    tenant_id  BINARY(16)  NULL,
    event_type VARCHAR(64) NOT NULL,
    outcome    VARCHAR(20) NOT NULL,
    ip_address VARCHAR(45) NULL,
    metadata   JSON        NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT pk_auth_events PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE INDEX idx_auth_events_user_id_created_at    ON auth_events (user_id,    created_at);
CREATE INDEX idx_auth_events_tenant_id_created_at  ON auth_events (tenant_id,  created_at);
CREATE INDEX idx_auth_events_event_type_created_at ON auth_events (event_type, created_at);

-- ---------------------------------------------------------------------------
-- Append-only enforcement on auth_events (NFR-009, AC-5).
-- Single-statement SIGNAL triggers — no BEGIN/END, no DELIMITER.
-- flyway-mysql parses CREATE TRIGGER boundaries natively; DELIMITER is a CLI construct only.
-- ---------------------------------------------------------------------------
CREATE TRIGGER trg_auth_events_no_update
    BEFORE UPDATE ON auth_events
    FOR EACH ROW
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'auth_events is append-only';

CREATE TRIGGER trg_auth_events_no_delete
    BEFORE DELETE ON auth_events
    FOR EACH ROW
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'auth_events is append-only';
