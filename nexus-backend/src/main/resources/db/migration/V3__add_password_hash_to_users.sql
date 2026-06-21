-- V3__add_password_hash_to_users.sql
-- Adds password_hash column required by US-002 self-service registration.
-- Argon2id output (Spring Security prefix string + salt + hash) fits in VARCHAR(255).
-- DEFAULT '' is a migration convenience: the users table is empty when V3 runs
-- (US-002 introduces the first write path). Rows with password_hash='' cannot
-- pass Argon2PasswordEncoder.matches() and therefore cannot log in.
-- Append-only migration (ADR-0003) — never edit after first apply.

ALTER TABLE users
    ADD COLUMN password_hash VARCHAR(255) NOT NULL DEFAULT '';

-- Throttle index for ResendVerificationUseCase rate-limit queries:
--   COUNT(*) WHERE user_id=? AND type='VERIFICATION' AND created_at > NOW()-INTERVAL ?
-- The existing idx_auth_tokens_user_id_type_consumed_at covers (user_id, type) but not
-- the created_at range scan required by the two throttle windows (60s, 24h).
CREATE INDEX idx_auth_tokens_user_id_type_created_at
    ON auth_tokens (user_id, type, created_at);
