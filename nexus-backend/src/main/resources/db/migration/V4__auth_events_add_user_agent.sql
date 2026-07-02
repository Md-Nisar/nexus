-- V4__auth_events_add_user_agent.sql
-- US-008 T-08-01: add first-class user_agent column to auth_events.
-- User-Agent is attacker-controlled, unbounded free text -> capped at 512 chars at the
-- application boundary (RequestContext, US-008 T-08-04) before insert; VARCHAR(512) here
-- is the storage-side backstop, not the primary control.
-- Additive / expand-only (ADR-0003) -- append-only, never edited after first apply.
-- No index: free text, never a query key. No backfill: historical rows stay NULL.

ALTER TABLE auth_events
    ADD COLUMN user_agent VARCHAR(512) NULL AFTER ip_address;
