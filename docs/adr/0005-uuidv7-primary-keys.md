# ADR 0005 — UUIDv7 Primary Keys

**Status:** Accepted
**Date:** 2026-06-14
**Author:** Engineering Team
**Supersedes:** ULID preference in `docs/coding-standards.md` (Database → Primary keys)

## Context

The platform requires globally unique, non-enumerable, index-friendly primary keys that are safe for distributed generation across application instances without coordination. The existing `docs/coding-standards.md` line 29 recommended `CHAR(26) ULID` for distributed contexts. US-001 (identity schema) is the first bounded context to establish production tables and must commit to a concrete PK strategy that downstream epics adopt immediately.

Two competing requirements informed this decision:
- **Sequential inserts**: random PKs (UUIDv4, random ULID) fragment B-tree indexes under insert load, increasing page splits and write amplification.
- **16-byte storage**: ULID is 26 chars when text-encoded, creating larger index entries and FK columns compared to binary UUID storage.

## Decision

**UUIDv7 stored as `BINARY(16)`, generated via `com.github.f4b6a3:uuid-creator` (pinned to version 6.1.1, MIT license), minted behind a `UuidGenerator` port in `identity.domain`.**

- Generated via `UuidCreator.getTimeOrderedEpoch()` (monotonic time-ordered UUIDv7 per RFC 9562).
- Stored as `BINARY(16)` in MySQL; `UuidV7Converter` (`@Converter(autoApply=true)`) handles `UUID ↔ byte[]` transparently in JPA — domain entities declare `UUID` fields, never `byte[]`.
- The `UuidGenerator` functional interface (`UUID newId()`) in `identity.domain` is the injection seam; `UuidV7Generator` in `identity.infrastructure.crypto` is the production implementation. Tests stub the interface with fixed UUIDs.
- Supply-chain note: `uuid-creator` 6.1.1 (MIT). No Bouncy Castle transitive dependency — confirmed via `mvn dependency:tree` during T-001. This library is NOT managed by the Spring Boot BOM and must remain explicitly pinned in `pom.xml`.

## Alternatives considered

**ULID (CHAR(26)):**
- Also time-ordered, but 26 chars text encoding → larger storage, larger FK columns.
- Requires a custom ULID library; `java.util.UUID` does not natively represent ULIDs.
- Ruled out in favour of UUIDv7 which achieves the same ordering benefit with standard types and smaller storage.

**UUIDv4 (random):**
- No sequential ordering → random B-tree inserts → page fragmentation under load.
- Ruled out on performance grounds.

**Auto-increment BIGINT:**
- Enumerable (leaks row count), no natural global uniqueness across shards.
- Ruled out: the platform targets multi-tenant distributed architecture.

**TSID (CHAR(13)):**
- Smaller than UUID but less tooling support; not an IETF standard.
- Ruled out in favour of standardisation.

## Rationale

- **Time-ordered → sequential B-tree inserts**: UUIDv7 embeds a 48-bit Unix millisecond timestamp in the most-significant bits, which orders new rows at the tail of the B-tree index, avoiding page splits under write load.
- **16 bytes**: 10 bytes smaller per key than a 26-char ULID text column; compounds on every FK column and every index entry.
- **Standard UUID type**: `java.util.UUID` interop across JDBC, JPA, Jackson, and developer tooling without custom serialisers.
- **RFC 9562 compliant**: UUIDv7 is an IETF standard, not a proprietary extension.

## Consequences

Positive:
- Sequential inserts maintain index locality; B-tree fragmentation minimised under write load.
- 16-byte FK and index entries reduce storage vs ULID alternatives.
- Standard `java.util.UUID` works without custom serialisers.
- Injectable `UuidGenerator` port makes ID generation testable with fixed stubs.

Negative:
- `BINARY(16)` columns are not human-readable in SQL clients; use `BIN_TO_UUID(id)` for ad-hoc queries.
- UUIDv7 embeds creation timestamp — accepted for internal PKs (creation time is not a secret in this system).
- One new pinned dependency (`uuid-creator`) must be kept up to date and scanned by OWASP dependency-check.

Follow-on:
- Every future bounded context must use `UuidGenerator` for PK generation.
- Update `docs/coding-standards.md` line 29 to reference this ADR (done in this task).
- Scan `uuid-creator` in every `-Psecurity` dependency-check run.
