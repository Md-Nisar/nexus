---
name: api-design
description: Use when designing or reviewing REST API endpoints for the Nexus platform. Covers URL design, status codes, request/response shape, error format, pagination, versioning, and idempotency.
---

# API Design Standards for Nexus

## URL design

- Resources are nouns, plural: `/users`, `/orders`, `/invoices`.
- Sub-resources express ownership: `/users/{userId}/orders`.
- Actions on a resource: prefer state changes via PATCH; reserve verb routes (`/orders/{id}/cancel`) for non-CRUD operations that don't map cleanly to a field update.
- Use kebab-case for multi-word path segments: `/payment-methods`.
- Query params for filtering / sorting / pagination, never for identity.

## HTTP methods

| Method | Use                                | Idempotent | Body |
|--------|------------------------------------|------------|------|
| GET    | Read                               | Yes        | No   |
| POST   | Create (server assigns ID), or non-idempotent action | No  | Yes |
| PUT    | Replace (client provides full state) | Yes      | Yes  |
| PATCH  | Partial update                     | Yes (if same body) | Yes |
| DELETE | Remove                             | Yes        | No   |

## Status codes

- **200 OK** — Success with body
- **201 Created** — Resource created; include `Location` header
- **202 Accepted** — Async work accepted; include status URL in body
- **204 No Content** — Success, no body (typical for DELETE)
- **400 Bad Request** — Validation failure; body explains
- **401 Unauthorized** — No or invalid credentials
- **403 Forbidden** — Authenticated but not permitted
- **404 Not Found** — Resource doesn't exist (or caller can't see it)
- **409 Conflict** — Version mismatch, duplicate, state conflict
- **422 Unprocessable Entity** — Semantic validation failure
- **429 Too Many Requests** — Rate limited; include `Retry-After`
- **500 Internal Server Error** — Unhandled server error
- **503 Service Unavailable** — Downstream dependency down

**Never** return 200 for an error.

## Request / response shape

### Requests

- JSON body for POST / PUT / PATCH.
- Required `Content-Type: application/json`.
- Validate at the controller boundary with bean validation.
- *(Target — not yet configured)* Reject unknown fields (`fail-on-unknown-properties=true`) — protects against typos and prevents silent feature drift. Don't flag existing endpoints for this in review; raise it as a separate change.

### Responses

- JSON only. UTF-8.
- Field naming: `camelCase`.
- ISO 8601 for dates: `"2025-11-12T14:30:00Z"`. UTC unless explicitly otherwise.
- IDs are strings (even if backed by numerics) — prevents JS precision loss.
- Money: object `{ "amount": 1299, "currency": "USD" }` with amount as minor units (cents).
- Booleans default to `false`; never `null` unless tri-state semantics are needed.

### Collections

```json
{
  "data": [ ... ],
  "page": { "size": 20, "number": 0, "totalElements": 142, "totalPages": 8 },
  "links": { "next": "/users?page=1", "prev": null }
}
```

- Always paginate list endpoints. Default page size 20, max 100.
- Cursor pagination for high-volume endpoints; offset for typical ones.

## Error format

**Every** non-2xx response is an RFC 9457 `ProblemDetail` (`application/problem+json`) produced by `GlobalExceptionHandler` — never a custom error DTO:

```json
{
  "type": "about:blank",
  "title": "Bad Request",
  "status": 400,
  "detail": "Request validation failed.",
  "instance": "/api/v1/users",
  "code": "VALIDATION_FAILED",
  "traceId": "abc123-def456",
  "details": [
    { "field": "email", "message": "must be a well-formed email address" }
  ]
}
```

- `code` is machine-readable, stable, SCREAMING_SNAKE_CASE (e.g. `VALIDATION_FAILED`, `RBAC_001`).
- `detail` is human-readable; safe to display in UI (no internal details).
- `traceId` is the request's correlation ID (MDC `correlationId`, echoed in the `X-Correlation-Id` response header).
- `details` only for validation errors; each entry is `{ field, message }`.
- Handlers may add specific extra properties (e.g. `requiredPermission` on `RBAC_001`).
- **Never** include stack traces, SQL, internal IDs, or system file paths.

## Versioning

- URI versioning: `/api/v1/...`, `/api/v2/...`.
- Bump major version only for breaking changes.
- Run old and new versions in parallel during deprecation (minimum one quarter).
- Deprecation: `Deprecation: true` header + `Sunset` header with date.

## Idempotency

*(Target — not yet implemented. Design new write endpoints so it can be added; don't flag existing endpoints for missing it.)*

- All write endpoints should accept an `Idempotency-Key` header.
- Server stores the key + response for a TTL (typically 24h).
- Replay returns the cached response, not a re-execution.

## Caching

- `Cache-Control` on GET responses.
- `ETag` for resources that benefit from conditional GET.
- `If-Match` on PUT/PATCH for optimistic concurrency:
  - Match → apply
  - Mismatch → 412 Precondition Failed

## Authentication & authorization

- JWT in `Authorization: Bearer <token>`.
- Every endpoint declares its auth requirement explicitly — no default-allow.
- Object-level authorization at the service layer — never trust the client-provided owner ID.
- Tenant ID extracted from the token, not the request body or path.

## Rate limiting

- Public endpoints: rate-limited by IP and by token (today: login, via `LoginRateLimitFilter`).
- 429 (and 423 account-locked) responses include `Retry-After` in seconds.
- *(Target — not yet implemented)* `X-RateLimit-Limit` / `-Remaining` / `-Reset` headers on every response.

## Observability

- Every request gets a correlation ID (`CorrelationIdFilter`): propagated from the `X-Correlation-Id` request header if present, generated otherwise, and echoed on the response.
- Log fields: `correlationId`, `userId`, `tenantId`, `endpoint`, `status`, `durationMs`.
- Emit metrics: request count by status, p50/p95/p99 latency by endpoint.

## Documentation

- Springdoc / OpenAPI annotations on every controller and DTO.
- Examples in `@Schema(example = "...")` for non-obvious fields.
- Spec exposed at `/v3/api-docs`; UI at `/swagger-ui.html` (non-prod environments only).

## Forbidden

- Verbs in URLs except for clear action endpoints (`/orders/{id}/cancel`)
- Returning different shapes from the same endpoint based on input
- 200 with `{ "success": false }` body
- Embedding tokens in URLs (query params or path)
- Returning HTML from a JSON API
- Snake_case field names
- `null` where empty string / empty array makes the contract clearer
