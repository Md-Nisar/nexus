# ADR 0010: Password-Reset Token Delivered as URL Query Parameter

**Status:** Accepted  
**Date:** 2026-07-01  
**Feature:** US-007 (Self-service password reset)

---

## Context

Password-reset tokens must be delivered to the user out-of-band (via email) and then presented back to the application. Common delivery mechanisms are:

1. **URL query parameter** — `https://app.example.com/auth/reset-password?token=<hex>` — conventional for email links; the user simply clicks the link.
2. **Body of a POST** — the email contains a short code the user types into a form.
3. **Fragment identifier** — `#token=<hex>` — not sent to the server; avoids access-log exposure but incompatible with server-side rendering.

The token has 256-bit entropy (32 bytes SecureRandom → 64-char hex). It is single-use, expires in 1 hour, and its SHA-256 hash is stored in the database (raw token never persisted).

---

## Decision

Deliver the token as a URL query parameter (`?token=<hex>`) in the email link.

After the Angular `ResetPasswordComponent` reads the token from `queryParamMap.get('token')` in `ngOnInit()`, it immediately strips the query string from the browser URL via:

```typescript
this.router.navigate([], { relativeTo: this.route, queryParams: {}, replaceUrl: true });
```

This replaces the browser history entry so the token does not persist in the address bar, Forward/Back history, or browser autofill.

The backend `PasswordResetController` is annotated with `@Tag(name = "Authentication", description = "Self-service password reset")` and each endpoint has `@Operation` + `@ApiResponse` for full OpenAPI documentation.

---

## Consequences

### Accepted risks

| Risk | Mitigation |
|------|------------|
| Token appears in server access logs for the frontend dev server / CDN | Frontend is a SPA served statically; no server-side routing logs the full URL. For production deployments behind a reverse proxy, `Referrer-Policy: no-referrer` must be set on the reset page. |
| Token visible in browser address bar between load and ngOnInit | `replaceUrl: true` removes it immediately in the same JS tick. Window is ~1 render frame. |
| Token in email client URL preview | Accepted; conventional for reset links. TTL is 1 hour; token is single-use. |
| Referer header leakage to third-party resources loaded on the reset page | The reset page loads no third-party resources. `Referrer-Policy: no-referrer` should be added at the CDN/reverse-proxy layer (deployment concern). |
| Shared-machine browser history | `replaceUrl: true` removes the URL from history. Accepted residual risk for shared machines (user should use private browsing). |

### Benefits

- Conventional UX: user clicks a single link — no code entry.
- Works in all email clients including plain-text renderers.
- The 256-bit entropy + 1-hour TTL + single-use enforcement makes online brute-forcing infeasible even if the URL appears in a log.

### Alternatives rejected

| Alternative | Why rejected |
|-------------|-------------|
| Fragment identifier (`#token=`) | Requires JavaScript to parse; incompatible with server-side OpenGraph rendering and some email clients that strip fragments. |
| Short numeric code (6-8 digits) | Requires form entry UX; much lower entropy unless explicitly rate-limited (brute-force risk even at 6 attempts/hour). |
| Signed JWT as token | Adds complexity; the simple hex+SHA256 pattern used elsewhere in Nexus is sufficient. |

---

## Related

- [ADR 0009](0009-requires-new-transaction-for-lockout-counters.md) — REQUIRES_NEW pattern reused for `recordFailure()` in `ResetPasswordUseCase`
- [ADR 0006](0006-email-blind-index-and-encryption.md) — email HMAC used for throttle lookup
- `SECURITY.md §6` — token entropy and storage requirements
- `docs/features/US-007/03b-threat-model.md` — full threat analysis (T-I2, T-S1, T-S2)
