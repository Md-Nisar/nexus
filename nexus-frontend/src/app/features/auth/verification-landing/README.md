# Verification Landing Component

## Overview

The `VerificationLandingComponent` handles the email verification flow for user registration (US-002). It consumes a one-time email verification token from the URL and transitions the user's account from PENDING → ACTIVE status.

**Feature design:** `docs/features/US-002/03-design.md` § 10.11  
**Bounded context:** `identity`  
**Related stories:** US-002 (registration), US-003 (login)

---

## Responsibility

This component is the landing page users reach when clicking the verification link in their email. It:

1. **Extracts the token** from the `?token=` query parameter
2. **Clears the URL** by replacing history (security: prevents Referer header leakage and browser history exposure)
3. **Calls the backend** via `AuthService.verifyEmail(token)` to consume the token and activate the account
4. **Renders three state machines:**
   - `loading` → spinning sync icon while verification is in progress
   - `success` → checkmark icon, confirmation message, link to login
   - `error` → error icon, message with optional resend link (only shown if error code is `AUTH_VRF_002`)

---

## Component State

### Signals

```typescript
protected readonly state = signal<ViewState<void>>(loading);
```

- **Type:** `ViewState<void>` — union of `{ kind: 'loading' }`, `{ kind: 'success', value: void }`, `{ kind: 'error', error: AppError }`
- **Lifecycle:**
  - Initialized to `loading` on component creation
  - Set to `success` when token verification succeeds (200 from backend)
  - Set to `failure` when token is missing or verification fails (410, etc.)

### Computed

```typescript
protected readonly errorDetail = computed(() => {
  const s = this.state();
  return s.kind === 'error' ? s.error : null;
});
```

Safely extracts the error object for template binding. Returns `null` if state is not `error`.

---

## Business Logic

### Security: Token URL Removal

```typescript
// Line 42-43
this.router.navigate([], { 
  relativeTo: this.route, 
  queryParams: {}, 
  replaceUrl: true 
});
```

**Why:** Prevents token leakage via:
- **Referer header** — if the user navigates to another site while on this page, the HTTP Referer would include the token in the URL
- **Browser history** — the back button would not re-display the token in the address bar
- **Proxy/CDN logs** — query parameters are often logged; removing the token immediately reduces the window of exposure

This pattern mirrors the security hardening applied to password-reset links (US-007).

### Token Validation Flow

```typescript
// Line 44-57
if (!token) {
  this.state.set(failure<void>({
    code: 'INVALID_LINK',
    message: 'This verification link is invalid. Please use the link from your verification email.',
  }));
  return;
}

this.authService.verifyEmail(token).subscribe({
  next: () => this.state.set(success(undefined)),
  error: (err: AppError) => this.state.set(failure<void>(err)),
});
```

**Flow:**
1. Token missing → immediate failure with code `INVALID_LINK` (no backend call)
2. Token present → POST to `/api/v1/auth/verify-email` with the token
3. Success → account is ACTIVE, state = `success`
4. Failure → state = `error` with the error code and message from the backend

**Error codes from backend:**
- `AUTH_VRF_002` — token is invalid, expired, or already consumed (410 Gone)
  - If this code, the template shows a "Resend verification email" link
  - Any other error → no resend link shown

---

## Template States

The template uses `@switch` (control flow) to render three mutually exclusive views:

### `@case ('loading')`

Displays while the verification request is in flight:
- Spinning `sync` icon with `aria-hidden="true"` (decorative)
- Status message: "Verifying your email address…"
- `role="status"` — screen reader announces when the state changes

### `@case ('success')`

Displays after successful verification:
- Green checkmark icon (`check_circle`)
- Heading: "Email verified!"
- Message: "Your account is active. You can now log in."
- Link to `/auth/login` (labeled "Go to login")
- `role="status"` — semantic for successful completion

### `@case ('error')`

Displays if verification fails:
- Red error icon (`error_outline`)
- Heading: "Verification failed"
- Message: `{{ errorDetail()?.message }}`
- **Conditional resend link:** shown only if `errorDetail()?.code === 'AUTH_VRF_002'`
  - Navigates to `/auth/resend-verification` where the user can request a new token
  - Uses `data-testid="verif-resend"` for testing
- `role="alert"` — screen reader announces the error immediately

---

## Dependencies

```typescript
protected readonly authService = inject(AuthService);
protected readonly route = inject(ActivatedRoute);
protected readonly router = inject(Router);
private readonly queryParams = toSignal(this.route.queryParams, {
  initialValue: {} as Record<string, string>,
});
```

| Dependency | Role | From |
|------------|------|------|
| `AuthService` | Calls `verifyEmail(token)` → POST `/api/v1/auth/verify-email` | `../auth.service` |
| `ActivatedRoute` | Reads `?token=` query param via `toSignal` | Angular routing |
| `Router` | Navigates away from the verification page and to login/resend routes | Angular routing |

---

## Testing Notes

### Unit tests: `verification-landing.component.spec.ts`

Key scenarios:
- **Token missing** → failure state with `INVALID_LINK` code
- **Successful verification** → success state, "Go to login" link visible
- **Token expired/consumed** → error state with `AUTH_VRF_002`, "Resend" link visible
- **Network error** → error state with generic error message, no "Resend" link
- **URL cleaning** — after init, query params removed from the address bar
- **Screen reader access** — `role="status"` and `role="alert"` present in all states

### E2E / Integration tests

Full flow:
1. User clicks verification email link → navigates to `/auth/verify-email?token=xxx`
2. Component removes the token from the URL
3. Backend returns 200 (success) or 410 (expired)
4. User sees success or error state
5. Clicking "Go to login" navigates to the login page

---

## Related Code

| File | Purpose |
|------|---------|
| `docs/features/US-002/03-design.md` | Full design including VerifyEmailUseCase, token format, and API contract |
| `docs/features/US-002/03b-threat-model.md` | Security considerations for email verification |
| `nexus-frontend/src/app/features/auth/auth.service.ts` | `verifyEmail(token)` call |
| `nexus-frontend/src/app/shared/types/view-state.ts` | `ViewState<T>` and helper functions |
| `nexus-backend/src/main/java/.../VerifyEmailUseCase.java` | Backend implementation |

---

## Known Limitations & Future Work

- **Token format validation is client-side only** — the component checks for token presence but doesn't validate the hex format (64 lowercase hex chars). The backend enforces the full pattern with `@Pattern`.
- **No retry mechanism** — if verification fails, the user must click the email link again or request a resend. Auto-retry was deemed unnecessary for the happy path.
- **Single-page refresh** — if the user hits F5 on the success page, the token is gone (removed from URL), so they see `INVALID_LINK`. This is intentional (no silent retry with a stale token).
