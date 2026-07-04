# Dashboard Component

## Overview

The `DashboardComponent` is the main authenticated user interface. It serves as the landing page after successful login and provides the user with a logout button that revokes all server-side refresh tokens (US-005).

**Feature design:** `docs/features/US-005/03-design.md`  
**Bounded context:** `identity`  
**Related stories:** US-003 (login), US-004 (token refresh), US-005 (logout)

---

## Responsibility

This component:

1. **Loads user profile data** via `httpResource` (GET `/v1/users/me`) to trigger the auth interceptor's proactive token refresh logic
2. **Displays the user dashboard** (minimal in scope — currently shows only the heading and logout button)
3. **Provides logout functionality** that revokes the user's refresh token family server-side
4. **Handles logout side effects:**
   - Clears the session (removes tokens, cookies)
   - Shows success/error toast notifications
   - Redirects to login page
5. **Manages request state** (loading/disabled) while logout is in flight

---

## Component State

### Signals

```typescript
readonly loggingOut = signal(false);
```

- **Type:** `boolean`
- **Transitions:**
  - `false` → initial (button enabled)
  - `true` → after `onLogout()` is called (button disabled, shows spinner)
  - `false` → after logout completes or fails (via `finalize`)
- **Purpose:** Prevents duplicate logout submissions and shows loading state to the user

### httpResource

```typescript
readonly userProfile = httpResource(() => `${this.config.apiBaseUrl}/v1/users/me`);
```

- **Type:** Angular's `httpResource` (reactive async data fetcher)
- **Triggers:** On component initialization and whenever the API base URL changes
- **Purpose:** Loads user profile to prime the auth interceptor's proactive refresh mechanism
- **Result:** Not rendered in the template; exists for its side effect only
  - The auth interceptor watches all HTTP responses and triggers refresh logic if `expiresAt - now < 120 s`
  - This GET ensures the interceptor runs once per dashboard session, preventing a stale token scenario

---

## Business Logic & Security

### Logout Flow

```typescript
onLogout(): void {
  this.loggingOut.set(true);
  this.authService
    .logout()
    .pipe(finalize(() => this.loggingOut.set(false)))
    .subscribe({
      next: () => {
        this.toast.success('You have been logged out.');
        this.router.navigate(['/auth/login']);
      },
      error: () => {
        this.toast.error('Logout could not be confirmed, but your session was ended.');
        this.router.navigate(['/auth/login']);
      },
    });
}
```

**State machine:**

1. **Button clicked** → `loggingOut = true` (button disabled, spinner visible)
2. **POST /api/v1/auth/logout** (Bearer-authenticated with access token)
   - Backend: revokes all refresh tokens for the user via `LogoutUseCase`
   - Clears the `refreshToken` cookie (HttpOnly, SameSite=Strict)
   - Returns 204 No Content
3. **Success path:**
   - Show success toast: "You have been logged out."
   - Redirect to `/auth/login`
   - `finalize` hook resets `loggingOut = false`
4. **Error path (network failure, 401, 500, etc.):**
   - Show error toast: "Logout could not be confirmed, but your session was ended."
   - Still redirect to `/auth/login` (user is logged out client-side regardless)
   - `finalize` hook resets `loggingOut = false`

**Design decision:** The error path redirects to login because:
- The client has already cleared the session (via `AuthService.clearSession()`)
- The user's access token will expire soon (typical TTL: 15 min)
- A network error during logout is rare; the tokens are already invalidated server-side
- User experience is uniform: logout always leads to login

### Interceptor Integration

**Key note:** The auth interceptor **must not retry logout failures with token refresh.**

```typescript
// auth.interceptor.ts
const AUTH_PATHS = ['/api/v1/auth/logout'];  // Added in US-005
const isAuthEndpoint = AUTH_PATHS.some(path => req.url.includes(path));

if (error instanceof HttpErrorResponse && error.status === 401 && !isAuthEndpoint) {
  // Attempt proactive refresh (suppress during /logout)
}
```

**Why:** If logout returns 401 (token already expired), the interceptor would attempt to call `POST /refresh` to get a new token, which would resurrect the session. This is prevented by excluding `/logout` from the refresh retry logic.

---

## Revocation Strategy

**Decision:** **TTL-only revocation for GA.** (ADR-0008, fast-follow: `jti` denylist)

- **Refresh tokens:** Revoked immediately in the database via `LogoutUseCase.revokeByUserId(userId)`
  - All families for the user are revoked (not just the current login session)
  - A captured refresh cookie cannot be replayed
- **Access token:** Remains valid for its residual TTL (≤15 min)
  - The token may still be valid if presented to other services during logout
  - This is acceptable; the user's session is effectively ended client-side
  - Instant access-token revocation (via `jti` denylist) is a planned enhancement

---

## Template

The component uses an inline template (no `.html` file):

```typescript
template: `
  <main class="dashboard" data-testid="dashboard-root">
    <h1>Dashboard</h1>
    <nx-button
      variant="secondary"
      [loading]="loggingOut()"
      [disabled]="loggingOut()"
      data-testid="logout-button"
      (clicked)="onLogout()"
    >
      Log out
    </nx-button>
  </main>
`
```

**Key bindings:**
- `[loading]="loggingOut()"` — shows spinner on the button while logout is in progress
- `[disabled]="loggingOut()"` — prevents clicking while request is in flight
- `(clicked)="onLogout()"` — calls the logout method (note: custom `clicked` event, not `click`)
- `data-testid="logout-button"` — used in E2E/unit tests for selection

**Design notes:**
- Dashboard is intentionally minimal (Gate 1 decision) — no user profile display yet
- Button is secondary variant (not primary) to avoid visual prominence of logout
- No form or user input — only navigation and logout

---

## Dependencies

```typescript
private readonly config = inject(APP_CONFIG);
private readonly authService = inject(AuthService);
private readonly router = inject(Router);
private readonly toast = inject(NxToast);
```

| Dependency | Role | From |
|------------|------|------|
| `APP_CONFIG` | Provides `apiBaseUrl` for the user profile fetch | `core/config/app-config` |
| `AuthService` | Calls `logout()` → POST `/api/v1/auth/logout` and `clearSession()` | `features/auth/auth.service` |
| `Router` | Navigates to `/auth/login` after logout | Angular routing |
| `NxToast` | Shows success/error notifications | `shared/ui` |

---

## Testing Notes

### Unit tests: `dashboard.component.spec.ts`

Key scenarios:
- **Button visible** — logout button is rendered in the dashboard
- **Loading state** — `loggingOut` signal becomes `true` when logout is called, button is disabled
- **Success path** — success toast shown, navigation to `/auth/login` called
- **Error path** — error toast shown, still navigates to `/auth/login`
- **Cleanup** — `loggingOut` reset to `false` after completion (both success and error)
- **HTTP request** — `GET /v1/users/me` is called on init to trigger the interceptor's refresh logic

### E2E / Integration tests

Full scenario:
1. User is authenticated and navigates to dashboard
2. Component loads user profile (triggers interceptor's proactive refresh if needed)
3. User clicks "Log out"
4. Button shows loading spinner
5. Backend revokes all refresh tokens for the user
6. Client clears session and shows success toast
7. User redirected to login page
8. If user tries to refresh with an old refresh token → 401 (token was revoked)

---

## Related Code

| File | Purpose |
|------|---------|
| `docs/features/US-005/03-design.md` | Full design including LogoutUseCase, revocation strategy, and interceptor integration |
| `nexus-frontend/src/app/features/auth/auth.service.ts` | `logout()` call and `clearSession()` |
| `nexus-frontend/src/app/core/interceptors/auth.interceptor.ts` | Proactive refresh logic and AUTH_PATHS list |
| `nexus-frontend/src/app/shared/ui/nx-button.component.ts` | Button component with loading/disabled states |
| `nexus-frontend/src/app/shared/ui/nx-toast.service.ts` | Toast notifications |
| `nexus-backend/src/main/java/.../LogoutUseCase.java` | Backend implementation |

---

## Known Limitations & Future Work

- **Minimal dashboard** — currently shows only a heading and logout button. User profile display, settings, and navigation are out of scope for US-005.
- **No offline support** — logout requires an internet connection. If the network is down, the button will timeout and show an error toast, but the session is still cleared client-side.
- **Access token not instantly revoked** — if an access token is captured during logout, it can be replayed for up to 15 minutes. Fast-follow (ADR-0008) adds `jti` denylist for instant revocation.
- **No logout confirmation** — users clicking the logout button are not prompted to confirm. This is acceptable for a personal app; added confirmation can be considered for admin/multi-account scenarios.
