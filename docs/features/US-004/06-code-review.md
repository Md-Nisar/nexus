# US-004 Code Review

Status: CHANGES REQUESTED  
Reviewer: code-reviewer agent (fresh context)  
Date: 2026-06-24  
Scope: `git diff origin/main…HEAD` + new untracked files (dashboard component, E2E spec)

---

## Verdict: CHANGES REQUESTED

| Severity | Count |
|----------|-------|
| Blocker  | 2     |
| High     | 2     |
| Medium   | 3     |
| Low/Nit  | 2     |

---

## Findings

### [BLOCKER] — `finalize` fires per-subscriber in proactive path, prematurely nulling `refreshInFlight`

**File:** `nexus-frontend/src/app/core/http/auth.interceptor.ts`  
**Line:** 42–47

**Issue:** The proactive path builds `refreshInFlight` with `shareReplay(1)` placed **before** `finalize`:

```typescript
refreshInFlight = authService.refresh().pipe(
  shareReplay(1),
  finalize(() => {
    refreshInFlight = null;
  }),
);
```

`shareReplay(1)` multicasts the source to all subscribers but each subscriber receives its own downstream chain including the `finalize`. This means `finalize` fires once per subscriber when *that subscriber's chain* completes — not once when the shared source fully completes. In the thundering-herd scenario (two concurrent requests both in the proactive path), the first request to flush its forwarded HTTP call will run `refreshInFlight = null` while the second request is still forwarding its own call. A third request arriving between those two completions will see `refreshInFlight = null`, call `authService.refresh()` a second time, and issue a second `POST /refresh` — the very race the guard is designed to prevent.

The reactive-401 path has the **correct** ordering: `finalize` is upstream of `shareReplay`.

**Why it matters:** Under burst load with a near-expiry session, multiple refresh calls issue to the backend. Each `POST /refresh` rotates the token; the second call presents the already-rotated token and may trigger theft detection, revoking the entire token family and force-logging the user out.

**Fix:** Swap the operator order to match the reactive path:

```typescript
refreshInFlight = authService.refresh().pipe(
  finalize(() => {
    refreshInFlight = null;
  }),
  shareReplay(1),
);
```

---

### [BLOCKER] — `catchError` in proactive path catches errors from the forwarded request, not only refresh failures

**File:** `nexus-frontend/src/app/core/http/auth.interceptor.ts`  
**Line:** 49–58

**Issue:** The proactive `catchError` is placed after `switchMap(() => next(...))`:

```typescript
return refreshInFlight.pipe(
  switchMap(() =>
    next(req.clone({ ... })),
  ),
  catchError((err) => {
    authStore.clearSession();
    router.navigate(['/auth/login']);
    return throwError(() => err);
  }),
);
```

`catchError` here catches errors from *both* `refreshInFlight` (the refresh call) **and** `next(...)` (the forwarded original request). If the original request returns a 403, 500, or a network timeout, `clearSession()` is called and the user is silently logged out and redirected to `/auth/login`. Only refresh failures should trigger session teardown.

**Why it matters:** A transient 503 on any protected API endpoint will log the user out mid-session.

**Fix:** Scope `catchError` only to the refresh observable, before the `switchMap`:

```typescript
return refreshInFlight.pipe(
  catchError((err) => {
    authStore.clearSession();
    router.navigate(['/auth/login']);
    return throwError(() => err);
  }),
  switchMap(() =>
    next(req.clone({ setHeaders: { Authorization: `Bearer ${authStore.accessToken()}` } })),
  ),
);
```

---

### [HIGH] — Missing required cross-path thundering-herd test (threat-model T-2, second bullet)

**File:** `nexus-frontend/src/app/core/http/auth.interceptor.spec.ts`

**Issue:** The threat model (`03b-threat-model.md` §5) explicitly requires: *"Proactive refresh in flight + a concurrent reactive 401 → still one shared `POST /refresh` (cross-path guard)."* No such test exists. T2-1 tests the thundering-herd *within* the proactive path but not the cross-path scenario where one request enters the proactive branch (creating `refreshInFlight`) and a concurrent request, already past the interceptor, receives a 401 and enters the reactive branch — both must reuse the same `refreshInFlight`.

**Fix:** Add a test:
1. Set `nearExpirySession()`.
2. Subscribe to request A — enters proactive path, `refreshInFlight` created (use `Subject` so it doesn't emit yet).
3. Subscribe to request B, flush B's forwarded HTTP call with 401 — enters reactive `catchError`.
4. Assert `mockAuthService.refresh` called exactly once (not twice).

---

### [HIGH] — Dashboard route added without `authGuard`

**File:** `nexus-frontend/src/app/app.routes.ts`  
**Line:** 16–19

**Issue:** An `authGuard` exists in the project (`src/app/core/guards/auth.guard.ts`) and is already tested. The new `/dashboard` route is added without `canActivate: [authGuard]`. An unauthenticated user can navigate to `/dashboard`; the reactive interceptor will eventually redirect them to login but only after a visible network round-trip.

**Fix:**

```typescript
{
  path: 'dashboard',
  canActivate: [authGuard],
  loadComponent: () =>
    import('./features/dashboard/dashboard.component').then((m) => m.DashboardComponent),
},
```

---

### [MEDIUM] — `DashboardComponent` subscribes without `takeUntilDestroyed`

**File:** `nexus-frontend/src/app/features/dashboard/dashboard.component.ts`  
**Line:** 21–24

**Issue:** The HTTP subscription is fire-and-forget. Angular's `HttpClient` observables complete after one emission, so there is no leak today. However, the pattern will cause a real leak the moment any long-lived observable is added to this component.

**Fix:** Use `takeUntilDestroyed(inject(DestroyRef))`.

---

### [MEDIUM] — `shareReplay(1)` without `refCount: true` is fragile

**File:** `nexus-frontend/src/app/core/http/auth.interceptor.ts`  
**Line:** Proactive path (new) and reactive path (pre-existing)

**Issue:** `shareReplay(1)` defaults to `refCount: false` — the internal `ReplaySubject` never unsubscribes from its source even when all subscribers leave. Benign today because `authService.refresh()` always completes. Fragile against future changes.

**Fix:** `shareReplay({ bufferSize: 1, refCount: true })` on both paths.

---

### [MEDIUM] — `TEST_SESSION.expiresAt` evaluated at module-import time

**File:** `nexus-frontend/src/app/core/http/auth.interceptor.spec.ts`  
**Line:** 17

**Issue:** `expiresAt: Date.now() + 3600 * 1000` is fixed at module load. In a long-running test runner session this creeps backward. Not immediately dangerous (3600s margin is enormous) but inconsistent with `nearExpirySession()` which correctly captures `Date.now()` at call time.

**Fix:** Acknowledge as acceptable given the large margin, or move to a `beforeEach`-refreshed factory.

---

### [LOW] — E2E TS-1: `waitForLoadState('networkidle')` is fragile for SPAs with polling/streaming

**File:** `nexus-frontend/e2e/auth/session-refresh.spec.ts`  
**Line:** 76

**Issue:** `waitForLoadState('networkidle')` will never resolve if a WebSocket or polling interval is added to the dashboard.

**Fix:** Replace with `await page.waitForResponse('**/api/v1/users/me')` to wait for the specific request that triggers the proactive refresh.

---

### [NIT] — Multi-sentence comment block on proactive branch re-explains the code

**File:** `nexus-frontend/src/app/core/http/auth.interceptor.ts`  
**Line:** 29–35

**Issue:** Five-line block comment partially re-states what the code already shows. The cross-tab safety rationale and design-section reference are worth keeping; the paraphrasing of `AUTH_PATHS` exclusion and `shareReplay(1)` sentence are redundant.

**Fix:** Trim to the genuine "why" (cross-tab safety note + AC-4 reference).

---

### [NIT] — `freshSession()` helper not implemented despite being specified in task breakdown

**File:** `nexus-frontend/src/app/core/http/auth.interceptor.spec.ts`  
**Line:** After `nearExpirySession` helper

**Issue:** `04-tasks.md` IMPL-02 "Setup additions" specifies both `nearExpirySession(msRemaining = 60_000)` and `freshSession()`. Only the former was added; P-2 uses `TEST_SESSION` directly. Functionally fine but inconsistent with the spec and less self-documenting.

**Fix:** `function freshSession(): AuthSession { return { ...TEST_SESSION, expiresAt: Date.now() + 900_000 }; }`

---

## What is correct

- The `expiresAt - Date.now() < PROACTIVE_REFRESH_THRESHOLD_MS` check, the `isAuthEndpoint` infinite-loop guard, the `refreshInFlight` sharing *intent*, the `finalize` reset, and the `authStore.accessToken()` read inside `switchMap` post-refresh all match the design exactly.
- Tests P-1 through P-5, T5-1, and T3-1 are well-structured and test the right invariants.
- T2-1 correctly uses a `Subject` to hold the refresh open long enough for both subscriptions to register.
- The E2E structure (intercepting login response to inject short `expiresIn`, counting refresh calls via pass-through intercept, skipping gracefully when the backend is down) is solid.
- The dashboard stub — including `catchError(() => EMPTY)` to swallow interceptor-rethrown errors — is an acceptable scaffold.
