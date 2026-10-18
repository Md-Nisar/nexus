import { HttpContextToken } from '@angular/common/http';

/**
 * Opt-out for the 403 `RBAC_001` redirect in `apiErrorInterceptor` (US-018 C6).
 *
 * By default a 403 with code `RBAC_001` sends the user to the Access Denied page. A caller that
 * handles the denial inline (for example a button that probes a permission and shows a message)
 * sets this token on its request context and keeps the `AppError` for itself:
 *
 * ```ts
 * http.get(url, { context: new HttpContext().set(SKIP_ACCESS_DENIED_REDIRECT, true) });
 * ```
 *
 * The decision stays with the caller, which is why this is a context token and not a URL allow-list
 * (an allow-list drifts, like the backend `permitAll` list did).
 */
export const SKIP_ACCESS_DENIED_REDIRECT = new HttpContextToken<boolean>(() => false);
