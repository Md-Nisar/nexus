import { inject } from '@angular/core';
import { CanMatchFn } from '@angular/router';
import { APP_CONFIG } from '../config/app-config';

/**
 * Release control for the access management console (US-020 design §4.3, §18; RC-76).
 *
 * Matches `/admin/access` only when `AppConfig.accessConsoleEnabled` is true; otherwise the router
 * falls through to the shell's `**` Not Found, still behind `authGuard`.
 *
 * It reads configuration and nothing else. `canMatch` runs in the recognition phase, before the
 * shell's `authGuard` has restored the session, so a guard here that read auth state would see an
 * empty session on a cold start (T-E57). `can-match-contract.spec.ts` holds every `canMatch` in
 * the route tree to a config-only allow-list.
 *
 * @security A release control, **not an access control**. Entry is gated by `anyPermissionGuard`
 * (UX only) and enforced by the server's `@RequiresPermission`.
 */
export const accessConsoleEnabledGuard: CanMatchFn = () => inject(APP_CONFIG).accessConsoleEnabled;
