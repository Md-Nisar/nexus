import { HttpContext } from '@angular/common/http';
import { SKIP_ACCESS_DENIED_REDIRECT } from '../../../core/http/skip-access-denied-redirect';

/**
 * The request context of every console call (US-020 design §6.5, §7; FR-F4): a 403 `RBAC_001`
 * stays with the console, which explains it inline, instead of sending the user to Access Denied.
 *
 * A factory rather than one shared `HttpContext`, because a context is mutable and is carried by
 * the request through every interceptor.
 */
export function consoleHttpContext(): HttpContext {
  return new HttpContext().set(SKIP_ACCESS_DENIED_REDIRECT, true);
}
