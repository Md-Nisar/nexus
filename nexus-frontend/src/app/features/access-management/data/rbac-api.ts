import { HttpClient } from '@angular/common/http';
import { Service, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { APP_CONFIG } from '../../../core/config/app-config';
import type { CallerAuthorizationResponse } from '../../../shared/types/api/rbac';
import { consoleHttpContext } from './console-http';

/**
 * Stateless client of the RBAC and caller-profile endpoints the console uses (US-020 design §7.1).
 * Paths are relative to `${apiBaseUrl}/v1`. Every request carries {@link consoleHttpContext}, so a
 * 403 stays with the console instead of redirecting to Access Denied (FR-F4).
 *
 * Errors arrive as `AppError` from `apiErrorInterceptor`; a 401 is renewed and replayed by
 * `authInterceptor`. This client never retries and never refreshes the session (ADR-0028).
 */
@Service()
export class RbacApi {
  private readonly http = inject(HttpClient);
  private readonly base = `${inject(APP_CONFIG).apiBaseUrl}/v1`;

  /**
   * `GET /users/me/authorization`: the caller's live roles and permissions (authenticated only;
   * under the us019 flag, so a switched-off backend answers 404 `RESOURCE_NOT_FOUND`).
   */
  getMyAuthorization(): Observable<CallerAuthorizationResponse> {
    return this.http.get<CallerAuthorizationResponse>(`${this.base}/users/me/authorization`, {
      context: consoleHttpContext(),
    });
  }
}
