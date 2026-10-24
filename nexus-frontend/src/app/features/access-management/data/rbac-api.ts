import { HttpClient, HttpResponse } from '@angular/common/http';
import { Service, inject } from '@angular/core';
import { Observable, map } from 'rxjs';
import { APP_CONFIG } from '../../../core/config/app-config';
import { CORRELATION_HEADER } from '../../../core/http/correlation-id.interceptor';
import type {
  CallerAuthorizationResponse,
  PermissionListResponse,
  PermissionPageResponse,
  PermissionResponse,
  RoleListResponse,
  RoleResponse,
} from '../../../shared/types/api/rbac';
import type { AppError } from '../../../shared/types/app-error';
import { consoleHttpContext } from './console-http';
import { EtagState, classifyEtag } from './etag';

/**
 * A role's permission set with the version tag it was read at (design §7.1).
 *
 * `correlationId` is the `X-Correlation-Id` the server echoed for this read (exposed through
 * CORS), or `null`: the reference the page shows when the tag is unusable (design §7.2).
 */
export interface VersionedPermissionSet {
  readonly permissions: readonly PermissionResponse[];
  readonly etag: EtagState;
  readonly correlationId: string | null;
}

/**
 * One path segment for an id taken from the URL. The router decodes route parameters, so a crafted
 * link could otherwise carry `/` or `..` into the API path; `.` is encoded too, because
 * `encodeURIComponent` leaves it, and a `..` segment would resolve to the parent path.
 */
function pathSegment(id: string): string {
  return encodeURIComponent(id).replaceAll('.', '%2E');
}

function toVersionedSet(response: HttpResponse<PermissionListResponse>): VersionedPermissionSet {
  if (response.body === null) {
    // A 200 without a body would otherwise look like a role that grants nothing.
    const error: AppError = {
      code: 'UNEXPECTED_ERROR',
      message: 'The permission set response had no body.',
    };
    throw error;
  }
  return {
    permissions: response.body.data,
    etag: classifyEtag(response.headers.get('ETag')),
    correlationId: response.headers.get(CORRELATION_HEADER),
  };
}

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

  /**
   * `GET /roles?page&size`: one page of the tenant's roles in `(name, id)` order (`role:read`,
   * us015 flag). `page` is zero-based.
   */
  listRoles(page: number, size: number): Observable<RoleListResponse> {
    return this.http.get<RoleListResponse>(`${this.base}/roles`, {
      params: { page, size },
      context: consoleHttpContext(),
    });
  }

  /** `GET /roles/{id}`: one role (`role:read`, us015 flag). It carries no `ETag` (design B-1). */
  getRole(id: string): Observable<RoleResponse> {
    return this.http.get<RoleResponse>(`${this.base}/roles/${pathSegment(id)}`, {
      context: consoleHttpContext(),
    });
  }

  /**
   * `GET /roles/{id}/permissions`: the role's permission set and its `ETag`, read with
   * `observe: 'response'` and classified by {@link classifyEtag} (design §7.2). The tag is the
   * only input a later save may send as `If-Match`; this client never alters it.
   */
  getRolePermissions(id: string): Observable<VersionedPermissionSet> {
    return this.http
      .get<PermissionListResponse>(`${this.base}/roles/${pathSegment(id)}/permissions`, {
        observe: 'response',
        context: consoleHttpContext(),
      })
      .pipe(map(toVersionedSet));
  }

  /**
   * `GET /permissions?page&size`: one page of the permission catalogue ordered by name
   * (`role:read`, us015 flag). `page` is zero-based.
   */
  listPermissions(page: number, size: number): Observable<PermissionPageResponse> {
    return this.http.get<PermissionPageResponse>(`${this.base}/permissions`, {
      params: { page, size },
      context: consoleHttpContext(),
    });
  }
}
