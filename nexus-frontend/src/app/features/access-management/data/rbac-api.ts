import { HttpClient, HttpResponse } from '@angular/common/http';
import { Service, inject } from '@angular/core';
import { Observable, map } from 'rxjs';
import { APP_CONFIG } from '../../../core/config/app-config';
import { CORRELATION_HEADER } from '../../../core/http/correlation-id.interceptor';
import { LoggerService } from '../../../core/logging/logger.service';
import type {
  AssignRoleRequest,
  CallerAuthorizationResponse,
  CreateRoleRequest,
  PermissionListResponse,
  PermissionPageResponse,
  PermissionResponse,
  ReplaceRolePermissionsRequest,
  RoleAssignmentListResponse,
  RoleAssignmentResponse,
  RoleListResponse,
  RoleResponse,
} from '../../../shared/types/api/rbac';
import type { AppError } from '../../../shared/types/app-error';
import { consoleHttpContext } from './console-http';
import { EtagState, classifyEtag } from './etag';
import { retryOnceOnClassificationChange } from './retry-once';

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
export function pathSegment(id: string): string {
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
 * `authInterceptor`. The one retry is the write path's single re-send on `RBAC_012`
 * ({@link retryOnceOnClassificationChange}); reads never retry, and this client never refreshes the
 * session (ADR-0028).
 */
@Service()
export class RbacApi {
  private readonly http = inject(HttpClient);
  private readonly logger = inject(LoggerService);
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
   * `PUT /roles/{id}/permissions`: replaces the role's whole set in one atomic call (`role:write`
   * and live `role:read`, us015 flag; design §7.1, §7.2, §7.3).
   *
   * - `ifMatch` is the strong tag of the set the user reviewed, sent **verbatim** as `If-Match`
   *   (quotes included, never altered); the caller holds only strong tags (`classifyEtag`).
   * - The 200 (applied or no-op) carries the new set and its new tag, so no re-read follows.
   * - A 409 `RBAC_012` is re-sent once with the same body and tag; every other failure, including
   *   412 and 428, surfaces for the editor to handle (no automatic resubmit, SD-9).
   */
  replaceRolePermissions(
    id: string,
    permissionIds: readonly string[],
    ifMatch: string,
  ): Observable<VersionedPermissionSet> {
    const body: ReplaceRolePermissionsRequest = { permissionIds };
    return retryOnceOnClassificationChange(
      () =>
        this.http.put<PermissionListResponse>(
          `${this.base}/roles/${pathSegment(id)}/permissions`,
          body,
          {
            headers: { 'If-Match': ifMatch },
            observe: 'response',
            context: consoleHttpContext(),
          },
        ),
      { operation: 'replace', roleId: id },
      this.logger,
    ).pipe(map(toVersionedSet));
  }

  /**
   * `POST /roles`: creates a custom role with exactly a name and a description (`role:write`,
   * us015 flag; design §7.1, §11.3). The 201 body is the new role. Never re-sent: a create is not
   * idempotent, so even `RBAC_012` surfaces.
   */
  createRole(body: CreateRoleRequest): Observable<RoleResponse> {
    const request: CreateRoleRequest = { name: body.name, description: body.description };
    return this.http.post<RoleResponse>(`${this.base}/roles`, request, {
      context: consoleHttpContext(),
    });
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

  /**
   * `GET /users/{id}/roles?page&size`: one page of a user's active role assignments (`user:read`,
   * us012 flag; design §7.1). `assignedBy` is `null` where the caller may not see it. A missing
   * and another tenant's user are the same 404 `USER_NOT_FOUND`. The id is one path segment.
   */
  listAssignments(
    userId: string,
    page: number,
    size: number,
  ): Observable<RoleAssignmentListResponse> {
    return this.http.get<RoleAssignmentListResponse>(
      `${this.base}/users/${pathSegment(userId)}/roles`,
      { params: { page, size }, context: consoleHttpContext() },
    );
  }

  /**
   * `POST /users/{id}/roles` `{roleId}`: assigns one role to a user (`user:role:assign`, us012
   * flag; design §7.1, §7.3). The 201 body is the new assignment.
   *
   * - A 409 `RBAC_012` (the role's classification changed while the request waited; nothing was
   *   applied) is re-sent once with the same body ({@link retryOnceOnClassificationChange}).
   * - Everything else surfaces for the dialog: 403 with its reason (including `SELF_ASSIGNMENT`),
   *   409 `RBAC_004` (already held: convergent), `RBAC_010`, a second `RBAC_012`, 429 `RBAC_011`,
   *   503. A 401 is renewed and replayed by `authInterceptor`; the filter refused it before the
   *   handler, so the replay is the first execution (SD-11).
   */
  assignRole(userId: string, roleId: string): Observable<RoleAssignmentResponse> {
    const body: AssignRoleRequest = { roleId };
    return retryOnceOnClassificationChange(
      () =>
        this.http.post<RoleAssignmentResponse>(
          `${this.base}/users/${pathSegment(userId)}/roles`,
          body,
          { context: consoleHttpContext() },
        ),
      { operation: 'assign', roleId },
      this.logger,
    );
  }

  /**
   * `DELETE /users/{id}/roles/{roleId}`: revokes one active assignment (`user:role:assign`, us012
   * flag; design §7.1, §11.4). Emits once on the 204, then completes. Both ids are one path
   * segment each.
   *
   * Never re-sent. Everything surfaces for the dialog: 403 with its reason (always before any 409,
   * so a caller who may not revoke never learns that a role guards the last administrator), 404
   * `ROLE_ASSIGNMENT_NOT_FOUND` (already removed: convergent), 409 `RBAC_002` (the last
   * administrator: nothing changed), 429 `RBAC_011`, 503. A 401 is renewed and replayed by
   * `authInterceptor`.
   */
  revokeRole(userId: string, roleId: string): Observable<void> {
    return this.http
      .delete<null>(`${this.base}/users/${pathSegment(userId)}/roles/${pathSegment(roleId)}`, {
        context: consoleHttpContext(),
      })
      .pipe(map((): void => undefined));
  }
}
