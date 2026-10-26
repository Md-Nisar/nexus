import { HttpClient, HttpParams } from '@angular/common/http';
import { Service, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { APP_CONFIG } from '../../../core/config/app-config';
import type {
  UserDirectoryEntry,
  UserDirectoryPage,
  UserLookupRequest,
  UserLookupResponse,
  UserStatus,
} from '../../../shared/types/api/user-directory';
import { consoleHttpContext } from './console-http';
import { pathSegment } from './rbac-api';

/** One page of the directory: zero-based `page`, `size` 1 to 100, and an optional status filter. */
export interface ListUsersQuery {
  readonly page: number;
  readonly size: number;
  readonly status?: UserStatus;
}

/**
 * Stateless client of the tenant user directory (US-019; US-020 design §7.1), under the us019
 * flag and `user:directory:read`. Paths are relative to `${apiBaseUrl}/v1`; every request carries
 * {@link consoleHttpContext}, so a 403 stays with the console (FR-F4).
 *
 * - **No address in a URL** (SD-13): the exact-email lookup is a `POST` with the address in the
 *   JSON body only, so it never reaches the URL, history, an access log or a `Referer`.
 * - Errors arrive as `AppError` from `apiErrorInterceptor`. Nothing is retried here: a 429 waits
 *   for the user (design §7.4), and this client never refreshes the session (ADR-0028).
 * - It logs nothing; callers log codes and ids only, never an address.
 */
@Service()
export class DirectoryApi {
  private readonly http = inject(HttpClient);
  private readonly base = `${inject(APP_CONFIG).apiBaseUrl}/v1/users`;

  /**
   * `GET /users?page&size&status`: one page of the tenant's users in id order. A `page` times
   * `size` beyond 10,000 is a 400 `VALIDATION_FAILED` (US-019 N10); a busy directory is a 429
   * `USER_DIR_002`.
   */
  listUsers(query: ListUsersQuery): Observable<UserDirectoryPage> {
    let params = new HttpParams().set('page', query.page).set('size', query.size);
    if (query.status !== undefined) params = params.set('status', query.status);
    return this.http.get<UserDirectoryPage>(this.base, {
      params,
      context: consoleHttpContext(),
    });
  }

  /**
   * `GET /users/{id}`: one user of the tenant. A missing id and another tenant's id are the same
   * 404 `USER_NOT_FOUND` (SD-20). The id is encoded as one path segment.
   */
  getUser(id: string): Observable<UserDirectoryEntry> {
    return this.http.get<UserDirectoryEntry>(`${this.base}/${pathSegment(id)}`, {
      context: consoleHttpContext(),
    });
  }

  /**
   * `POST /users/lookup` `{ email }`: the tenant's user with exactly this address, or none (a miss
   * and another tenant's user look the same). Throttled per caller: 429 `USER_DIR_001`.
   */
  lookupUser(email: string): Observable<UserLookupResponse> {
    const body: UserLookupRequest = { email };
    return this.http.post<UserLookupResponse>(`${this.base}/lookup`, body, {
      context: consoleHttpContext(),
    });
  }
}
