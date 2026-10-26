import type { PageLinks, PageMetadata } from './rbac';

/**
 * Wire types of the tenant user directory (US-019). Pinned to the recorded responses in
 * `contracts/api` by `api-contract.spec.ts`.
 */

/** Throttle codes of the directory endpoints (429 with `Retry-After`). */
export type DirectoryErrorCode = 'USER_DIR_001' | 'USER_DIR_002';

export type UserStatus = 'PENDING' | 'ACTIVE' | 'LOCKED' | 'DISABLED';

export interface UserDirectoryEntry {
  readonly userId: string;
  readonly email: string;
  readonly status: UserStatus;
  readonly emailVerified: boolean;
  readonly createdAt: string;
}

export interface UserDirectoryPage {
  readonly data: readonly UserDirectoryEntry[];
  readonly page: PageMetadata;
  readonly links: PageLinks;
}

export interface UserLookupRequest {
  readonly email: string;
}

export interface UserLookupResponse {
  readonly data: readonly UserDirectoryEntry[];
}
