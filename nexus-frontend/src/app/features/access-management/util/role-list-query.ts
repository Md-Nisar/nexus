import type { RoleResponse } from '../../../shared/types/api/rbac';

/** Rows per client-side page of the roles list (design §6.4). */
export const ROLE_PAGE_SIZE = 20;

export const ROLE_FILTERS = ['all', 'system', 'custom'] as const;
export type RoleFilter = (typeof ROLE_FILTERS)[number];

/** The filter a `filter` query parameter names; anything else is `all`. */
export function parseRoleFilter(raw: string | null): RoleFilter {
  return ROLE_FILTERS.find((filter) => filter === raw) ?? 'all';
}

export interface RoleQuery {
  /** Search text; trimmed, case-folded, matched literally against the name. */
  readonly q: string;
  readonly filter: RoleFilter;
  /** Zero-based page. */
  readonly page: number;
  readonly size: number;
}

export interface RoleQueryResult {
  readonly rows: readonly RoleResponse[];
  /** Roles that match the search and filter, over all pages. */
  readonly total: number;
  /** The page actually returned: the requested one clamped into range. */
  readonly page: number;
  /** At least 1, so an empty result is still one (empty) page. */
  readonly pageCount: number;
}

/**
 * Client-side search, filter, order and paging of the fetched roles (US-020 design §6.4).
 *
 * - **Search** is a substring match of the case-folded name. It is never a pattern, so regex
 *   characters match themselves.
 * - **Order** is a stable partition: system roles first, and inside each group the server's
 *   `(name, id)` order, which this function does not re-sort. A client collation could disagree
 *   with the server's.
 * - **Page** is clamped into range, so a stale `page` parameter shows the last page.
 *
 * Pure: the input is not modified.
 */
export function queryRoles(roles: readonly RoleResponse[], query: RoleQuery): RoleQueryResult {
  const needle = query.q.trim().toLowerCase();
  const matching = roles.filter(
    (role) =>
      (query.filter === 'all' || role.isSystemRole === (query.filter === 'system')) &&
      (needle === '' || role.name.toLowerCase().includes(needle)),
  );
  const ordered = [
    ...matching.filter((role) => role.isSystemRole),
    ...matching.filter((role) => !role.isSystemRole),
  ];
  const pageCount = Math.max(1, Math.ceil(ordered.length / query.size));
  const page = Math.min(Math.max(query.page, 0), pageCount - 1);
  return {
    rows: ordered.slice(page * query.size, (page + 1) * query.size),
    total: ordered.length,
    page,
    pageCount,
  };
}
