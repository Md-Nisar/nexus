import { Service, inject } from '@angular/core';
import { AuthStore } from '../../../core/auth/auth.store';
import type { PermissionResponse, RoleResponse } from '../../../shared/types/api/rbac';

/** The role a Clone starts from and its permission set, as the role page read them. */
export interface CloneSource {
  readonly role: RoleResponse;
  readonly permissions: readonly PermissionResponse[];
}

/**
 * Hands the role page's read of a role to the Create page when the user presses Clone, so the
 * source is not read again (US-020 design §6.5 "Create": the source GET only "if not cached").
 * `RoleDetailStore` is scoped to `roles/:roleId` and cannot be reached from the sibling
 * `roles/new`, hence this hand-over.
 *
 * - Memory only (never storage), one entry, taken at most once.
 * - Keyed by the signed-in user: an entry offered by one user is never given to another, and
 *   nothing is kept while signed out.
 * - A deep link or a reload finds nothing and reads the source itself.
 */
@Service()
export class CloneSourceCache {
  private readonly auth = inject(AuthStore);
  private entry: (CloneSource & { readonly owner: string }) | null = null;

  /** Keeps `role` and its `permissions` for the next {@link take} by the same user. */
  offer(role: RoleResponse, permissions: readonly PermissionResponse[]): void {
    const owner = this.auth.currentUser()?.userId ?? null;
    this.entry = owner === null ? null : { owner, role, permissions };
  }

  /** The offered source of `roleId` for the signed-in user, or `null`. The entry is dropped. */
  take(roleId: string): CloneSource | null {
    const entry = this.entry;
    this.entry = null;
    const owner = this.auth.currentUser()?.userId ?? null;
    if (entry === null || owner === null || entry.owner !== owner || entry.role.id !== roleId) {
      return null;
    }
    return { role: entry.role, permissions: entry.permissions };
  }
}
