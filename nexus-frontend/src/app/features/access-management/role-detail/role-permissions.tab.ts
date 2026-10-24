import { Component, computed, inject } from '@angular/core';
import type { PermissionResponse } from '../../../shared/types/api/rbac';
import { NxEmptyState, NxSkeleton } from '../../../shared/ui';
import { CONSOLE_COPY } from '../copy/console-copy';
import { resolveConsoleError } from '../copy/resolve-console-error';
import { CatalogueStore, PermissionGroup } from '../data/catalogue.store';
import { ConsoleErrorPanel } from '../ui/console-error-panel';
import { PermissionMatrix } from '../ui/permission-matrix';
import { RoleDetailStore } from './role-detail.store';

const OTHER = 'other';

/**
 * The catalogue groups, plus any granted permission the catalogue does not hold (a permission
 * added after this console session read the catalogue). It goes into the `other` group, so a
 * granted permission is never hidden from the read view.
 */
function withGrantedExtras(
  groups: readonly PermissionGroup[],
  known: ReadonlyMap<string, PermissionResponse>,
  granted: readonly PermissionResponse[],
): readonly PermissionGroup[] {
  const extras = granted.filter((entry) => !known.has(entry.id));
  if (extras.length === 0) return groups;
  const other = groups.find((group) => group.resource === OTHER);
  const merged: PermissionGroup = {
    resource: OTHER,
    label: other?.label ?? CONSOLE_COPY.catalogue.otherGroup,
    permissions: [...(other?.permissions ?? []), ...extras],
  };
  return [...groups.filter((group) => group !== other), merged];
}

/**
 * The Permissions tab of a role (US-020 design §6.1, §12.3): the read-only matrix of the role
 * the page has loaded. Smart but thin: the {@link RoleDetailPage} owns the loads (the role, its
 * set and the catalogue); this tab only reads them. It renders nothing until the role is ready,
 * because the page shows those states.
 *
 * - Zero granted permissions: "This role grants no access yet" instead of the matrix (FR-A5).
 * - The catalogue still loading, or failed: a loading state, or the error panel whose Retry
 *   reads the catalogue only.
 */
@Component({
  selector: 'app-role-permissions-tab',
  imports: [NxEmptyState, NxSkeleton, ConsoleErrorPanel, PermissionMatrix],
  template: `
    @if (data(); as detail) {
      @if (detail.permissions.length === 0) {
        <nx-empty-state
          icon="key_off"
          [title]="copy.roleDetail.emptyPermissions"
          data-testid="role-permissions-empty"
        />
      } @else {
        @switch (catalogueStatus()) {
          @case ('ready') {
            <app-permission-matrix
              [groups]="groups()"
              [granted]="granted()"
              [roleName]="detail.role.name"
            />
          }
          @case ('error') {
            @if (catalogueError(); as view) {
              <app-console-error-panel
                [view]="view"
                [recordedAt]="catalogueFailedAt()"
                (retry)="retryCatalogue()"
                data-testid="role-permissions-error"
              />
            }
          }
          @default {
            <div
              class="role-permissions__loading"
              aria-busy="true"
              data-testid="role-permissions-loading"
            >
              <p class="role-permissions__loading-text" role="status">
                {{ copy.roleDetail.loadingPermissions }}
              </p>
              @for (row of skeletonRows; track row) {
                <nx-skeleton class="role-permissions__skeleton" variant="rect" />
              }
            </div>
          }
        }
      }
    }
  `,
  styles: `
    :host {
      display: block;
      min-width: 0;
      padding-block-start: var(--nx-space-4);
    }

    .role-permissions__loading {
      display: grid;
      gap: var(--nx-space-3);
    }

    .role-permissions__loading-text {
      margin: 0;
      color: var(--nx-color-on-surface-muted);
    }

    .role-permissions__skeleton {
      display: block;
      height: var(--nx-space-10);
    }
  `,
})
export class RolePermissionsTab {
  private readonly detail = inject(RoleDetailStore);
  private readonly catalogue = inject(CatalogueStore);

  protected readonly copy = CONSOLE_COPY;
  protected readonly skeletonRows = [0, 1, 2, 3];

  protected readonly data = computed(() => {
    const state = this.detail.state();
    return state.status === 'ready' ? state.data : null;
  });

  protected readonly granted = computed<ReadonlySet<string>>(
    () => new Set((this.data()?.permissions ?? []).map((entry) => entry.id)),
  );

  protected readonly catalogueStatus = computed(() => this.catalogue.state().status);

  protected readonly groups = computed<readonly PermissionGroup[]>(() => {
    const state = this.catalogue.state();
    if (state.status !== 'ready') return [];
    return withGrantedExtras(state.data.groups, state.data.byId, this.data()?.permissions ?? []);
  });

  private readonly catalogueFailure = computed(() => {
    const state = this.catalogue.state();
    return state.status === 'error' ? state : null;
  });

  protected readonly catalogueError = computed(() => {
    const failure = this.catalogueFailure();
    return failure === null
      ? null
      : resolveConsoleError(failure.error, { area: 'permissions', action: 'load' });
  });

  protected readonly catalogueFailedAt = computed(() => this.catalogueFailure()?.failedAt);

  protected retryCatalogue(): void {
    this.catalogue.load();
  }
}
