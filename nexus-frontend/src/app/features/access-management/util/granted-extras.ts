import type { PermissionResponse } from '../../../shared/types/api/rbac';
import { CONSOLE_COPY } from '../copy/console-copy';
import type { PermissionGroup } from '../data/catalogue.store';

const OTHER = 'other';

/**
 * The catalogue groups, plus any granted permission the catalogue does not hold (a permission
 * added after this console session read the catalogue). It goes into the `other` group, so a
 * granted permission is never hidden from the matrix, in read or edit mode.
 */
export function withGrantedExtras(
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
