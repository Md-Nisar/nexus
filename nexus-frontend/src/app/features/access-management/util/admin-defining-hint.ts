import type { RoleResponse } from '../../../shared/types/api/rbac';

/**
 * Whether a role **looks** administrator-defining: it carries as many permissions as the
 * catalogue holds (US-020 design §8.3, Gate 1 Q17). ADR-0021 D3 defines an administrator as
 * someone holding one role that grants the whole catalogue; the server decides that from the
 * actual sets under its locks. This is a hint for copy only and never blocks anything.
 *
 * It reads `permissionCount` only and **never `memberCount`** (Gate 1 Q16): how many people hold
 * a role says nothing about whether it defines an administrator. A spec pins this.
 *
 * An unknown catalogue total (0) gives `false`.
 */
export function isAdminDefiningHint(role: RoleResponse, catalogueTotal: number): boolean {
  return catalogueTotal > 0 && role.permissionCount === catalogueTotal;
}
