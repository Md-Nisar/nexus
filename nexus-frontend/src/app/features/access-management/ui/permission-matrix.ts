import { NgTemplateOutlet } from '@angular/common';
import { Component, computed, input, output } from '@angular/core';
import { NxBadge, NxCheckbox, NxIcon } from '../../../shared/ui';
import { CONSOLE_COPY, format } from '../copy/console-copy';
import { permissionLabel } from '../copy/permission-labels';
import type { PermissionGroup } from '../data/catalogue.store';
import type { Affordance, AffordanceReason } from '../util/affordances';
import { EMPTY_INTENT, StagedIntent } from '../util/diff-permissions';
import { SensitiveBadge } from './sensitive-badge';
import { UserText } from './user-text';

/** Read mode shows the granted set; edit mode adds a checkbox per permission and per group. */
export type MatrixMode = 'read' | 'edit';

/** A row checkbox was toggled: set `permissionId` to `next` in the staged result. */
export interface MatrixToggle {
  readonly permissionId: string;
  readonly next: boolean;
}

/** A group checkbox was toggled: set every **enabled** member of `resource` to `next`. */
export interface MatrixGroupToggle {
  readonly resource: string;
  readonly next: boolean;
}

/** One permission as the matrix shows it; `label` is `null` for a code without a label. */
interface MatrixRow {
  readonly id: string;
  readonly code: string;
  readonly label: string | null;
  readonly description: string;
  readonly isSensitive: boolean;
  /** Read mode: in the base set. Edit mode: in the staged result. */
  readonly granted: boolean;
  /** Edit mode: "{label} ({code})", unique per permission. */
  readonly checkboxLabel: string;
  readonly enabled: boolean;
  /** Visible reason of a disabled row; empty when enabled. */
  readonly reason: string;
}

interface MatrixGroup {
  readonly resource: string;
  readonly label: string;
  readonly headingId: string;
  readonly rows: readonly MatrixRow[];
  /** Edit mode: "All {group} permissions". */
  readonly checkboxLabel: string;
  /** At least one member can be changed; otherwise no group checkbox is rendered. */
  readonly hasEnabled: boolean;
  /** Every member is in the result. */
  readonly checked: boolean;
  /** Some, not all, members are in the result (`aria-checked="mixed"`). */
  readonly mixed: boolean;
  /** What a click on the group checkbox asks for. */
  readonly next: boolean;
}

/** Visible text of each disabled reason (design §14.2). */
export const AFFORDANCE_REASON_TEXT: Readonly<Record<AffordanceReason, string>> = {
  'profile-unavailable': CONSOLE_COPY.disabledReason.profileUnavailable,
  'not-held': CONSOLE_COPY.disabledReason.notHeld,
  'admin-only-directory': CONSOLE_COPY.disabledReason.adminOnlyDirectory,
  'role-exceeds-caller': CONSOLE_COPY.disabledReason.roleExceedsCaller,
};

function reasonOf(affordance: Affordance | undefined): string {
  return affordance?.kind === 'disabled' ? AFFORDANCE_REASON_TEXT[affordance.reason] : '';
}

const ROLE_PLACEHOLDER = '{role}';
const [CAPTION_BEFORE, CAPTION_AFTER = ''] = CONSOLE_COPY.matrix.caption.split(ROLE_PLACEHOLDER);

let nextId = 0;

/**
 * The permission matrix (US-020 design §6.1, §12.3, §12.4, §13; FR-A6). Dumb: it shows the groups
 * it is given and marks each permission whose id is in `granted`.
 *
 * **Edit mode** (`mode="edit"`): the state shown is `granted` with `staged` applied. Each
 * permission gets an `nx-checkbox` named "{label} ({code})"; a row whose affordance is disabled
 * stays focusable, `aria-disabled`, with its reason as visible text linked by `aria-describedby`.
 * Each group with at least one enabled member gets "All {group} permissions": checked when every
 * member is in the result, mixed when some are, and a click asks to set every enabled member to
 * the opposite of "all enabled members are in". The checkboxes are controlled: the host owns the
 * state, through the `permissionToggle` and `groupToggle` outputs. The Status column is dropped.
 *
 * - **Native table:** `<caption>` naming the role, `<th scope="col">` column headers, one group row
 *   per resource (`<th scope="row" colspan>`), and a row header per permission (its label), so
 *   each status cell is announced with its permission.
 * - **Status as text:** "Granted" or "Not granted", with an icon hidden from assistive technology;
 *   never colour or an icon alone (WCAG 1.4.1). There is no checkbox in read mode.
 * - **Narrow (below 600 px):** the table is replaced, in CSS only, by one section per resource (an
 *   `h3` per group under an `h2` standing in for the caption), so nothing scrolls sideways
 *   (WCAG 1.4.10). Both renderings are in the DOM; the hidden one is `display: none`, so assistive
 *   technology meets exactly one.
 * - **Text:** the role name is user-authored and renders through {@link UserText} inside the
 *   caption, by interpolation only. Labels, codes and descriptions are catalogue text.
 */
@Component({
  selector: 'app-permission-matrix',
  imports: [NgTemplateOutlet, NxBadge, NxCheckbox, NxIcon, SensitiveBadge, UserText],
  templateUrl: './permission-matrix.html',
  styleUrl: './permission-matrix.scss',
})
export class PermissionMatrix {
  /** The catalogue groups, in display order. */
  readonly groups = input.required<readonly PermissionGroup[]>();
  /** Ids of the permissions the role grants. */
  readonly granted = input.required<ReadonlySet<string>>();
  /** The role's name, for the caption. User-authored. */
  readonly roleName = input.required<string>();
  readonly mode = input<MatrixMode>('read');
  /** Edit mode: the staged intent relative to `granted`. */
  readonly staged = input<StagedIntent>(EMPTY_INTENT);
  /** Edit mode: the affordance of each permission id. A missing id is not changeable. */
  readonly affordances = input<ReadonlyMap<string, Affordance>>(new Map());

  /** Edit mode: a row checkbox was toggled. */
  readonly permissionToggle = output<MatrixToggle>();
  /** Edit mode: a group checkbox was toggled. */
  readonly groupToggle = output<MatrixGroupToggle>();

  protected readonly copy = CONSOLE_COPY;
  protected readonly captionBefore = CAPTION_BEFORE;
  protected readonly captionAfter = CAPTION_AFTER;
  protected readonly editing = computed(() => this.mode() === 'edit');
  protected readonly columnCount = computed(() => (this.editing() ? 3 : 4));
  private readonly idPrefix = `app-permission-matrix-${nextId++}`;

  protected readonly view = computed<readonly MatrixGroup[]>(() => {
    const granted = this.granted();
    const editing = this.editing();
    const staged = this.staged();
    const affordances = this.affordances();
    const isIn = (id: string): boolean =>
      editing ? staged.add.has(id) || (granted.has(id) && !staged.remove.has(id)) : granted.has(id);
    return this.groups().map((group) => {
      const rows = group.permissions.map((entry): MatrixRow => {
        const label = permissionLabel(entry.name) ?? null;
        const affordance = affordances.get(entry.id);
        return {
          id: entry.id,
          code: entry.name,
          label,
          description: entry.description,
          isSensitive: entry.isSensitive,
          granted: isIn(entry.id),
          checkboxLabel: format(CONSOLE_COPY.editor.rowLabel, {
            label: label ?? entry.name,
            code: entry.name,
          }),
          enabled: affordance?.kind === 'enabled',
          reason: reasonOf(affordance),
        };
      });
      const inCount = rows.filter((row) => row.granted).length;
      const enabled = rows.filter((row) => row.enabled);
      return {
        resource: group.resource,
        label: group.label,
        headingId: `${this.idPrefix}-${group.resource}`,
        rows,
        checkboxLabel: format(CONSOLE_COPY.editor.groupLabel, { group: group.label }),
        hasEnabled: enabled.length > 0,
        checked: rows.length > 0 && inCount === rows.length,
        mixed: inCount > 0 && inCount < rows.length,
        next: !enabled.every((row) => row.granted),
      };
    });
  });

  protected onToggle(row: MatrixRow, next: boolean): void {
    if (row.enabled) this.permissionToggle.emit({ permissionId: row.id, next });
  }

  protected onToggleGroup(group: MatrixGroup): void {
    if (group.hasEnabled) this.groupToggle.emit({ resource: group.resource, next: group.next });
  }
}
