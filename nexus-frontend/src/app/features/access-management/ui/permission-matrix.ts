import { NgTemplateOutlet } from '@angular/common';
import { Component, computed, input } from '@angular/core';
import { NxBadge, NxIcon } from '../../../shared/ui';
import { CONSOLE_COPY } from '../copy/console-copy';
import { permissionLabel } from '../copy/permission-labels';
import type { PermissionGroup } from '../data/catalogue.store';
import { SensitiveBadge } from './sensitive-badge';
import { UserText } from './user-text';

/** One permission as the matrix shows it; `label` is `null` for a code without a label. */
interface MatrixRow {
  readonly id: string;
  readonly code: string;
  readonly label: string | null;
  readonly description: string;
  readonly isSensitive: boolean;
  readonly granted: boolean;
}

interface MatrixGroup {
  readonly resource: string;
  readonly label: string;
  readonly headingId: string;
  readonly rows: readonly MatrixRow[];
}

const ROLE_PLACEHOLDER = '{role}';
const [CAPTION_BEFORE, CAPTION_AFTER = ''] = CONSOLE_COPY.matrix.caption.split(ROLE_PLACEHOLDER);

let nextId = 0;

/**
 * The permission matrix in **read mode** (US-020 design §6.1, §12.3, §13; FR-A6). Dumb: it shows
 * the groups it is given and marks each permission whose id is in `granted`. Edit mode (checkboxes,
 * affordances, toggle outputs) arrives with the editor in T-010.
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
  imports: [NgTemplateOutlet, NxBadge, NxIcon, SensitiveBadge, UserText],
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

  protected readonly copy = CONSOLE_COPY;
  protected readonly captionBefore = CAPTION_BEFORE;
  protected readonly captionAfter = CAPTION_AFTER;
  protected readonly columnCount = 4;
  private readonly idPrefix = `app-permission-matrix-${nextId++}`;

  protected readonly view = computed<readonly MatrixGroup[]>(() => {
    const granted = this.granted();
    return this.groups().map((group) => ({
      resource: group.resource,
      label: group.label,
      headingId: `${this.idPrefix}-${group.resource}`,
      rows: group.permissions.map((entry) => ({
        id: entry.id,
        code: entry.name,
        label: permissionLabel(entry.name) ?? null,
        description: entry.description,
        isSensitive: entry.isSensitive,
        granted: granted.has(entry.id),
      })),
    }));
  });
}
