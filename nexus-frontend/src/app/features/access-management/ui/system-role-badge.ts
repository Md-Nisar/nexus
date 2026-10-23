import { Component, input } from '@angular/core';
import { NxBadge, NxIcon } from '../../../shared/ui';
import { CONSOLE_COPY } from '../copy/console-copy';

/**
 * "System" (with a lock icon) or "Custom" for a role (US-020 design §6.1, §12.2). Icon plus text,
 * never colour alone. `data-kind` is the stable hook for tests.
 */
@Component({
  selector: 'app-system-role-badge',
  imports: [NxBadge, NxIcon],
  template: `
    <nx-badge
      [variant]="isSystemRole() ? 'primary' : 'neutral'"
      [attr.data-kind]="isSystemRole() ? 'system' : 'custom'"
      data-testid="system-role-badge"
    >
      @if (isSystemRole()) {
        <nx-icon name="lock" />
        {{ copy.badges.system }}
      } @else {
        {{ copy.badges.custom }}
      }
    </nx-badge>
  `,
})
export class SystemRoleBadge {
  readonly isSystemRole = input.required<boolean>();

  protected readonly copy = CONSOLE_COPY;
}
