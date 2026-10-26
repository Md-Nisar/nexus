import { Component } from '@angular/core';
import { NxBadge, NxIcon } from '../../../shared/ui';
import { CONSOLE_COPY } from '../copy/console-copy';

/**
 * "Sensitive" with a warning icon, shown beside a permission whose grant needs care (US-020
 * design §6.1, §12.6). Icon plus text, never colour alone. The definition is shown as visible text
 * by the page that uses it, not here.
 */
@Component({
  selector: 'app-sensitive-badge',
  imports: [NxBadge, NxIcon],
  template: `
    <nx-badge variant="warning" data-testid="sensitive-badge">
      <nx-icon name="warning" />
      {{ copy.badges.sensitive }}
    </nx-badge>
  `,
})
export class SensitiveBadge {
  protected readonly copy = CONSOLE_COPY;
}
