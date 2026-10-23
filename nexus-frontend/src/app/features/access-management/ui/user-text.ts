import { Component, computed, input } from '@angular/core';
import { NxBadge, NxIcon } from '../../../shared/ui';
import { CONSOLE_COPY } from '../copy/console-copy';
import { hasHiddenCharacters } from '../util/hidden-characters';

let nextId = 0;

/**
 * Renders one piece of user-authored text: a role name or a description (US-020 design §6.1,
 * §15.3; threat model SD-6, SD-7, T-S15). `text` mode only; `email` mode lands with the users
 * pages (T-015).
 *
 * - **Text, never markup.** The value is bound by interpolation inside `<bdi>`. There is no
 *   `innerHTML`, no sanitiser bypass and no pipe that interprets it, so markup in a role name is
 *   shown as the characters it is made of. `<bdi>` also isolates the string's direction from its
 *   neighbours.
 * - **Truncation** (`maxLines`) is CSS only: the full text stays in the DOM, so the accessible
 *   name is the full text, and it is also the `title`. Nothing is sliced in code, which could cut
 *   a surrogate pair or a bidi sequence in half.
 * - **Hidden characters** (RC-68, D-1): when the text holds invisible or direction-changing
 *   characters a "Contains hidden characters" badge shows next to it, outside the truncated span
 *   so it is never cut off. The text itself is unchanged.
 *
 * Never put the value in `document.title`, a toast or a log context (design §15.3).
 */
@Component({
  selector: 'app-user-text',
  imports: [NxBadge, NxIcon],
  template: `
    <bdi
      class="user-text"
      [class.user-text--clamped]="maxLines() !== null"
      [style.--user-text-lines]="maxLines()"
      [attr.title]="maxLines() !== null ? text() : null"
      data-testid="user-text"
      >{{ text() }}</bdi
    >
    @if (hidden()) {
      <nx-badge
        class="user-text__badge"
        variant="warning"
        [attr.aria-describedby]="explanationId"
        data-testid="user-text-hidden-badge"
      >
        <nx-icon name="visibility_off" />
        {{ copy.badges.hiddenCharacters }}
      </nx-badge>
      <span [id]="explanationId" class="user-text__explanation">
        {{ copy.badges.hiddenCharactersExplanation }}
      </span>
    }
  `,
  styleUrl: './user-text.scss',
})
export class UserText {
  /** The user-authored value. */
  readonly text = input.required<string>();
  /** Clamp to this many lines with an ellipsis; `null` shows all of it. */
  readonly maxLines = input<number | null>(null);

  protected readonly copy = CONSOLE_COPY;
  protected readonly explanationId = `app-user-text-explanation-${nextId++}`;
  protected readonly hidden = computed(() => hasHiddenCharacters(this.text()));
}
