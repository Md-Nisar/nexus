import { Component, computed, input } from '@angular/core';
import { NxBadge, NxIcon } from '../../../shared/ui';
import { CONSOLE_COPY, format } from '../copy/console-copy';
import { hasHiddenCharacters, splitHiddenCharacters } from '../util/hidden-characters';

/** `text` for role names and descriptions; `email` for addresses (RC-68). */
export type UserTextMode = 'text' | 'email';

/** One rendered piece of an address in `email` mode: visible text, or a hidden-character token. */
type EmailPart =
  | { readonly kind: 'text'; readonly text: string }
  | { readonly kind: 'hidden'; readonly token: string; readonly name: string };

let nextId = 0;

/**
 * Renders one piece of user-authored text: a role name, a description or an email address
 * (US-020 design §6.1, §15.3; threat model SD-6, SD-7, T-S15, RC-68 with D-1).
 *
 * - **Text, never markup.** The value is bound by interpolation inside `<bdi>`. There is no
 *   `innerHTML`, no sanitiser bypass and no pipe that interprets it, so markup in a role name is
 *   shown as the characters it is made of. `<bdi>` also isolates the string's direction from its
 *   neighbours.
 * - **`email` mode** (RC-68): `<bdi>` does not neutralise an override or a zero-width character
 *   *inside* the address, so every hidden code point ({@link splitHiddenCharacters}, the D-1 set)
 *   is replaced by its own `<span>` holding the visible token `⟨U+XXXX⟩`, named "hidden character
 *   U+XXXX" for assistive technology. The hidden code point itself never reaches the DOM, so it
 *   cannot reorder or hide anything; two addresses that differ only by one never render the same.
 *   Each segment is a text-only `<span>` built in an `@for`, never HTML.
 * - **`text` mode:** the value as written; hidden characters add the badge only.
 * - **Truncation** (`maxLines`) is CSS only: the full text stays in the DOM, so the accessible
 *   name is the full text, and it is also the `title` (in `email` mode, the tokenised text). Nothing
 *   is sliced in code, which could cut a surrogate pair or a bidi sequence in half.
 * - **Hidden characters** (RC-68, D-1): in both modes a "Contains hidden characters" badge shows
 *   next to the value, outside the truncated span so it is never cut off, described by the
 *   explanation (the address wording in `email` mode).
 *
 * Never put the value in `document.title`, a toast or a log context (design §15.3).
 */
@Component({
  selector: 'app-user-text',
  imports: [NxBadge, NxIcon],
  template: `
    @if (emailParts(); as parts) {
      <bdi
        class="user-text"
        [class.user-text--clamped]="maxLines() !== null"
        [style.--user-text-lines]="maxLines()"
        [attr.title]="maxLines() !== null ? shownText() : null"
        data-testid="user-text"
      >
        @for (part of parts; track $index) {
          @if (part.kind === 'hidden') {
            <span
              class="user-text__token"
              role="img"
              [attr.aria-label]="part.name"
              data-testid="user-text-hidden-token"
              >{{ part.token }}</span
            >
          } @else {
            <span>{{ part.text }}</span>
          }
        }
      </bdi>
    } @else {
      <bdi
        class="user-text"
        [class.user-text--clamped]="maxLines() !== null"
        [style.--user-text-lines]="maxLines()"
        [attr.title]="maxLines() !== null ? text() : null"
        data-testid="user-text"
        >{{ text() }}</bdi
      >
    }
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
        {{ explanation() }}
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
  /** `email` shows hidden characters as tokens; `text` only adds the badge. */
  readonly mode = input<UserTextMode>('text');

  protected readonly copy = CONSOLE_COPY;
  protected readonly explanationId = `app-user-text-explanation-${nextId++}`;
  protected readonly hidden = computed(() => hasHiddenCharacters(this.text()));

  /** The segments of an address in `email` mode; `null` in `text` mode. */
  protected readonly emailParts = computed<readonly EmailPart[] | null>(() => {
    if (this.mode() !== 'email') return null;
    return splitHiddenCharacters(this.text()).map((segment) =>
      segment.kind === 'text'
        ? { kind: 'text', text: segment.text }
        : {
            kind: 'hidden',
            token: format(CONSOLE_COPY.badges.hiddenCharacterToken, { hex: segment.codePoint }),
            name: format(CONSOLE_COPY.badges.hiddenCharacterName, { hex: segment.codePoint }),
          },
    );
  });

  /** The address as shown in `email` mode, tokens in place of hidden characters (the `title`). */
  protected readonly shownText = computed(() =>
    (this.emailParts() ?? [])
      .map((part) => (part.kind === 'text' ? part.text : part.token))
      .join(''),
  );

  protected readonly explanation = computed(() =>
    this.mode() === 'email'
      ? CONSOLE_COPY.badges.hiddenCharactersEmailExplanation
      : CONSOLE_COPY.badges.hiddenCharactersExplanation,
  );
}
