/**
 * Invisible or direction-changing code points (US-020 threat model T-S15, RC-68, delta D-1):
 * format characters (`Cf`: bidi overrides and isolates, zero-width characters, the byte-order
 * mark), default-ignorable code points (Hangul fillers, variation selectors, the combining
 * grapheme joiner) and every space or line/paragraph separator except U+0020.
 *
 * The ASCII space is excluded because role names and descriptions legitimately contain it.
 */
const HIDDEN = /(?! )[\p{Cf}\p{Default_Ignorable_Code_Point}\p{Zs}\p{Zl}\p{Zp}]/u;

/**
 * Whether `text` contains a character that renders as nothing, as a space, or that changes the
 * direction of the text around it. `<bdi>` isolates a string from its neighbours but does not
 * neutralise any of these inside it, so the console flags them next to the value.
 */
export function hasHiddenCharacters(text: string): boolean {
  return HIDDEN.test(text);
}

/**
 * One piece of a string split at its hidden characters: visible text, or exactly one hidden code
 * point with its hex code (upper case, at least four digits, as in "U+202E").
 */
export type HiddenCharacterSegment =
  | { readonly kind: 'text'; readonly text: string }
  | { readonly kind: 'hidden'; readonly text: string; readonly codePoint: string };

/** One code point of the D-1 set; `HIDDEN` is not global, so `test` keeps no state. */
const HIDDEN_CODE_POINT = new RegExp(`^${HIDDEN.source}$`, HIDDEN.flags);

/**
 * Splits `text` into visible runs and single hidden code points (design §15.3 with D-1), so that
 * `UserText` can render each hidden one as a visible token without ever parsing HTML.
 *
 * Iterates by code point, so a supplementary character (for example U+E0100) is one segment and is
 * never cut into surrogate halves. Joining every segment's `text` gives `text` back unchanged.
 */
export function splitHiddenCharacters(text: string): readonly HiddenCharacterSegment[] {
  const segments: HiddenCharacterSegment[] = [];
  let run = '';
  for (const char of text) {
    if (!HIDDEN_CODE_POINT.test(char)) {
      run += char;
      continue;
    }
    if (run !== '') segments.push({ kind: 'text', text: run });
    run = '';
    const codePoint = (char.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, '0');
    segments.push({ kind: 'hidden', text: char, codePoint });
  }
  if (run !== '') segments.push({ kind: 'text', text: run });
  return segments;
}
