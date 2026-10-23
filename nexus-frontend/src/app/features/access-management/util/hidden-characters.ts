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
