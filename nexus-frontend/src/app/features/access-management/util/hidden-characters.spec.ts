import { describe, expect, it } from 'vitest';
import { hasHiddenCharacters, splitHiddenCharacters } from './hidden-characters';

describe('hasHiddenCharacters (threat model D-1, RC-68)', () => {
  it.each([
    ['plain ASCII', 'Support Agent'],
    ['empty', ''],
    ['ASCII spaces, hyphens, dots', 'a b-c.d_e'],
    ['accented letters', 'Équipe'],
    ['CJK text', '管理者'],
  ])('is false for %s', (_name, text) => {
    expect(hasHiddenCharacters(text)).toBe(false);
  });

  it.each([
    ['right-to-left override U+202E', 'abc‮def'],
    ['left-to-right override U+202D', '‭abc'],
    ['isolate U+2066', 'a⁦b'],
    ['zero-width space U+200B', 'a​b'],
    ['zero-width joiner U+200D', 'a‍b'],
    ['byte-order mark U+FEFF', '﻿abc'],
    ['word joiner U+2060', 'a⁠b'],
    ['Hangul filler U+3164', 'aㅤb'],
    ['Hangul choseong filler U+115F', 'aᅟb'],
    ['Hangul jungseong filler U+1160', 'aᅠb'],
    ['halfwidth Hangul filler U+FFA0', 'aﾠb'],
    ['combining grapheme joiner U+034F', 'a͏b'],
    ['variation selector U+FE0F', 'a️b'],
    ['supplementary variation selector U+E0100', 'a\u{E0100}b'],
    ['no-break space U+00A0', 'a b'],
    ['en quad U+2000', 'a b'],
    ['ideographic space U+3000', 'a　b'],
    ['line separator U+2028', 'a b'],
    ['paragraph separator U+2029', 'a b'],
  ])('is true for %s', (_name, text) => {
    expect(hasHiddenCharacters(text)).toBe(true);
  });
});

describe('splitHiddenCharacters (threat model D-1, RC-68)', () => {
  /** Joins the segments by their raw text: the split loses nothing. */
  function rejoin(segments: ReturnType<typeof splitHiddenCharacters>): string {
    return segments.map((segment) => segment.text).join('');
  }

  it.each([
    ['right-to-left override', 'ab\u202Ecd', '202E'],
    ['zero-width joiner', 'ab\u200Dcd', '200D'],
    ['byte-order mark', 'ab\uFEFFcd', 'FEFF'],
    ['Hangul filler', 'ab\u3164cd', '3164'],
    ['no-break space', 'ab\u00A0cd', '00A0'],
    ['variation selector-16', 'ab\uFE0Fcd', 'FE0F'],
    ['line separator', 'ab\u2028cd', '2028'],
  ])('splits out a %s as one hidden segment', (_name, text, hex) => {
    const segments = splitHiddenCharacters(text);

    expect(segments).toEqual([
      { kind: 'text', text: 'ab' },
      { kind: 'hidden', text: String.fromCodePoint(Number.parseInt(hex, 16)), codePoint: hex },
      { kind: 'text', text: 'cd' },
    ]);
    expect(rejoin(segments)).toBe(text);
  });

  it('keeps a supplementary code point whole (U+E0100), never two surrogate halves', () => {
    const text = 'a\u{E0100}b';
    const segments = splitHiddenCharacters(text);

    expect(segments).toEqual([
      { kind: 'text', text: 'a' },
      { kind: 'hidden', text: '\u{E0100}', codePoint: 'E0100' },
      { kind: 'text', text: 'b' },
    ]);
    expect(rejoin(segments)).toBe(text);
  });

  it('returns a clean address as one text segment', () => {
    const text = 'clean.address+tag@directory.invalid';
    expect(splitHiddenCharacters(text)).toEqual([{ kind: 'text', text }]);
  });

  it('does not flag a plain space', () => {
    expect(splitHiddenCharacters('a b')).toEqual([{ kind: 'text', text: 'a b' }]);
  });

  it('gives one segment per hidden code point, adjacent ones included, at either end', () => {
    const text = '\u202Ea\u200B\u200Cb\u2066';
    const segments = splitHiddenCharacters(text);

    expect(
      segments.map((segment) => (segment.kind === 'hidden' ? segment.codePoint : 'text')),
    ).toEqual(['202E', 'text', '200B', '200C', 'text', '2066']);
    expect(rejoin(segments)).toBe(text);
  });

  it('returns no segment for the empty string', () => {
    expect(splitHiddenCharacters('')).toEqual([]);
  });

  it('agrees with hasHiddenCharacters', () => {
    for (const text of ['abc', 'a\u202Eb', 'a\u00A0b', 'a b', '\u3164']) {
      const flagged = splitHiddenCharacters(text).some((segment) => segment.kind === 'hidden');
      expect(flagged).toBe(hasHiddenCharacters(text));
    }
  });
});
