import { describe, expect, it } from 'vitest';
import { hasHiddenCharacters } from './hidden-characters';

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
