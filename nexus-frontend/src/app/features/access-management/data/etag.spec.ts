import { describe, expect, it } from 'vitest';
import { classifyEtag } from './etag';

describe('classifyEtag (US-020 design §7.2, SD-8)', () => {
  it('classifies one quoted opaque tag as strong and keeps it verbatim, quotes included', () => {
    expect(classifyEtag('"3f2a9c"')).toEqual({ kind: 'strong', value: '"3f2a9c"' });
  });

  it('keeps every visible ASCII character the server accepts inside the quotes', () => {
    const raw = '"!#$%&\'()*+,-./09:;<=>?@AZ[\\]^_`az{|}~"';
    expect(classifyEtag(raw)).toEqual({ kind: 'strong', value: raw });
  });

  it.each([['W/"3f2a9c"'], ['W/""'], ['W/3f2a9c']])(
    'classifies %s as weak, never stripping the W/ prefix',
    (raw) => {
      const state = classifyEtag(raw);
      expect(state).toEqual({ kind: 'weak' });
      expect('value' in state).toBe(false);
    },
  );

  it.each([
    ['null (no header)', null],
    ['the empty string', ''],
    ['an empty quoted tag', '""'],
    ['an unquoted value', '3f2a9c'],
    ['a value quoted on one side only', '"3f2a9c'],
    ['a list of two tags', '"a", "b"'],
    ['a list without a space', '"a","b"'],
    ['a strong and a weak tag', '"a", W/"b"'],
    ['the wildcard', '*'],
    ['a double quote inside the tag', '"a"b"'],
    ['a space inside the tag', '"a b"'],
    ['a non-ASCII character inside the tag', '"café"'],
    ['a control character inside the tag', '"a\u0001"'],
    ['leading whitespace', ' "a"'],
    ['trailing whitespace', '"a" '],
    ['a lowercase weak prefix', 'w/"a"'],
  ])('classifies %s as missing', (_name, raw) => {
    expect(classifyEtag(raw)).toEqual({ kind: 'missing' });
  });
});
