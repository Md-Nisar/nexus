import { describe, expect, it } from 'vitest';
import {
  CatalogueIndex,
  EMPTY_INTENT,
  StagedIntent,
  diffPermissions,
  normaliseIntent,
  rebase,
  toggle,
  toggleGroup,
} from './diff-permissions';

const CATALOGUE: CatalogueIndex = {
  order: ['p-a', 'p-b', 'p-c', 'p-d'],
  sensitive: new Set(['p-c']),
};

function set(...ids: string[]): ReadonlySet<string> {
  return new Set(ids);
}

function intent(add: string[] = [], remove: string[] = []): StagedIntent {
  return { add: new Set(add), remove: new Set(remove) };
}

function expectInvariants(base: ReadonlySet<string>, staged: StagedIntent): void {
  for (const id of staged.add) {
    expect(base.has(id)).toBe(false);
    expect(staged.remove.has(id)).toBe(false);
  }
  for (const id of staged.remove) expect(base.has(id)).toBe(true);
}

describe('toggle (design §8.1)', () => {
  const base = set('p-a', 'p-b');

  it('stages an add for an id outside the base and a remove for an id in it', () => {
    const added = toggle(base, EMPTY_INTENT, 'p-c', true);
    expect([...added.add]).toEqual(['p-c']);
    expect(added.remove.size).toBe(0);
    const removed = toggle(base, EMPTY_INTENT, 'p-a', false);
    expect([...removed.remove]).toEqual(['p-a']);
    expect(removed.add.size).toBe(0);
  });

  it('clears the entry when toggled back to the base state', () => {
    const there = toggle(base, EMPTY_INTENT, 'p-c', true);
    expect(toggle(base, there, 'p-c', false)).toEqual(EMPTY_INTENT);
    const gone = toggle(base, EMPTY_INTENT, 'p-a', false);
    expect(toggle(base, gone, 'p-a', true)).toEqual(EMPTY_INTENT);
  });

  it('is a no-op when the id already has the requested state', () => {
    expect(toggle(base, EMPTY_INTENT, 'p-a', true)).toEqual(EMPTY_INTENT);
    expect(toggle(base, EMPTY_INTENT, 'p-c', false)).toEqual(EMPTY_INTENT);
  });

  it('keeps add ∩ base = ∅, remove ⊆ base and add ∩ remove = ∅ over any sequence', () => {
    const steps: readonly [string, boolean][] = [
      ['p-c', true],
      ['p-a', false],
      ['p-a', true],
      ['p-d', true],
      ['p-b', false],
      ['p-c', false],
      ['p-c', true],
      ['p-a', false],
      ['p-b', true],
    ];
    let staged = EMPTY_INTENT;
    for (const [id, next] of steps) {
      staged = toggle(base, staged, id, next);
      expectInvariants(base, staged);
    }
    expect([...staged.add].sort()).toEqual(['p-c', 'p-d']);
    expect([...staged.remove]).toEqual(['p-a']);
  });

  it('never mutates the intent it was given', () => {
    const before = intent(['p-c']);
    toggle(base, before, 'p-d', true);
    expect([...before.add]).toEqual(['p-c']);
  });
});

describe('toggleGroup (design §8.1)', () => {
  const base = set('p-a');
  const enabled = (id: string): boolean => id !== 'p-b';

  it('applies the state to every enabled member only', () => {
    const on = toggleGroup(base, EMPTY_INTENT, ['p-a', 'p-b', 'p-c'], true, enabled);
    expect([...on.add]).toEqual(['p-c']);
    expect(on.remove.size).toBe(0);
    const off = toggleGroup(base, EMPTY_INTENT, ['p-a', 'p-b', 'p-c'], false, enabled);
    expect([...off.remove]).toEqual(['p-a']);
    expect(off.add.size).toBe(0);
  });

  it('leaves a staged entry of a disabled member untouched', () => {
    const staged = intent(['p-b']);
    const off = toggleGroup(base, staged, ['p-a', 'p-b'], false, enabled);
    expect([...off.add]).toEqual(['p-b']);
    expect([...off.remove]).toEqual(['p-a']);
  });
});

describe('diffPermissions (design §8.1)', () => {
  it('lists adds, removes and the result in catalogue order, unknown ids last', () => {
    const diff = diffPermissions(
      set('p-d', 'x-extra', 'p-b'),
      intent(['p-c', 'p-a'], ['p-d']),
      CATALOGUE,
    );
    expect(diff.added).toEqual(['p-a', 'p-c']);
    expect(diff.removed).toEqual(['p-d']);
    expect(diff.resulting).toEqual(['p-a', 'p-b', 'p-c', 'x-extra']);
    expect(diff.isEmpty).toBe(false);
  });

  it('is empty with no intent', () => {
    const diff = diffPermissions(set('p-a'), EMPTY_INTENT, CATALOGUE);
    expect(diff).toEqual({
      added: [],
      removed: [],
      resulting: ['p-a'],
      isEmpty: true,
      addsSensitive: false,
      resultIsEmpty: false,
      resultIsWholeCatalogue: false,
    });
  });

  it('flags a sensitive add, and not a sensitive remove', () => {
    expect(diffPermissions(set(), intent(['p-c']), CATALOGUE).addsSensitive).toBe(true);
    expect(diffPermissions(set('p-c'), intent([], ['p-c']), CATALOGUE).addsSensitive).toBe(false);
  });

  it('flags an empty result', () => {
    const diff = diffPermissions(set('p-a', 'p-b'), intent([], ['p-a', 'p-b']), CATALOGUE);
    expect(diff.resultIsEmpty).toBe(true);
    expect(diff.resulting).toEqual([]);
  });

  it('flags a result holding the whole catalogue', () => {
    const whole = diffPermissions(set('p-a', 'p-b'), intent(['p-c', 'p-d']), CATALOGUE);
    expect(whole.resultIsWholeCatalogue).toBe(true);
    const partial = diffPermissions(set('p-a', 'p-b'), intent(['p-c']), CATALOGUE);
    expect(partial.resultIsWholeCatalogue).toBe(false);
  });

  it('never calls an empty catalogue "whole"', () => {
    const diff = diffPermissions(set(), EMPTY_INTENT, { order: [], sensitive: new Set() });
    expect(diff.resultIsWholeCatalogue).toBe(false);
  });
});

describe('normaliseIntent', () => {
  it('drops adds now in the base and removes now outside it', () => {
    const normal = normaliseIntent(intent(['p-a', 'p-c'], ['p-b', 'p-d']), set('p-a', 'p-b'));
    expect([...normal.add]).toEqual(['p-c']);
    expect([...normal.remove]).toEqual(['p-b']);
  });

  it('returns the same object when nothing changes', () => {
    const staged = intent(['p-c'], ['p-a']);
    expect(normaliseIntent(staged, set('p-a'))).toBe(staged);
  });
});

describe('rebase (design §8.2)', () => {
  it('drops no-ops, reports them, and reports what changed underneath', () => {
    const result = rebase(
      intent(['p-c', 'p-d'], ['p-a', 'p-b']),
      set('p-b', 'p-c'),
      set('p-a', 'p-b'),
    );
    expect([...result.intent.add]).toEqual(['p-d']);
    expect([...result.intent.remove]).toEqual(['p-b']);
    expect(result.droppedAsAlreadyApplied).toEqual(['p-a', 'p-c']);
    expect(result.upstream).toEqual({ added: ['p-c'], removed: ['p-a'] });
    expectInvariants(set('p-b', 'p-c'), result.intent);
  });

  it('gives no upstream change when the old base is unknown', () => {
    const result = rebase(intent(['p-c']), set('p-a', 'p-c'), null);
    expect(result.upstream).toBeNull();
    expect(result.intent).toEqual(EMPTY_INTENT);
    expect(result.droppedAsAlreadyApplied).toEqual(['p-c']);
  });

  it('reports empty upstream lists when the base did not change', () => {
    const result = rebase(intent(['p-c']), set('p-a'), set('p-a'));
    expect(result.upstream).toEqual({ added: [], removed: [] });
    expect(result.droppedAsAlreadyApplied).toEqual([]);
  });
});
