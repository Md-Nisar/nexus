/**
 * The staging engine of the role editor (US-020 design §8.1, §8.2). Pure functions over
 * permission **ids**, with no Angular import and no I/O: the PUT takes ids, and labels are looked
 * up only when something is shown.
 *
 * Staged edits are an intent relative to a base set, so a 412 rebase, a Refresh while editing
 * and a draft restore are the same operation.
 */

/**
 * What the user has staged against a base set. Invariant (kept by every function here):
 * `add ∩ base = ∅`, `remove ⊆ base`, `add ∩ remove = ∅`.
 */
export interface StagedIntent {
  readonly add: ReadonlySet<string>;
  readonly remove: ReadonlySet<string>;
}

/** Nothing staged. */
export const EMPTY_INTENT: StagedIntent = Object.freeze({
  add: new Set<string>(),
  remove: new Set<string>(),
});

/** The catalogue as the engine needs it: display order and which ids are sensitive. */
export interface CatalogueIndex {
  /** Every catalogue id, in the order lists are shown. */
  readonly order: readonly string[];
  readonly sensitive: ReadonlySet<string>;
}

/** What an intent changes, in catalogue order (ids the catalogue does not hold come last). */
export interface PermissionDiff {
  readonly added: readonly string[];
  readonly removed: readonly string[];
  /** The set the role would grant. */
  readonly resulting: readonly string[];
  /** Nothing would change. */
  readonly isEmpty: boolean;
  /** At least one added permission is sensitive (the confirm becomes "Grant sensitive access"). */
  readonly addsSensitive: boolean;
  /** The role would grant nothing. */
  readonly resultIsEmpty: boolean;
  /** The role would grant every catalogue permission, which makes it administrator-defining. */
  readonly resultIsWholeCatalogue: boolean;
}

/** The outcome of moving an intent onto a new base (design §8.2). */
export interface RebaseResult {
  readonly intent: StagedIntent;
  /** Staged entries the new base already has: adds now in it, removes now gone. Sorted. */
  readonly droppedAsAlreadyApplied: readonly string[];
  /** What changed underneath, or `null` when the old base is unknown. Sorted. */
  readonly upstream: {
    readonly added: readonly string[];
    readonly removed: readonly string[];
  } | null;
}

function without(source: ReadonlySet<string>, id: string): ReadonlySet<string> {
  const next = new Set(source);
  next.delete(id);
  return next;
}

function withId(source: ReadonlySet<string>, id: string): ReadonlySet<string> {
  return new Set(source).add(id);
}

function sorted(ids: Iterable<string>): string[] {
  return [...ids].sort();
}

function inCatalogueOrder(ids: ReadonlySet<string>, order: readonly string[]): string[] {
  const known = new Set(order);
  return [...order.filter((id) => ids.has(id)), ...sorted([...ids].filter((id) => !known.has(id)))];
}

/**
 * Sets `id` to `next` in the staged result. Toggling back to the base state removes the entry;
 * asking for the state the result already has changes nothing.
 */
export function toggle(
  base: ReadonlySet<string>,
  intent: StagedIntent,
  id: string,
  next: boolean,
): StagedIntent {
  const inBase = base.has(id);
  if (next) {
    if (intent.remove.has(id)) return { add: intent.add, remove: without(intent.remove, id) };
    if (inBase || intent.add.has(id)) return intent;
    return { add: withId(intent.add, id), remove: intent.remove };
  }
  if (intent.add.has(id)) return { add: without(intent.add, id), remove: intent.remove };
  if (!inBase || intent.remove.has(id)) return intent;
  return { add: intent.add, remove: withId(intent.remove, id) };
}

/** Applies {@link toggle} to every member of a group for which `isEnabled` is true, only. */
export function toggleGroup(
  base: ReadonlySet<string>,
  intent: StagedIntent,
  members: readonly string[],
  next: boolean,
  isEnabled: (id: string) => boolean,
): StagedIntent {
  return members.filter(isEnabled).reduce((staged, id) => toggle(base, staged, id, next), intent);
}

/** The result of applying `intent` to `base`. */
export function resultOf(base: ReadonlySet<string>, intent: StagedIntent): ReadonlySet<string> {
  const result = new Set([...base].filter((id) => !intent.remove.has(id)));
  for (const id of intent.add) result.add(id);
  return result;
}

/** What `intent` changes on `base`, with the flags the Review needs (design §8.1). */
export function diffPermissions(
  base: ReadonlySet<string>,
  intent: StagedIntent,
  catalogue: CatalogueIndex,
): PermissionDiff {
  const result = resultOf(base, intent);
  const added = inCatalogueOrder(intent.add, catalogue.order);
  const removed = inCatalogueOrder(intent.remove, catalogue.order);
  return {
    added,
    removed,
    resulting: inCatalogueOrder(result, catalogue.order),
    isEmpty: added.length === 0 && removed.length === 0,
    addsSensitive: added.some((id) => catalogue.sensitive.has(id)),
    resultIsEmpty: result.size === 0,
    resultIsWholeCatalogue:
      catalogue.order.length > 0 && catalogue.order.every((id) => result.has(id)),
  };
}

/**
 * Drops the entries `base` already satisfies: adds now in it and removes no longer in it. Returns
 * `intent` itself when nothing is dropped, so a `computed` over it stays stable.
 */
export function normaliseIntent(intent: StagedIntent, base: ReadonlySet<string>): StagedIntent {
  const add = [...intent.add].filter((id) => !base.has(id));
  const remove = [...intent.remove].filter((id) => base.has(id));
  if (add.length === intent.add.size && remove.length === intent.remove.size) return intent;
  return { add: new Set(add), remove: new Set(remove) };
}

/**
 * Drops the entries whose row is no longer enabled (RC-74 item 3): after a draft restore or a 412
 * rebase, a row the caller cannot change must never show as staged. `dropped` is sorted. Returns
 * `intent` itself when nothing is dropped.
 */
export function dropDisabled(
  intent: StagedIntent,
  isEnabled: (id: string) => boolean,
): { readonly intent: StagedIntent; readonly dropped: readonly string[] } {
  const add = [...intent.add].filter(isEnabled);
  const remove = [...intent.remove].filter(isEnabled);
  if (add.length === intent.add.size && remove.length === intent.remove.size) {
    return { intent, dropped: [] };
  }
  const dropped = [...intent.add, ...intent.remove].filter((id) => !isEnabled(id));
  return { intent: { add: new Set(add), remove: new Set(remove) }, dropped: sorted(dropped) };
}

/**
 * Moves `intent` onto `newBase` (design §8.2): no-ops are dropped and reported, and `upstream`
 * says what changed between `oldBase` and `newBase` (`null` when `oldBase` is unknown, as for a
 * draft whose base tag differs).
 */
export function rebase(
  intent: StagedIntent,
  newBase: ReadonlySet<string>,
  oldBase: ReadonlySet<string> | null,
): RebaseResult {
  const next = normaliseIntent(intent, newBase);
  const dropped = [
    ...[...intent.add].filter((id) => !next.add.has(id)),
    ...[...intent.remove].filter((id) => !next.remove.has(id)),
  ];
  return {
    intent: next,
    droppedAsAlreadyApplied: sorted(dropped),
    upstream:
      oldBase === null
        ? null
        : {
            added: sorted([...newBase].filter((id) => !oldBase.has(id))),
            removed: sorted([...oldBase].filter((id) => !newBase.has(id))),
          },
  };
}
