import axe from 'axe-core';

const WCAG_TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'] as const;
const BLOCKING_IMPACTS: readonly (string | null | undefined)[] = ['critical', 'serious'];

/**
 * Fails when axe finds critical or serious WCAG 2.0/2.1/2.2 A/AA violations in `root`.
 *
 * `color-contrast` is disabled because jsdom has no layout or computed colours; contrast is
 * covered by the token checks and the Playwright axe runs.
 */
export async function expectNoAxeViolations(root: HTMLElement): Promise<void> {
  const results = await axe.run(root, {
    runOnly: { type: 'tag', values: [...WCAG_TAGS] },
    rules: { 'color-contrast': { enabled: false } },
  });
  const blocking = results.violations.filter((v) => BLOCKING_IMPACTS.includes(v.impact));
  if (blocking.length > 0) {
    const summary = blocking
      .map((v) => `${v.id} (${v.impact}): ${v.help} [${v.nodes.length} node(s)]`)
      .join('\n');
    throw new Error(`Axe found ${blocking.length} blocking violation(s):\n${summary}`);
  }
}
