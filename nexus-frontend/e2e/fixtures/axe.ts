import AxeBuilder from '@axe-core/playwright';
import { expect, Page, test } from '@playwright/test';

interface AxeOptions {
  readonly include?: string;
  readonly disableRules?: readonly string[];
}

/**
 * Fails on any critical or serious WCAG 2.x A/AA violation and attaches the JSON result. Scans after
 * finite animations and transitions have finished.
 */
export async function expectNoSeriousA11yViolations(
  page: Page,
  options: AxeOptions = {},
): Promise<void> {
  // Contrast is measured on what is painted, so a dialog still fading in reads as a violation.
  await page.evaluate(() =>
    Promise.all(
      document
        .getAnimations()
        .filter((animation) => animation.effect?.getComputedTiming().iterations !== Infinity)
        .map((animation) => animation.finished.catch(() => undefined)),
    ),
  );
  let builder = new AxeBuilder({ page }).withTags([
    'wcag2a',
    'wcag2aa',
    'wcag21a',
    'wcag21aa',
    'wcag22aa',
  ]);
  if (options.include) builder = builder.include(options.include);
  if (options.disableRules) builder = builder.disableRules([...options.disableRules]);

  const results = await builder.analyze();
  const serious = results.violations.filter(
    (v) => v.impact === 'critical' || v.impact === 'serious',
  );
  if (serious.length > 0) {
    await test.info().attach('axe-violations.json', {
      body: JSON.stringify(serious, null, 2),
      contentType: 'application/json',
    });
  }
  expect(serious.map((v) => `${v.id} (${v.impact}): ${v.nodes.length} node(s)`)).toEqual([]);
}
