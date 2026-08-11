import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

/**
 * E2E: US-013 Access Denied page accessibility (AC-5).
 *
 * The page is public and unguarded and makes no HTTP call, so this test needs no
 * backend and no login — it always runs.
 */
test.describe('access denied page', () => {
  test('has zero critical accessibility violations (AC-5)', async ({ page }) => {
    await page.goto('/access-denied');
    await expect(page.locator('[data-testid="access-denied-root"]')).toBeVisible();

    const results = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa']).analyze();

    const critical = results.violations.filter((v) => v.impact === 'critical');
    expect(
      critical,
      `Critical a11y violations:\n${critical.map((v) => `  [${v.id}] ${v.description}\n    ${v.nodes[0]?.html}`).join('\n')}`,
    ).toHaveLength(0);
  });
});
