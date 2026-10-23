import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';

const SCHEMES = ['light', 'dark'] as const;

test.describe('design system accessibility', () => {
  for (const scheme of SCHEMES) {
    test(`/design-system has no WCAG A/AA violations in ${scheme} mode`, async ({ browser }) => {
      const context = await browser.newContext({ colorScheme: scheme });
      await context.addInitScript((theme) => localStorage.setItem('nx-theme', theme), scheme);
      const page = await context.newPage();

      await page.goto('/design-system');
      await expect(page.locator('html')).toHaveAttribute('data-theme', scheme);
      await expect(page.getByRole('heading', { level: 1, name: 'Design System' })).toBeVisible();

      const results = await new AxeBuilder({ page })
        .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'])
        .analyze();

      expect(
        results.violations.map((v) => `${v.id} (${v.impact}): ${v.nodes.length} node(s)`),
      ).toEqual([]);
      await context.close();
    });
  }
});
