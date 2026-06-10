import { test, expect } from '@playwright/test';

test.describe('application shell', () => {
  test('boots and renders without console errors', async ({ page }) => {
    const consoleErrors: string[] = [];
    page.on('console', (message) => {
      if (message.type() === 'error') {
        consoleErrors.push(message.text());
      }
    });

    await page.goto('/');

    await expect(page.locator('app-root')).toBeAttached();
    expect(consoleErrors).toEqual([]);
  });
});
