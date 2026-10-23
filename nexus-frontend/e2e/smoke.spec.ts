import { test, expect } from '@playwright/test';

test.describe('application shell', () => {
  test('boots and renders without console errors', async ({ page }) => {
    const consoleErrors: string[] = [];
    page.on('console', (message) => {
      if (message.type() === 'error') {
        consoleErrors.push(message.text());
      }
    });

    // The sign-in page makes no API call, so the check holds with or without a backend; `/` would
    // try a session refresh first.
    await page.goto('/auth/login');

    await expect(page.locator('app-root')).toBeAttached();
    expect(consoleErrors).toEqual([]);
  });
});
