import { expect, test } from '../fixtures/test';

test.describe('cold-start deep link', () => {
  test('a signed-in user reloading a protected route stays on it', async ({ personaContext }) => {
    const page = await (await personaContext('member')).newPage();
    try {
      await page.goto('/dashboard');
      await expect(page.getByTestId('dashboard-root')).toBeVisible();
      await page.reload();
      await expect(page).toHaveURL(/\/dashboard$/);
      await expect(page.getByTestId('dashboard-root')).toBeVisible();
      await expect(page).toHaveTitle('Dashboard · Nexus');
    } finally {
      await page.close();
    }
  });

  test('the home URL reaches the dashboard for a signed-in user', async ({ personaContext }) => {
    const page = await (await personaContext('admin')).newPage();
    try {
      await page.goto('/');
      await expect(page).toHaveURL(/\/dashboard$/);
    } finally {
      await page.close();
    }
  });

  test('a signed-out visitor is sent to login, not to access denied', async ({ page }) => {
    await page.goto('/dashboard');
    await expect(page).toHaveURL(/\/auth\/login\?returnUrl=%2Fdashboard$/);
    await expect(page.getByTestId('login-submit')).toBeVisible();
  });
});
