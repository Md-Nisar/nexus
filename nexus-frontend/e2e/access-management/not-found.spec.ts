import { expectNoSeriousA11yViolations } from '../fixtures/axe';
import { expect, test } from '../fixtures/test';

test.describe('not found', () => {
  test('an unknown URL renders Not Found inside the shell with a way home', async ({
    personaContext,
  }) => {
    const page = await (await personaContext('member')).newPage();
    try {
      await page.goto('/no/such/page');
      await expect(page).toHaveURL(/\/no\/such\/page$/);
      await expect(page).toHaveTitle('Page not found · Nexus');
      await expect(page.getByRole('heading', { level: 1, name: 'Page not found' })).toBeVisible();
      await expect(page.getByTestId('primary-nav')).toBeVisible();
      await expectNoSeriousA11yViolations(page);

      await page.getByTestId('not-found-dashboard-link').click();
      await expect(page).toHaveURL(/\/dashboard$/);
    } finally {
      await page.close();
    }
  });

  test('a signed-out visitor to an unknown URL is sent to login', async ({ page }) => {
    await page.goto('/no/such/page');
    await expect(page).toHaveURL(/\/auth\/login\?returnUrl=%2Fno%2Fsuch%2Fpage$/);
  });
});
