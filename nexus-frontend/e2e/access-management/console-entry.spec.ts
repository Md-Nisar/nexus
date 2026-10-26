import { expect, test } from '../fixtures/test';

/**
 * US-020 P-27: the console entry gate. A persona holding neither role:read nor
 * user:directory:read is turned away by anyPermissionGuard with a bare redirect: no query string
 * reflecting the attempted URL or the required permissions.
 */
test.describe('access console entry', () => {
  test('P-27: a member deep link to /admin/access lands on /access-denied', async ({
    personaContext,
  }) => {
    const page = await (await personaContext('member')).newPage();
    try {
      await page.goto('/admin/access');
      await expect(page).toHaveURL(/\/access-denied$/);
      expect(new URL(page.url()).search).toBe('');
      await expect(page.getByTestId('access-denied-heading')).toBeVisible();
    } finally {
      await page.close();
    }
  });
});
