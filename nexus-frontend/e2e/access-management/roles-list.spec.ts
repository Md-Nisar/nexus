import { Page } from '@playwright/test';
import { expectNoSeriousA11yViolations } from '../fixtures/axe';
import { PersonaKey } from '../fixtures/personas';
import { expect, test } from '../fixtures/test';

// The roles list renders tenant data; no trace is recorded, so nothing personal reaches the
// uploaded report (file-level: Playwright does not allow a trace override inside a group).
test.use({ trace: 'off' });

/**
 * US-020 T-007: the roles list. Both personas hold role:read; only the administrator is asserted
 * to see "Create role" (the role manager's profile may or may not hold role:write, so that is
 * covered by the unit specs). Reads only: nothing here creates or changes a role.
 */
const PERSONAS_UNDER_TEST: readonly PersonaKey[] = ['admin', 'roleManager'];

function rowNames(page: Page) {
  return page.getByTestId('role-name');
}

async function openRoles(page: Page, query = ''): Promise<void> {
  const loaded = page.waitForResponse(
    (response) =>
      response.request().method() === 'GET' &&
      new URL(response.url()).pathname === '/api/v1/roles' &&
      response.ok(),
  );
  await page.goto(`/admin/access/roles${query}`);
  await loaded;
  await expect(page.getByTestId('roles-count')).toBeVisible();
}

test.describe('roles list', () => {
  for (const key of PERSONAS_UNDER_TEST) {
    test.describe(`persona ${key}`, () => {
      test('lists the system roles first with a count, and names are not links', async ({
        personaContext,
      }) => {
        const page = await (await personaContext(key)).newPage();
        try {
          await openRoles(page);

          await expect(page.getByRole('heading', { level: 1, name: 'Roles' })).toBeVisible();
          await expect(page.getByRole('status').filter({ hasText: /^\d+ roles?$/ })).toBeVisible();
          const badges = page.getByTestId('system-role-badge');
          await expect(badges.first()).toHaveAttribute('data-kind', 'system');
          // System roles are one block at the top: no system badge after the first custom one.
          const kinds = await badges.evaluateAll((nodes) =>
            nodes.map((node) => node.getAttribute('data-kind')),
          );
          const firstCustom = kinds.indexOf('custom');
          if (firstCustom !== -1) expect(kinds.slice(firstCustom)).not.toContain('system');
          await expect(page.locator('tbody a')).toHaveCount(0);
        } finally {
          await page.close();
        }
      });

      test('search and filter write q and filter to the URL; Back and Forward restore them', async ({
        personaContext,
      }) => {
        const page = await (await personaContext(key)).newPage();
        try {
          await openRoles(page);
          const search = page.getByRole('searchbox', { name: 'Search roles' });

          await search.fill('member');
          await search.press('Enter');
          await expect(page).toHaveURL(/[?&]q=member(&|$)/);
          await expect(rowNames(page).first()).toContainText(/member/i);
          for (const name of await rowNames(page).allTextContents()) {
            expect(name.toLowerCase()).toContain('member');
          }

          await page.getByRole('combobox', { name: 'Filter by type' }).click();
          await page.getByRole('option', { name: 'System', exact: true }).click();
          await expect(page).toHaveURL(/filter=system/);
          await expect(
            page.locator('[data-testid="system-role-badge"][data-kind="custom"]'),
          ).toHaveCount(0);

          await page.goBack();
          await expect(page).not.toHaveURL(/filter=system/);
          await expect(search).toHaveValue('member');

          await page.goBack();
          await expect(page).not.toHaveURL(/q=member/);
          await expect(search).toHaveValue('');

          await page.goForward();
          await expect(search).toHaveValue('member');
          await expect(page).toHaveURL(/[?&]q=member(&|$)/);
        } finally {
          await page.close();
        }
      });

      test('keeps the query across a reload', async ({ personaContext }) => {
        const page = await (await personaContext(key)).newPage();
        try {
          await openRoles(page, '?q=member&filter=system');
          await page.reload();
          await expect(page.getByTestId('roles-count')).toBeVisible();
          await expect(page.getByRole('searchbox', { name: 'Search roles' })).toHaveValue('member');
          await expect(page).toHaveURL(/q=member&filter=system/);
        } finally {
          await page.close();
        }
      });

      test('shows "No roles match your search" for a search nothing matches', async ({
        personaContext,
      }) => {
        const page = await (await personaContext(key)).newPage();
        try {
          await openRoles(page, '?q=zz-no-such-role-zz');
          await expect(page.getByTestId('nx-empty-state')).toContainText(
            'No roles match your search',
          );
        } finally {
          await page.close();
        }
      });

      for (const scheme of ['light', 'dark'] as const) {
        test(`has no serious accessibility violations in ${scheme} mode`, async ({
          personaContext,
        }) => {
          const page = await (await personaContext(key)).newPage();
          try {
            await page.emulateMedia({ colorScheme: scheme });
            await page.addInitScript((theme) => localStorage.setItem('nx-theme', theme), scheme);
            await openRoles(page);
            await expect(page.locator('html')).toHaveAttribute('data-theme', scheme);
            await expectNoSeriousA11yViolations(page);
          } finally {
            await page.close();
          }
        });
      }
    });
  }

  test('the administrator sees "Create role"', async ({ personaContext }) => {
    const page = await (await personaContext('admin')).newPage();
    try {
      await openRoles(page);
      await expect(page.getByTestId('roles-create')).toBeVisible();
    } finally {
      await page.close();
    }
  });
});
