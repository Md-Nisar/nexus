import { Page, Response } from '@playwright/test';
import { expectNoSeriousA11yViolations } from '../fixtures/axe';
import { PERSONAS, PersonaKey } from '../fixtures/personas';
import { enterAddress } from '../fixtures/secret-input';
import { expect, test } from '../fixtures/test';

// The user page renders a directory address; no trace is recorded, so nothing personal reaches
// the uploaded report (file-level: Playwright does not allow a trace override inside a group).
test.use({ trace: 'off' });

/**
 * US-020 T-016: the user page and its Roles tab, read as the role-reader user manager
 * (`role:read`, `user:read`, `user:directory:read`; not an administrator). Reads only: nothing
 * here changes a user or an assignment, so target B keeps its one seeded role.
 *
 * PII (design §19.3): target B is reached through the exact-email lookup, typed with
 * `enterAddress`, so the address never reaches a step title; the page is asserted by test id,
 * role name and attributes, never by address text.
 */
const PERSONA = 'roleReaderUserManager';
/** Target B's one role, seeded by `DevDataInitializer` (a custom role). */
const TARGET_ROLE = 'Target Reader';
const UUID = '[0-9a-f-]{36}';

function isLookupResponse(response: Response): boolean {
  return (
    response.request().method() === 'POST' &&
    new URL(response.url()).pathname === '/api/v1/users/lookup'
  );
}

function isAssignmentsResponse(response: Response): boolean {
  return (
    response.request().method() === 'GET' &&
    /^\/api\/v1\/users\/[0-9a-f-]{36}\/roles$/.test(new URL(response.url()).pathname)
  );
}

/** Opens target B's user page through the lookup and waits for its assignments read. */
async function openTargetB(page: Page): Promise<Response> {
  await page.goto('/admin/access/users');
  const field = page.getByRole('searchbox', { name: 'Find by email' });
  await enterAddress(field, PERSONAS.targetB.email);
  const found = page.waitForResponse(isLookupResponse);
  await field.press('Enter');
  expect((await found).ok()).toBe(true);

  const result = page.getByTestId('users-lookup-result');
  await expect(result.getByTestId('user-row-email')).toHaveCount(1);
  const assignments = page.waitForResponse(isAssignmentsResponse);
  await result.locator('tbody a').first().click();
  const response = await assignments;
  await expect(page).toHaveURL(new RegExp(`/admin/access/users/${UUID}/roles$`));
  return response;
}

async function withPage(
  personaContext: (key: PersonaKey) => Promise<{ newPage(): Promise<Page> }>,
  key: PersonaKey,
  body: (page: Page) => Promise<void>,
): Promise<void> {
  const page = await (await personaContext(key)).newPage();
  try {
    await body(page);
  } finally {
    await page.close();
  }
}

test.describe('user page', () => {
  test("shows target B's status and its one role from the join, without an assigner for a non-administrator", async ({
    personaContext,
  }) => {
    await withPage(personaContext, PERSONA, async (page) => {
      const response = await openTargetB(page);
      expect(response.ok()).toBe(true);
      expect(page.url()).not.toMatch(/@|%40/);
      await expect(page).toHaveTitle('User roles · Nexus');

      await expect(page.getByTestId('user-detail-title')).toBeVisible();
      await expect(page.getByTestId('user-status-badge')).toHaveAttribute('data-status', 'ACTIVE');
      await expect(page.getByTestId('user-verified')).toHaveCount(1);
      await expect(page.getByTestId('user-detail-joined')).toBeVisible();
      await expect(page.getByTestId('user-status-banner')).toHaveCount(0);

      const name = page.getByTestId('user-role-name');
      await expect(name).toHaveCount(1);
      await expect(name).toHaveText(TARGET_ROLE);
      await expect(name.getByRole('link')).toHaveAttribute(
        'href',
        new RegExp(`^/admin/access/roles/${UUID}$`),
      );
      // The Type badge comes from the roles join (role:read).
      await expect(page.getByTestId('system-role-badge')).toHaveAttribute('data-kind', 'custom');
      await expect(page.getByTestId('user-roles-no-role-read')).toHaveCount(0);
      // The server redacts the assigner for a non-administrator, so the column is not shown.
      await expect(page.getByTestId('user-role-assigned-by')).toHaveCount(0);
      await expect(page.getByRole('columnheader', { name: 'Assigned by' })).toHaveCount(0);
    });
  });

  test('shows who assigned target B its role to an administrator', async ({ personaContext }) => {
    await withPage(personaContext, 'admin', async (page) => {
      const response = await openTargetB(page);
      expect(response.ok()).toBe(true);

      await expect(page.getByTestId('user-role-name')).toHaveText(TARGET_ROLE);
      await expect(page.getByRole('columnheader', { name: 'Assigned by' })).toBeVisible();
      await expect(page.getByTestId('user-role-assigned-by')).toHaveCount(1);
    });
  });

  test('an unknown id is the "not found" page with a way back to Users', async ({
    personaContext,
  }) => {
    await withPage(personaContext, PERSONA, async (page) => {
      await page.goto('/admin/access/users/00000000-0000-7000-8000-00000000ffff');

      await expect(page.getByTestId('user-detail-title')).toHaveText(
        "We couldn't find this person",
      );
      await expect(page.getByTestId('user-not-found')).toContainText(
        "They aren't in your organisation, or the link is wrong.",
      );
      await page.getByTestId('user-not-found-back').click();
      await expect(page).toHaveURL(/\/admin\/access\/users$/);
    });
  });

  for (const scheme of ['light', 'dark'] as const) {
    test(`has no serious accessibility violations in ${scheme} mode`, async ({
      personaContext,
    }) => {
      await withPage(personaContext, PERSONA, async (page) => {
        await page.emulateMedia({ colorScheme: scheme });
        await page.addInitScript((theme) => localStorage.setItem('nx-theme', theme), scheme);
        await openTargetB(page);
        await expect(page.getByTestId('user-role-name')).toHaveCount(1);
        await expect(page.locator('html')).toHaveAttribute('data-theme', scheme);
        await expectNoSeriousA11yViolations(page);
      });
    });
  }
});
