import { APIRequestContext, BrowserContext, Page, Response } from '@playwright/test';
import { expectNoSeriousA11yViolations } from '../fixtures/axe';
import { apiBase } from '../fixtures/backend';
import { PERSONAS, PersonaKey } from '../fixtures/personas';
import { enterAddress } from '../fixtures/secret-input';
import { expect, test } from '../fixtures/test';

// The dialog renders directory addresses; no trace is recorded, so nothing personal reaches the
// uploaded report (file-level: Playwright does not allow a trace override inside a group).
test.use({ trace: 'off' });

/**
 * US-020 T-017: the Assign dialog (design §8.3, §12.9, §19.3; RC-68, RC-69, H-2).
 *
 * - Assignments go to **target A** only, and only of per-worker roles `e2e-w{worker}-{random}`
 *   created through the API as the administrator. `afterAll` revokes every assignment made here
 *   and deletes the roles, so target B's seeded role and every persona's roles stay untouched.
 * - API writes use a bearer token taken from the administrator context's own refresh cookie while
 *   no page of that context is open (one page at a time per persona context, `fixtures/test.ts`).
 * - PII: addresses are typed with `enterAddress` and never asserted as text; rows, badges, tokens
 *   and the dialog identity line are asserted by test id and attribute.
 * - RC-68 item 4: the hidden-character target is the PENDING persona `hiddenCharacterTarget`,
 *   seeded by the dev seeder below the registration validation. The suite never registers such an
 *   address, so it neither depends on nor pins registration accepting U+202E: when F-5 makes
 *   registration reject it, this suite stays green (review Medium on F-5).
 */
const ASSIGNER: PersonaKey = 'roleReaderUserManager';

/** Labels of the permissions used here (`copy/permission-labels.ts`, provisional D3). */
const LABELS = {
  'role:read': 'Read roles and their permission assignments',
  'audit:read': 'Read the authentication and audit event trail',
  'user:directory:read': 'Read the tenant user directory, including email addresses',
} as const;

type Code = keyof typeof LABELS;

const UUID = '[0-9a-f-]{36}';

/** Role ids this worker created, and the target-A assignments made with them. */
const createdRoles: string[] = [];
const madeAssignments: { userId: string; roleId: string }[] = [];

interface AdminClient {
  createRole(codes: readonly Code[]): Promise<{ id: string; name: string }>;
  revoke(userId: string, roleId: string): Promise<number>;
  deleteRole(roleId: string): Promise<number>;
}

async function adminClient(context: BrowserContext): Promise<AdminClient> {
  const request: APIRequestContext = context.request;
  const refreshed = await request.post(`${apiBase}/api/v1/auth/refresh`);
  expect(refreshed.ok()).toBe(true);
  const session = (await refreshed.json()) as { accessToken: string; tokenType: string };
  const headers = { Authorization: `${session.tokenType} ${session.accessToken}` };

  const catalogue = await request.get(`${apiBase}/api/v1/permissions?page=0&size=100`, {
    headers,
  });
  expect(catalogue.ok()).toBe(true);
  const byName = new Map(
    ((await catalogue.json()) as { data: { id: string; name: string }[] }).data.map((entry) => [
      entry.name,
      entry.id,
    ]),
  );

  return {
    async createRole(codes) {
      const name = `e2e-w${test.info().workerIndex}-${Math.random().toString(36).slice(2, 10)}`;
      const created = await request.post(`${apiBase}/api/v1/roles`, {
        headers,
        data: { name, description: 'Created by the assign dialog end-to-end test' },
      });
      expect(created.status()).toBe(201);
      const { id } = (await created.json()) as { id: string };
      createdRoles.push(id);
      const set = await request.get(`${apiBase}/api/v1/roles/${id}/permissions`, { headers });
      expect(set.ok()).toBe(true);
      const replaced = await request.put(`${apiBase}/api/v1/roles/${id}/permissions`, {
        headers: { ...headers, 'If-Match': set.headers()['etag'] ?? '' },
        data: {
          permissionIds: codes.map((code) => {
            const permissionId = byName.get(code);
            if (permissionId === undefined) throw new Error(`${code} is not in the catalogue`);
            return permissionId;
          }),
        },
      });
      expect(replaced.status()).toBe(200);
      return { id, name };
    },
    async revoke(userId, roleId) {
      const response = await request.delete(`${apiBase}/api/v1/users/${userId}/roles/${roleId}`, {
        headers,
      });
      return response.status();
    },
    async deleteRole(roleId) {
      const response = await request.delete(`${apiBase}/api/v1/roles/${roleId}`, { headers });
      return response.status();
    },
  };
}

function isLookupResponse(response: Response): boolean {
  return (
    response.request().method() === 'POST' &&
    new URL(response.url()).pathname === '/api/v1/users/lookup'
  );
}

function isAssignmentsRead(response: Response): boolean {
  return (
    response.request().method() === 'GET' &&
    new RegExp(`^/api/v1/users/${UUID}/roles$`).test(new URL(response.url()).pathname)
  );
}

function isAssignPost(response: Response): boolean {
  return (
    response.request().method() === 'POST' &&
    new RegExp(`^/api/v1/users/${UUID}/roles$`).test(new URL(response.url()).pathname)
  );
}

function isPermissionsRead(roleId: string): (response: Response) => boolean {
  return (response) =>
    response.request().method() === 'GET' &&
    new URL(response.url()).pathname === `/api/v1/roles/${roleId}/permissions`;
}

/** Looks an address up on the users page; returns the lookup result region. */
async function lookUp(page: Page, address: string) {
  await page.goto('/admin/access/users');
  const field = page.getByRole('searchbox', { name: 'Find by email' });
  await enterAddress(field, address);
  const found = page.waitForResponse(isLookupResponse);
  await field.press('Enter');
  expect((await found).ok()).toBe(true);
  const result = page.getByTestId('users-lookup-result');
  await expect(result.getByTestId('user-row-email')).toHaveCount(1);
  return result;
}

/** Opens a person's user page through the lookup; returns their user id. */
async function openUser(page: Page, address: string): Promise<string> {
  const result = await lookUp(page, address);
  const assignments = page.waitForResponse(isAssignmentsRead);
  await result.locator('tbody a').first().click();
  await assignments;
  await expect(page).toHaveURL(new RegExp(`/admin/access/users/${UUID}/roles$`));
  const match = new RegExp(`/users/(${UUID})/roles$`).exec(new URL(page.url()).pathname);
  if (match === null) throw new Error('No user id in the user page URL');
  return match[1];
}

async function openDialog(page: Page) {
  const assign = page.getByTestId('user-roles-assign').getByRole('button');
  await expect(assign).not.toHaveAttribute('aria-disabled', 'true');
  await assign.click();
  const dialog = page.getByTestId('assign-dialog');
  await expect(dialog).toBeVisible();
  return dialog;
}

async function choose(page: Page, roleId: string): Promise<void> {
  const option = page.locator(`[data-testid="assign-role-option"][data-role-id="${roleId}"]`);
  const read = page.waitForResponse(isPermissionsRead(roleId));
  await option.getByRole('radio').check();
  expect((await read).ok()).toBe(true);
}

async function withPage(
  personaContext: (key: PersonaKey) => Promise<BrowserContext>,
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

async function admin(personaContext: (key: PersonaKey) => Promise<BrowserContext>) {
  return adminClient(await personaContext('admin'));
}

test.describe('assign dialog', () => {
  test.afterAll(async ({ personaContext }) => {
    const client = await admin(personaContext);
    for (const { userId, roleId } of madeAssignments.splice(0)) {
      expect([204, 404]).toContain(await client.revoke(userId, roleId));
    }
    for (const roleId of createdRoles.splice(0)) {
      expect(await client.deleteRole(roleId)).toBe(204);
    }
  });

  test('assigns a grantable role to target A: toast, propagation line and the re-read row', async ({
    personaContext,
  }) => {
    const role = await (await admin(personaContext)).createRole(['role:read']);
    await withPage(personaContext, ASSIGNER, async (page) => {
      const userId = await openUser(page, PERSONAS.targetA.email);
      const dialog = await openDialog(page);
      await expect(dialog.getByTestId('target-identity')).toBeVisible();
      await expect(dialog.getByTestId('user-status-badge')).toHaveAttribute(
        'data-status',
        'ACTIVE',
      );
      await expect(dialog.getByTestId('assign-pending-warning')).toHaveCount(0);

      await choose(page, role.id);
      await expect(dialog.getByTestId('assign-selected-grants')).toHaveText(
        `Grants: ${LABELS['role:read']}`,
      );
      const confirm = dialog.getByTestId('assign-confirm').getByRole('button');
      await expect(confirm).toHaveText('Assign role');

      const posted = page.waitForResponse(isAssignPost);
      const reread = page.waitForResponse(isAssignmentsRead);
      await confirm.click();
      const response = await posted;
      expect(response.status()).toBe(201);
      madeAssignments.push({ userId, roleId: role.id });
      await reread;

      await expect(page.getByTestId('assign-dialog')).toHaveCount(0);
      await expect(page.getByTestId('user-roles-propagation')).toContainText(
        'This takes effect within about 15 minutes',
      );
      await expect(page.getByTestId('user-role-name').filter({ hasText: role.name })).toHaveCount(
        1,
      );
    });
  });

  test('C3(b): a role carrying a permission the assigner lacks is refused with the missing label', async ({
    personaContext,
  }) => {
    const role = await (await admin(personaContext)).createRole(['role:read', 'audit:read']);
    await withPage(personaContext, ASSIGNER, async (page) => {
      await openUser(page, PERSONAS.targetA.email);
      const dialog = await openDialog(page);
      await choose(page, role.id);

      await expect(dialog.getByTestId('assign-selected-reason')).toHaveText(
        `This role includes access you don't hold: ${LABELS['audit:read']}.`,
      );
      await expect(dialog.getByTestId('assign-confirm').getByRole('button')).toHaveAttribute(
        'aria-disabled',
        'true',
      );
    });
  });

  test('PII rule: a role carrying user:directory:read is administrator-only', async ({
    personaContext,
  }) => {
    const role = await (await admin(personaContext)).createRole(['user:directory:read']);
    await withPage(personaContext, ASSIGNER, async (page) => {
      await openUser(page, PERSONAS.targetA.email);
      const dialog = await openDialog(page);
      await choose(page, role.id);

      await expect(dialog.getByTestId('assign-selected-reason')).toHaveText(
        'Only an administrator can grant access to email addresses.',
      );
      await expect(dialog.getByTestId('assign-confirm').getByRole('button')).toHaveAttribute(
        'aria-disabled',
        'true',
      );
    });
  });

  test("FR-C4: a user manager's own page offers no assign, with the reason", async ({
    personaContext,
  }) => {
    await withPage(personaContext, 'userManager', async (page) => {
      await openUser(page, PERSONAS.userManager.email);
      await expect(page.getByTestId('user-you')).toBeVisible();

      const assign = page.getByTestId('user-roles-assign').getByRole('button');
      await expect(assign).toHaveAttribute('aria-disabled', 'true');
      await expect(page.getByTestId('user-roles-assign-reason')).toHaveText(
        "You can't change your own roles. Ask an administrator.",
      );
      // Playwright waits for an aria-disabled button to become enabled; the click is forced so
      // that the button itself is what refuses it.
      await assign.click({ force: true });
      await expect(page.getByTestId('assign-dialog')).toHaveCount(0);
    });
  });

  test('RC-68: hidden characters show in the row, as a token, and on the dialog identity line', async ({
    personaContext,
  }) => {
    await withPage(personaContext, ASSIGNER, async (page) => {
      const result = await lookUp(page, PERSONAS.hiddenCharacterTarget.email);
      const row = result.getByTestId('user-row-email');
      await expect(row.getByTestId('user-text-hidden-badge')).toHaveCount(1);
      await expect(row.getByTestId('user-text-hidden-token')).toHaveText('⟨U+202E⟩');
      await expect(row.getByTestId('user-text-hidden-token')).toHaveAttribute(
        'aria-label',
        'hidden character U+202E',
      );

      const assignments = page.waitForResponse(isAssignmentsRead);
      await result.locator('tbody a').first().click();
      await assignments;
      const dialog = await openDialog(page);
      const identity = dialog.getByTestId('target-identity');
      await expect(identity.getByTestId('user-text-hidden-badge')).toHaveCount(1);
      await expect(identity.getByTestId('user-text-hidden-token')).toHaveText('⟨U+202E⟩');
      await expect(identity.getByTestId('user-status-badge')).toHaveAttribute(
        'data-status',
        'PENDING',
      );
      await expect(identity.getByTestId('target-identity-verified')).toHaveAttribute(
        'data-verified',
        'false',
      );
      // RC-69: the target has not verified, so the risk warning is an alert.
      await expect(dialog.getByTestId('assign-pending-warning').getByRole('alert')).toBeVisible();

      await dialog.getByTestId('assign-cancel').getByRole('button').click();
      await expect(page.getByTestId('assign-dialog')).toHaveCount(0);
    });
  });

  for (const scheme of ['light', 'dark'] as const) {
    test(`the dialog has no serious accessibility violations in ${scheme} mode`, async ({
      personaContext,
    }) => {
      const role = await (await admin(personaContext)).createRole(['role:read']);
      await withPage(personaContext, ASSIGNER, async (page) => {
        await page.emulateMedia({ colorScheme: scheme });
        await page.addInitScript((theme) => localStorage.setItem('nx-theme', theme), scheme);
        await openUser(page, PERSONAS.targetA.email);
        await expect(page.locator('html')).toHaveAttribute('data-theme', scheme);
        const dialog = await openDialog(page);
        await choose(page, role.id);
        await expect(dialog.getByTestId('assign-selected-grants')).toBeVisible();
        await expectNoSeriousA11yViolations(page);
      });
    });
  }
});
