import { APIRequestContext, BrowserContext, Locator, Page, Response } from '@playwright/test';
import { expectNoSeriousA11yViolations } from '../fixtures/axe';
import { apiBase } from '../fixtures/backend';
import { PERSONAS, PersonaKey } from '../fixtures/personas';
import { enterAddress } from '../fixtures/secret-input';
import { expect, test } from '../fixtures/test';

// The dialogs render directory addresses; no trace is recorded, so nothing personal reaches the
// uploaded report (file-level: Playwright does not allow a trace override inside a group).
test.use({ trace: 'off' });

/**
 * US-020 T-018: the Revoke dialogs (design §11.4, §12.10, §19.3; RC-68 item 2, D-5).
 *
 * - Revokes act on **target A** only, and only on per-worker roles `e2e-w{worker}-{random}` that
 *   the administrator creates and assigns through the API first. `afterAll` revokes whatever is
 *   left and deletes the roles, so target B's seeded role and every persona's roles stay untouched.
 * - The typed self-revoke dialog is opened on the administrator's own page for the accessibility
 *   scan only and is always cancelled: it is never confirmed.
 * - `RBAC_002` is not covered here (design §19.3: it needs a tenant with a single administrator);
 *   the unit spec and the backend `LastAdminLockoutIT` cover it.
 * - API writes use a bearer token taken from the administrator context's own refresh cookie while
 *   no page of that context is open (one page at a time per persona context, `fixtures/test.ts`).
 * - PII: addresses are typed with `enterAddress` and never asserted as text.
 */
const REVOKER: PersonaKey = 'roleReaderUserManager';

const ROLE_READ_LABEL = 'Read roles and their permission assignments';
const SYSTEM_ADMIN_ROLE = 'TENANT_ADMIN';

const UUID = '[0-9a-f-]{36}';

/** Role ids this worker created, and the target-A assignments that may still need removing. */
const createdRoles: string[] = [];
const madeAssignments: { userId: string; roleId: string }[] = [];

interface AdminClient {
  /** Creates a per-worker role granting `role:read` and assigns it to target A. */
  assignNewRoleToTargetA(): Promise<{ id: string; name: string; userId: string }>;
  revoke(userId: string, roleId: string): Promise<number>;
  deleteRole(roleId: string): Promise<number>;
}

async function adminClient(context: BrowserContext): Promise<AdminClient> {
  const request: APIRequestContext = context.request;
  const refreshed = await request.post(`${apiBase}/api/v1/auth/refresh`);
  expect(refreshed.ok()).toBe(true);
  const session = (await refreshed.json()) as { accessToken: string; tokenType: string };
  const headers = { Authorization: `${session.tokenType} ${session.accessToken}` };

  async function permissionId(code: string): Promise<string> {
    const catalogue = await request.get(`${apiBase}/api/v1/permissions?page=0&size=100`, {
      headers,
    });
    expect(catalogue.ok()).toBe(true);
    const entry = ((await catalogue.json()) as { data: { id: string; name: string }[] }).data.find(
      (permission) => permission.name === code,
    );
    if (entry === undefined) throw new Error(`${code} is not in the catalogue`);
    return entry.id;
  }

  async function targetAId(): Promise<string> {
    // The address travels in a POST body only, never in a URL (SD-13).
    const found = await request.post(`${apiBase}/api/v1/users/lookup`, {
      headers,
      data: { email: PERSONAS.targetA.email },
    });
    expect(found.ok()).toBe(true);
    const { data } = (await found.json()) as { data: { userId: string }[] };
    expect(data).toHaveLength(1);
    return data[0].userId;
  }

  return {
    async assignNewRoleToTargetA() {
      const name = `e2e-w${test.info().workerIndex}-${Math.random().toString(36).slice(2, 10)}`;
      const created = await request.post(`${apiBase}/api/v1/roles`, {
        headers,
        data: { name, description: 'Created by the revoke dialog end-to-end test' },
      });
      expect(created.status()).toBe(201);
      const { id } = (await created.json()) as { id: string };
      createdRoles.push(id);
      const set = await request.get(`${apiBase}/api/v1/roles/${id}/permissions`, { headers });
      expect(set.ok()).toBe(true);
      const replaced = await request.put(`${apiBase}/api/v1/roles/${id}/permissions`, {
        headers: { ...headers, 'If-Match': set.headers()['etag'] ?? '' },
        data: { permissionIds: [await permissionId('role:read')] },
      });
      expect(replaced.status()).toBe(200);

      const userId = await targetAId();
      const assigned = await request.post(`${apiBase}/api/v1/users/${userId}/roles`, {
        headers,
        data: { roleId: id },
      });
      expect(assigned.status()).toBe(201);
      madeAssignments.push({ userId, roleId: id });
      return { id, name, userId };
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

function isRevoke(roleId: string): (response: Response) => boolean {
  return (response) =>
    response.request().method() === 'DELETE' &&
    new RegExp(`^/api/v1/users/${UUID}/roles/${roleId}$`).test(new URL(response.url()).pathname);
}

function isPermissionsRead(roleId: string): (response: Response) => boolean {
  return (response) =>
    response.request().method() === 'GET' &&
    new URL(response.url()).pathname === `/api/v1/roles/${roleId}/permissions`;
}

/** Opens a person's user page through the lookup. */
async function openUser(page: Page, address: string): Promise<void> {
  await page.goto('/admin/access/users');
  const field = page.getByRole('searchbox', { name: 'Find by email' });
  await enterAddress(field, address);
  const found = page.waitForResponse(isLookupResponse);
  await field.press('Enter');
  expect((await found).ok()).toBe(true);
  const result = page.getByTestId('users-lookup-result');
  await expect(result.getByTestId('user-row-email')).toHaveCount(1);
  const assignments = page.waitForResponse(isAssignmentsRead);
  await result.locator('tbody a').first().click();
  await assignments;
  await expect(page).toHaveURL(new RegExp(`/admin/access/users/${UUID}/roles$`));
}

function removeButton(page: Page, roleId: string): Locator {
  return page
    .locator(`[data-testid="user-role-revoke"][data-role-id="${roleId}"]`)
    .getByRole('button');
}

/** Opens the standard dialog for a role and waits for its "They will lose" read. */
async function openStandard(page: Page, roleId: string): Promise<Locator> {
  const remove = removeButton(page, roleId);
  await expect(remove).not.toHaveAttribute('aria-disabled', 'true');
  const read = page.waitForResponse(isPermissionsRead(roleId));
  await remove.click();
  expect((await read).ok()).toBe(true);
  const dialog = page.getByTestId('revoke-dialog');
  await expect(dialog).toBeVisible();
  await expect(dialog.getByTestId('revoke-loss')).toHaveText(`They will lose: ${ROLE_READ_LABEL}.`);
  return dialog;
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

async function useScheme(page: Page, scheme: 'light' | 'dark'): Promise<void> {
  await page.emulateMedia({ colorScheme: scheme });
  await page.addInitScript((theme) => localStorage.setItem('nx-theme', theme), scheme);
}

test.describe('revoke dialogs', () => {
  test.afterAll(async ({ personaContext }) => {
    const client = await admin(personaContext);
    for (const { userId, roleId } of madeAssignments.splice(0)) {
      expect([204, 404]).toContain(await client.revoke(userId, roleId));
    }
    for (const roleId of createdRoles.splice(0)) {
      expect(await client.deleteRole(roleId)).toBe(204);
    }
  });

  test('removes a role from target A: identity line, what they lose, toast, propagation line and the re-read', async ({
    personaContext,
  }) => {
    const role = await (await admin(personaContext)).assignNewRoleToTargetA();
    await withPage(personaContext, REVOKER, async (page) => {
      await openUser(page, PERSONAS.targetA.email);
      await expect(page.getByTestId('user-role-name').filter({ hasText: role.name })).toHaveCount(
        1,
      );

      const dialog = await openStandard(page, role.id);
      await expect(dialog.getByTestId('revoke-dialog-title')).toContainText(
        `Remove ${role.name} from`,
      );
      await expect(dialog.getByTestId('target-identity')).toBeVisible();
      await expect(dialog.getByTestId('user-status-badge')).toHaveAttribute(
        'data-status',
        'ACTIVE',
      );
      await expect(dialog.getByTestId('revoke-admin-warning')).toHaveCount(0);
      const confirm = dialog.getByTestId('revoke-confirm').getByRole('button');
      await expect(confirm).toHaveText('Remove role');

      const revoked = page.waitForResponse(isRevoke(role.id));
      const reread = page.waitForResponse(isAssignmentsRead);
      await confirm.click();
      expect((await revoked).status()).toBe(204);
      await reread;

      await expect(page.getByTestId('revoke-dialog')).toHaveCount(0);
      await expect(page.getByText('Role removed.')).toBeVisible();
      await expect(page.getByTestId('user-roles-propagation')).toContainText(
        "This takes effect on the person's next request",
      );
      await expect(page.getByTestId('user-role-name').filter({ hasText: role.name })).toHaveCount(
        0,
      );
    });
  });

  test('converges when the role was already removed before the confirm (404 ROLE_ASSIGNMENT_NOT_FOUND)', async ({
    personaContext,
  }) => {
    const client = await admin(personaContext);
    const role = await client.assignNewRoleToTargetA();
    await withPage(personaContext, REVOKER, async (page) => {
      await openUser(page, PERSONAS.targetA.email);
      const dialog = await openStandard(page, role.id);

      // Someone else removes it first.
      expect(await client.revoke(role.userId, role.id)).toBe(204);

      const revoked = page.waitForResponse(isRevoke(role.id));
      const reread = page.waitForResponse(isAssignmentsRead);
      await dialog.getByTestId('revoke-confirm').getByRole('button').click();
      expect((await revoked).status()).toBe(404);
      await reread;

      await expect(page.getByTestId('revoke-dialog')).toHaveCount(0);
      await expect(page.getByText('This role had already been removed.')).toBeVisible();
      await expect(page.getByTestId('user-role-name').filter({ hasText: role.name })).toHaveCount(
        0,
      );
    });
  });

  for (const scheme of ['light', 'dark'] as const) {
    test(`the standard dialog has no serious accessibility violations in ${scheme} mode`, async ({
      personaContext,
    }) => {
      const role = await (await admin(personaContext)).assignNewRoleToTargetA();
      await withPage(personaContext, REVOKER, async (page) => {
        await useScheme(page, scheme);
        await openUser(page, PERSONAS.targetA.email);
        await expect(page.locator('html')).toHaveAttribute('data-theme', scheme);
        const dialog = await openStandard(page, role.id);
        await expectNoSeriousA11yViolations(page);

        await dialog.getByTestId('revoke-cancel').getByRole('button').click();
        await expect(page.getByTestId('revoke-dialog')).toHaveCount(0);
      });
    });

    test(`the typed self-revoke dialog has no serious accessibility violations in ${scheme} mode`, async ({
      personaContext,
    }) => {
      await withPage(personaContext, 'admin', async (page) => {
        await useScheme(page, scheme);
        await openUser(page, PERSONAS.admin.email);
        await expect(page.locator('html')).toHaveAttribute('data-theme', scheme);
        await expect(page.getByTestId('user-you')).toBeVisible();

        const row = page.getByRole('row').filter({
          has: page.getByTestId('user-role-name').filter({ hasText: SYSTEM_ADMIN_ROLE }),
        });
        const remove = row.getByTestId('user-role-revoke').getByRole('button');
        await expect(remove).not.toHaveAttribute('aria-disabled', 'true');
        await remove.click();

        // D-5: the caller's own administrator role opens the typed variant, with no identity line.
        const typed = page.getByRole('dialog');
        await expect(
          typed.getByRole('heading', { name: `Remove your own ${SYSTEM_ADMIN_ROLE} role?` }),
        ).toBeVisible();
        await expect(page.getByTestId('target-identity')).toHaveCount(0);
        await expect(page.getByTestId('nx-typed-confirm-confirm')).toHaveAttribute(
          'aria-disabled',
          'true',
        );
        await expectNoSeriousA11yViolations(page);

        // Never confirmed: cancelling sends nothing.
        await page.getByTestId('nx-typed-confirm-cancel').click();
        await expect(page.getByRole('dialog')).toHaveCount(0);
        await expect(
          page.getByTestId('user-role-name').filter({ hasText: SYSTEM_ADMIN_ROLE }),
        ).toHaveCount(1);
      });
    });
  }
});
