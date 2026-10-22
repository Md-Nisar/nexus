import { defineConfig, devices } from '@playwright/test';

/**
 * E2E configuration. `webServer` boots the Angular dev server automatically, so
 * `npm run e2e` works locally and in CI with no manual setup beyond
 * `npx playwright install chromium`.
 */
export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env['CI'],
  retries: process.env['CI'] ? 2 : 0,
  reporter: process.env['CI'] ? [['html', { open: 'never' }], ['github']] : 'list',
  use: {
    baseURL: 'http://localhost:2000',
    trace: 'on-first-retry',
    // CI uploads artifacts after a text-only PII scan (e2e/tools/scan-pii.mjs); a screenshot of
    // the shell header shows the signed-in address and cannot be scanned, so CI takes none.
    screenshot: process.env['CI'] ? 'off' : 'only-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: {
    command: 'npm start',
    url: 'http://localhost:2000',
    reuseExistingServer: !process.env['CI'],
    timeout: 120_000,
  },
});
