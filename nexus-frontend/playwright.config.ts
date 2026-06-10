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
    screenshot: 'only-on-failure',
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
