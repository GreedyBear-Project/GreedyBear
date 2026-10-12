import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./tests/visual",
  fullyParallel: true,
  reporter: "html",
  snapshotPathTemplate: "{testDir}/{testFilePath}-snapshots/{arg}{ext}",
  expect: {
    // Absorb sub-pixel font/AA drift across OSes and Chromium versions;
    // layout-level regressions (missing panels, size changes) still fail.
    toHaveScreenshot: { maxDiffPixelRatio: 0.05 },
  },
  use: {
    baseURL: "http://127.0.0.1:3002",
    trace: "on-first-retry",
  },
  projects: [
    {
      name: "desktop-chromium",
      use: {
        ...devices["Desktop Chrome"],
        viewport: { width: 1440, height: 1200 },
      },
    },
    {
      name: "mobile-chromium",
      use: {
        ...devices["Pixel 7"],
      },
    },
  ],
  webServer: {
    command: "npm run start:visual",
    url: "http://127.0.0.1:3002/tests/visual.html",
    reuseExistingServer: !process.env.CI,
    timeout: 120000,
  },
});
