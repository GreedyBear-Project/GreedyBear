import { expect, test } from "@playwright/test";

async function freezeExternalNetwork(page, baseURL) {
  await page.route("**/*", async (route) => {
    const url = route.request().url();

    if (
      url.startsWith(baseURL) ||
      url.startsWith("data:") ||
      url.startsWith("blob:")
    ) {
      await route.continue();
      return;
    }

    await route.abort();
  });
}

async function openTable(page, baseURL) {
  await freezeExternalNetwork(page, baseURL);
  await page.goto("/tests/visual.html");
  await expect(page.getByRole("heading", { name: "Table" })).toBeVisible();
  await expect(page.getByTestId("table-visual-interactive")).toBeVisible();
}

test.describe("table visual states", () => {
  test("default state", async ({ page, baseURL, browserName, isMobile }) => {
    test.skip(browserName !== "chromium");
    test.skip(isMobile);

    await openTable(page, baseURL);

    await expect(page.getByTestId("table-visual-interactive")).toHaveScreenshot(
      "table-default-desktop.png",
      { animations: "disabled", caret: "hide" },
    );
  });

  test("sorted ascending", async ({ page, baseURL, browserName, isMobile }) => {
    test.skip(browserName !== "chromium");
    test.skip(isMobile);

    await openTable(page, baseURL);

    const section = page.getByTestId("table-visual-interactive");
    await section.getByRole("button", { name: /Title/i }).click();

    await expect(section).toHaveScreenshot("table-sorted-asc-desktop.png", {
      animations: "disabled",
      caret: "hide",
    });
  });

  test("sorted descending", async ({
    page,
    baseURL,
    browserName,
    isMobile,
  }) => {
    test.skip(browserName !== "chromium");
    test.skip(isMobile);

    await openTable(page, baseURL);

    const section = page.getByTestId("table-visual-interactive");
    const titleHeader = section.getByRole("button", { name: /Title/i });

    await titleHeader.click();
    await titleHeader.click();

    await expect(section).toHaveScreenshot("table-sorted-desc-desktop.png", {
      animations: "disabled",
      caret: "hide",
    });
  });

  test("active filters", async ({ page, baseURL, browserName, isMobile }) => {
    test.skip(browserName !== "chromium");
    test.skip(isMobile);

    await openTable(page, baseURL);

    const section = page.getByTestId("table-visual-interactive");
    const titleFilter = section.getByPlaceholder("Search keyword..").first();

    await titleFilter.fill("Alpha Watch");
    await titleFilter.press("Enter");

    await expect(section).toHaveScreenshot("table-filtered-desktop.png", {
      animations: "disabled",
      caret: "hide",
    });
  });

  test("expanded row", async ({ page, baseURL, browserName, isMobile }) => {
    test.skip(browserName !== "chromium");
    test.skip(isMobile);

    await openTable(page, baseURL);

    const section = page.getByTestId("table-visual-interactive");

    await section.locator("tbody tr [role='button']").first().click();
    await expect(section.getByTestId("expanded-row-1")).toBeVisible();

    await expect(section).toHaveScreenshot("table-expanded-desktop.png", {
      animations: "disabled",
      caret: "hide",
    });
  });

  test("selected rows", async ({ page, baseURL, browserName, isMobile }) => {
    test.skip(browserName !== "chromium");
    test.skip(isMobile);

    await openTable(page, baseURL);

    const section = page.getByTestId("table-visual-interactive");
    const alphaRow = section.locator("tbody tr", { hasText: "Alpha Watch" });
    const cipherRow = section.locator("tbody tr", { hasText: "Cipher Sweep" });

    await alphaRow.locator("input[type='checkbox']").check();
    await cipherRow.locator("input[type='checkbox']").check();
    await expect(alphaRow.locator("input[type='checkbox']")).toBeChecked();
    await expect(cipherRow.locator("input[type='checkbox']")).toBeChecked();
    await page.mouse.move(0, 0);
    await page.evaluate(() => {
      if (document.activeElement instanceof HTMLElement)
        document.activeElement.blur();
    });

    await expect(section).toHaveScreenshot("table-selected-desktop.png", {
      animations: "disabled",
      caret: "hide",
      maxDiffPixels: 700,
    });
  });

  test("disabled row styling", async ({
    page,
    baseURL,
    browserName,
    isMobile,
  }) => {
    test.skip(browserName !== "chromium");
    test.skip(isMobile);

    await openTable(page, baseURL);

    await expect(page.getByTestId("table-visual-disabled")).toHaveScreenshot(
      "table-disabled-row-desktop.png",
      { animations: "disabled", caret: "hide" },
    );
  });

  test("empty state", async ({ page, baseURL, browserName, isMobile }) => {
    test.skip(browserName !== "chromium");
    test.skip(isMobile);

    await openTable(page, baseURL);

    await expect(page.getByTestId("table-visual-empty")).toHaveScreenshot(
      "table-empty-state-desktop.png",
      { animations: "disabled", caret: "hide" },
    );
  });

  test("paginator ellipsis", async ({
    page,
    baseURL,
    browserName,
    isMobile,
  }) => {
    test.skip(browserName !== "chromium");
    test.skip(isMobile);

    await openTable(page, baseURL);

    await expect(
      page.getByTestId("table-visual-interactive").locator(".table-paginator"),
    ).toHaveScreenshot("table-paginator-ellipsis-desktop.png", {
      animations: "disabled",
      caret: "hide",
    });
  });
});

test.describe("table mobile visual state", () => {
  test("default state on mobile", async ({
    page,
    baseURL,
    browserName,
    isMobile,
  }) => {
    test.skip(browserName !== "chromium");
    test.skip(!isMobile);

    await openTable(page, baseURL);

    await expect(page.getByTestId("table-visual-interactive")).toHaveScreenshot(
      "table-default-mobile.png",
      { animations: "disabled", caret: "hide" },
    );
  });
});
