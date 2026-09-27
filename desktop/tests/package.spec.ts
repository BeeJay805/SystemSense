import { test, expect, _electron as electron } from "@playwright/test";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
test("distributable executable launches its bundled investigator", async () => {
  test.skip(
    process.env.SYSTEMSENSE_TEST_PACKAGE !== "1",
    "Run after building the Windows package.",
  );
  const data = await fs.mkdtemp(
    path.join(os.tmpdir(), "systemsense-packaged-"),
  );
  const env: Record<string, string> = Object.fromEntries(
    Object.entries(process.env).filter(
      (entry): entry is [string, string] =>
        typeof entry[1] === "string" && entry[0] !== "ELECTRON_RUN_AS_NODE",
    ),
  );
  const app = await electron.launch({
    executablePath: path.resolve("release/win-unpacked/SystemSense.exe"),
    args: [`--user-data-dir=${data}`],
    env,
  });
  try {
    expect(await app.evaluate(({ app }) => app.isPackaged)).toBe(true);
    expect(await app.evaluate(({ app }) => app.getPath("userData"))).toBe(data);
    const page = await app.firstWindow();
    await expect(page.getByText("On this computer · Read-only")).toBeVisible({
      timeout: 30000,
    });
    await page
      .getByRole("button", { name: "Get started", exact: true })
      .click();
    await page.getByLabel("Describe the problem").fill("CPU and memory usage");
    await page
      .getByRole("button", { name: "Investigate", exact: true })
      .click();
    await page
      .getByRole("button", { name: "Start investigation", exact: true })
      .click();
    await expect(
      page.getByRole("button", { name: "Stop investigation" }),
    ).toBeVisible();
    await page.getByRole("button", { name: "Stop investigation" }).click();
    await expect(
      page.getByRole("heading", { name: "Investigation stopped", exact: true }),
    ).toBeVisible({ timeout: 30000 });
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.screenshot({
      path: "artifacts/packaged-app.png",
      fullPage: true,
    });
  } finally {
    await app.close();
  }
});
