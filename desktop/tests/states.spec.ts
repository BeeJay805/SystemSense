import { test, expect, _electron as electron } from "@playwright/test";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
const outcomes = {
  empty: "No supported answer yet",
  denied: "No supported answer yet",
  supported: "An observed finding",
  uncertain: "No supported answer yet",
  failed: "Investigation could not finish",
  waiting: "Choose the app to continue",
};
for (const [state, title] of Object.entries(outcomes)) {
  test(`development fixture: ${state}`, async () => {
    const data = await fs.mkdtemp(
      path.join(os.tmpdir(), "systemsense-ui-fixture-"),
    );
    const env: Record<string, string> = Object.fromEntries(
      Object.entries(process.env).filter(
        (entry): entry is [string, string] =>
          typeof entry[1] === "string" && entry[0] !== "ELECTRON_RUN_AS_NODE",
      ),
    );
    env.SYSTEMSENSE_FIXTURE = state;
    const app = await electron.launch({
      args: ["tests/fixture-main.cjs", `--user-data-dir=${data}`],
      env,
      cwd: process.cwd(),
    });
    try {
      const page = await app.firstWindow();
      if (await page.getByRole("button", { name: "Do this later" }).isVisible())
        await page.getByRole("button", { name: "Do this later" }).click();
      await expect(
        page.getByRole("heading", { name: title, exact: true }),
      ).toBeVisible();
      await expect(
        page.getByText(/DEVELOPMENT FIXTURE · Simulated/),
      ).toBeVisible();
      if (state === "denied")
        await expect(
          page.getByText("Some evidence is limited or unavailable"),
        ).toBeVisible();
      if (state === "waiting") {
        await page
          .getByRole("button", { name: /Development fixture app/ })
          .click();
        await expect(
          page.getByRole("heading", { name: "No supported answer yet" }),
        ).toBeVisible();
      }
      await page.evaluate(() => window.scrollTo(0, 0));
      await page.screenshot({
        path: `artifacts/fixture-${state}.png`,
        fullPage: true,
      });
      await page.getByRole("button", { name: /History/ }).click();
      await page.keyboard.press("Shift+Tab");
      expect(
        await page.evaluate(() =>
          document.querySelector("dialog")?.contains(document.activeElement),
        ),
      ).toBe(true);
      await page.keyboard.press("Escape");
      await expect(page.getByRole("dialog")).not.toBeVisible();
      if (state === "empty") {
        const initialWidth = await page.evaluate(() => window.innerWidth);
        await app.evaluate(({ BrowserWindow }) =>
          BrowserWindow.getAllWindows()[0].webContents.setZoomFactor(1.5),
        );
        await expect
          .poll(() => page.evaluate(() => window.innerWidth))
          .toBeLessThan(initialWidth * 0.7);
        await expect
          .poll(() =>
            page.evaluate(
              () => document.documentElement.scrollWidth <= window.innerWidth,
            ),
          )
          .toBe(true);
        const metrics = await page.evaluate(() => ({
          viewport: window.innerWidth,
          content: document.documentElement.scrollWidth,
          dpr: window.devicePixelRatio,
        }));
        await fs.writeFile(
          "artifacts/zoom-metrics.json",
          JSON.stringify(metrics, null, 2),
        );
        await page.evaluate(
          () =>
            new Promise<void>((resolve) =>
              requestAnimationFrame(() =>
                requestAnimationFrame(() => resolve()),
              ),
            ),
        );
        const png = await app.evaluate(async ({ BrowserWindow }) =>
          (await BrowserWindow.getAllWindows()[0].capturePage())
            .toPNG()
            .toString("base64"),
        );
        await fs.writeFile(
          "artifacts/fixture-150-percent-native.png",
          Buffer.from(png, "base64"),
        );
      }
    } finally {
      await app.close();
    }
  });
}
test("development fixture: disconnected never enables an investigation", async () => {
  const env: Record<string, string> = Object.fromEntries(
    Object.entries(process.env).filter(
      (entry): entry is [string, string] =>
        typeof entry[1] === "string" && entry[0] !== "ELECTRON_RUN_AS_NODE",
    ),
  );
  env.SYSTEMSENSE_FIXTURE = "disconnected";
  const app = await electron.launch({
    args: ["tests/fixture-main.cjs"],
    env,
    cwd: process.cwd(),
  });
  try {
    const page = await app.firstWindow();
    await expect(page.getByRole("button", { name: "Reconnect" })).toBeVisible({
      timeout: 20000,
    });
    if (await page.getByRole("button", { name: "Do this later" }).isVisible())
      await page.getByRole("button", { name: "Do this later" }).click();
    await page.getByLabel("Describe the problem").fill("Example problem");
    await expect(
      page.getByRole("button", { name: "Investigate", exact: true }),
    ).toBeDisabled();
    await page.screenshot({
      path: "artifacts/fixture-disconnected.png",
      fullPage: true,
    });
  } finally {
    await app.close();
  }
});
