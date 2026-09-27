import { test, expect, _electron as electron } from "@playwright/test";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
for (const state of ["landing", "running", "empty"]) {
  test(`minimal visual journey: ${state}`, async () => {
    const data = await fs.mkdtemp(path.join(os.tmpdir(), "systemsense-d017-"));
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
      if (state === "landing") {
        await expect(
          page.getByRole("heading", {
            name: "What’s not working?",
            exact: true,
          }),
        ).toBeVisible();
        const overflow = await page.evaluate(() => {
          const banner = document.querySelector("body > aside") as HTMLElement;
          const before =
            document.documentElement.scrollHeight - window.innerHeight;
          const bannerHeight = banner.getBoundingClientRect().height;
          banner.style.display = "none";
          const withoutBanner =
            document.documentElement.scrollHeight - window.innerHeight;
          banner.style.display = "";
          return { before, bannerHeight, withoutBanner };
        });
        await fs.writeFile(
          "artifacts/d017-landing-overflow.json",
          JSON.stringify(overflow, null, 2),
        );
        expect(overflow.withoutBanner).toBe(0);
        expect(overflow.before).toBe(0);
        await expect(page.locator(".assurance")).toHaveCount(0);
        await expect(page.locator("main .card")).toHaveCount(0);
        await page
          .getByLabel("Describe the problem")
          .fill("My game keeps freezing…");
        await expect(
          page.getByRole("button", { name: "Investigate", exact: true }),
        ).toBeEnabled();
      } else {
        await expect(
          page.getByRole("heading", {
            name:
              state === "running"
                ? "Investigating your problem"
                : "No supported answer yet",
            exact: true,
          }),
        ).toBeVisible();
        await expect(page.getByLabel("Describe the problem")).toHaveCount(0);
        await expect(page.locator(".working")).toHaveCount(
          state === "running" ? 1 : 0,
        );
      }
      await expect(
        page.getByText(
          /Nothing changes without|Investigation doesn’t change|Evidence first\./,
        ),
      ).toHaveCount(0);
      for (const zoom of [1, 1.5]) {
        await app.evaluate(
          ({ BrowserWindow }, factor) =>
            BrowserWindow.getAllWindows()[0].webContents.setZoomFactor(factor),
          zoom,
        );
        await expect
          .poll(() => page.evaluate(() => window.devicePixelRatio))
          .toBe(zoom);
        await expect
          .poll(() =>
            page.evaluate(
              () => document.documentElement.scrollWidth <= window.innerWidth,
            ),
          )
          .toBe(true);
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
          `artifacts/d017-${state}-${zoom * 100}.png`,
          Buffer.from(png, "base64"),
        );
      }
      if (state !== "landing") {
        await page.locator(".card-footer").scrollIntoViewIfNeeded();
        const png = await app.evaluate(async ({ BrowserWindow }) =>
          (await BrowserWindow.getAllWindows()[0].capturePage())
            .toPNG()
            .toString("base64"),
        );
        await fs.writeFile(
          `artifacts/d017-${state}-150-controls.png`,
          Buffer.from(png, "base64"),
        );
      }
      if (state === "landing") {
        await page.getByLabel("Describe the problem").focus();
        await page.keyboard.press("Enter");
        await expect(page.getByRole("dialog")).toHaveCount(0);
        await expect(
          page.getByRole("heading", {
            name: "Investigating your problem",
            exact: true,
          }),
        ).toBeVisible();
        await expect(page.getByLabel("Describe the problem")).toHaveCount(0);
        await page.getByRole("button", { name: "Stop investigation" }).click();
        await expect(
          page.getByRole("heading", {
            name: "Investigation stopped",
            exact: true,
          }),
        ).toBeVisible();
        await page
          .getByRole("button", { name: "Continue investigation" })
          .click();
        await expect(page.locator(".working")).toHaveCount(1);
        await page.getByRole("button", { name: "Stop investigation" }).click();
        await page
          .getByRole("button", { name: "New investigation", exact: true })
          .click();
        await expect(page.getByLabel("Describe the problem")).toHaveValue("");
        await page.getByRole("button", { name: "History" }).click();
        await page
          .getByRole("button", { name: /My game keeps freezing/ })
          .click();
        await expect(
          page.getByRole("heading", {
            name: "Investigation stopped",
            exact: true,
          }),
        ).toBeVisible();
        await page.getByRole("button", { name: "Show details" }).click();
        await page.getByRole("tab", { name: "Observations" }).focus();
        await page.keyboard.press("ArrowRight");
        await expect(page.getByRole("tab", { name: "Coverage" })).toBeFocused();
        await expect(
          page.getByRole("tab", { name: "Coverage" }),
        ).toHaveAttribute("aria-selected", "true");
        await page.getByRole("button", { name: "Export evidence" }).click();
        await expect(page.getByRole("status")).toHaveText(
          "Evidence report saved.",
        );
      }
      if (state === "landing") {
        await app.evaluate(({ BrowserWindow }) =>
          BrowserWindow.getAllWindows()[0].setSize(640, 480),
        );
        await page
          .getByRole("button", { name: "New investigation", exact: true })
          .click();
        await page
          .getByLabel("Describe the problem")
          .fill("Small window check");
        await page
          .getByRole("button", { name: "Investigate", exact: true })
          .scrollIntoViewIfNeeded();
        await expect(
          page.getByRole("button", { name: "Investigate", exact: true }),
        ).toBeInViewport();
        expect(
          await page.evaluate(
            () => document.documentElement.scrollWidth <= window.innerWidth,
          ),
        ).toBe(true);
        expect(
          await page.evaluate(
            () => document.documentElement.scrollHeight > window.innerHeight,
          ),
        ).toBe(true);
      }
      if (state === "running") {
        await page.getByRole("button", { name: "Stop investigation" }).click();
        await expect(
          page.getByRole("heading", {
            name: "Investigation stopped",
            exact: true,
          }),
        ).toBeVisible();
        await expect(page.locator(".working")).toHaveCount(0);
      }
    } finally {
      await app.close();
    }
  });
}
