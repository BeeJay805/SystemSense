import { test, expect, _electron as electron } from "@playwright/test";
import path from "node:path";
import fs from "node:fs/promises";
import os from "node:os";

test("packaged investigator: intake, progress, cancel, reopen and durable recovery", async () => {
  const data = await fs.mkdtemp(
    path.join(os.tmpdir(), "systemsense-desktop-test-"),
  );
  const env: Record<string, string> = Object.fromEntries(
    Object.entries({
      ...process.env,
      SYSTEMSENSE_DESKTOP_TEST_DATA: data,
    }).filter(
      (entry): entry is [string, string] => typeof entry[1] === "string",
    ),
  );
  delete env.ELECTRON_RUN_AS_NODE;
  const desktop = await electron.launch({
    args: ["."],
    cwd: process.cwd(),
    env,
  });
  let id: string;
  try {
    const page = await desktop.firstWindow();
    await expect
      .poll(
        async () =>
          page.evaluate(
            async () =>
              window.systemsense
                ?.capabilities()
                .then((value) => value.read_only)
                .catch(() => false) ?? false,
          ),
        { timeout: 30000 },
      )
      .toBe(true);

    await page
      .getByLabel("Describe the problem")
      .fill("Chrome says pages cannot be reached");
    await expect(
      page.getByText(/Open-page browser access is unavailable/),
    ).toBeVisible();
    await page.screenshot({ path: "artifacts/intake-limits-1100.png" });
    await page.getByLabel("Describe the problem").press("Enter");
    await expect(page.getByRole("dialog")).toHaveCount(0);
    await expect(
      page.getByRole("button", { name: "Stop investigation" }),
    ).toBeVisible({ timeout: 30000 });
    await expect(
      page.getByRole("button", { name: "Investigate", exact: true }),
    ).toHaveCount(0);
    id = await page.evaluate(() => localStorage.getItem("selectedCase")!);
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.screenshot({
      path: "artifacts/progress-1100.png",
      fullPage: true,
    });
    await page.getByRole("button", { name: "Stop investigation" }).click();
    await expect(
      page.getByRole("heading", { name: "Investigation stopped", exact: true }),
    ).toBeVisible({ timeout: 30000 });
    await page
      .getByRole("button", { name: "Show details", exact: true })
      .click();
    await page.getByRole("tab", { name: "Coverage", exact: true }).click();
    await expect(
      page.getByText(
        "Not collected, denied and unavailable checks are not healthy checks.",
      ),
    ).toBeVisible();
    await page.screenshot({ path: "artifacts/cancelled-1100.png" });
    await desktop.evaluate(({ BrowserWindow }) =>
      BrowserWindow.getAllWindows()[0].setSize(640, 720),
    );
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.screenshot({
      path: "artifacts/cancelled-640.png",
      fullPage: true,
    });
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= window.innerWidth,
      ),
    ).toBe(true);
    await page.getByRole("button", { name: /History/ }).click();
    await page
      .getByRole("button", { name: /Chrome says pages cannot be reached/ })
      .click();
    expect(
      await page.evaluate(() => localStorage.getItem("selectedCase")),
    ).toBe(id);
  } finally {
    await desktop.close();
  }
  const reopened = await electron.launch({
    args: ["."],
    cwd: process.cwd(),
    env,
  });
  try {
    const page = await reopened.firstWindow();
    await expect(
      page.getByRole("heading", { name: "Investigation stopped", exact: true }),
    ).toBeVisible({ timeout: 30000 });
    const cases = await page.evaluate(() => window.systemsense!.listCases());
    expect(cases.cases).toHaveLength(1);
    expect(cases.cases[0].case_id).toBe(id!);
    await page.getByRole("button", { name: "Continue investigation" }).click();
    await expect(
      page.getByRole("button", { name: "Stop investigation" }),
    ).toBeVisible();
    await page.getByRole("button", { name: "Stop investigation" }).click();
    await expect(
      page.getByRole("heading", { name: "Investigation stopped", exact: true }),
    ).toBeVisible();
  } finally {
    await reopened.close();
  }
});

test("real observations complete while minimized; explicit quit saves an active case", async () => {
  const data = await fs.mkdtemp(
    path.join(os.tmpdir(), "systemsense-desktop-live-"),
  );
  const env: Record<string, string> = Object.fromEntries(
    Object.entries({
      ...process.env,
      SYSTEMSENSE_DESKTOP_TEST_DATA: data,
    }).filter(
      (entry): entry is [string, string] =>
        typeof entry[1] === "string" && entry[0] !== "ELECTRON_RUN_AS_NODE",
    ),
  );
  const desktop = await electron.launch({
    args: ["."],
    cwd: process.cwd(),
    env,
  });
  try {
    const page = await desktop.firstWindow();
    await expect
      .poll(
        async () =>
          page.evaluate(
            async () =>
              window.systemsense
                ?.capabilities()
                .then((value) => value.read_only)
                .catch(() => false) ?? false,
          ),
        { timeout: 30000 },
      )
      .toBe(true);

    await page.getByLabel("Describe the problem").fill("CPU and memory usage");
    await page
      .getByRole("button", { name: "Investigate", exact: true })
      .click();
    await desktop.evaluate(({ BrowserWindow }) =>
      BrowserWindow.getAllWindows()[0].minimize(),
    );
    await expect
      .poll(
        async () =>
          page.evaluate(async () => {
            const cases = await window.systemsense!.listCases();
            return cases.cases[0]?.status;
          }),
        { timeout: 70000 },
      )
      .toBe("complete");
    await desktop.evaluate(({ BrowserWindow }) =>
      BrowserWindow.getAllWindows()[0].restore(),
    );
    const result = await page.evaluate(async () =>
      window.systemsense!.getCase(
        (await window.systemsense!.listCases()).cases[0].case_id!,
      ),
    );
    expect(
      result.evidence?.some(
        (item) =>
          item.status === "observed" &&
          item.facts &&
          Object.keys(item.facts).length > 0,
      ),
    ).toBe(true);
    await expect(
      page.getByRole("heading", { name: "No supported answer yet" }),
    ).toBeVisible();
    const exported = path.join(data, "export.json");
    await desktop.evaluate(({ dialog }, filePath) => {
      dialog.showSaveDialog = async () => ({ canceled: false, filePath });
    }, exported);
    await page
      .getByRole("button", { name: "Show details", exact: true })
      .click();
    await page
      .getByRole("button", { name: "Export evidence", exact: true })
      .click();
    await expect(
      page.getByText("Evidence report saved.", { exact: true }),
    ).toBeVisible();
    const report = JSON.parse(await fs.readFile(exported, "utf8"));
    expect(JSON.stringify(report)).toContain(result.case_id!);
    expect(JSON.stringify(report)).toContain("core.system");
    await page.screenshot({
      path: "artifacts/real-complete.png",
      fullPage: true,
    });
    await page
      .getByRole("button", { name: "New investigation", exact: true })
      .click();
    await page
      .getByLabel("Describe the problem")
      .fill("Chrome cannot load a page");
    await page
      .getByRole("button", { name: "Investigate", exact: true })
      .click();
    await expect(
      page.getByRole("button", { name: "Stop investigation" }),
    ).toBeVisible();
    await page.getByRole("button", { name: "History", exact: true }).click();
    await page
      .getByRole("button", { name: "Quit SystemSense", exact: true })
      .click();
    await desktop.waitForEvent("close", { timeout: 30000 });
  } finally {
    await desktop.close().catch(() => {});
  }
  const reopened = await electron.launch({
    args: ["."],
    cwd: process.cwd(),
    env,
  });
  try {
    const page = await reopened.firstWindow();
    await expect
      .poll(
        async () =>
          page.evaluate(
            async () =>
              window.systemsense
                ?.capabilities()
                .then((value) => value.read_only)
                .catch(() => false) ?? false,
          ),
        { timeout: 30000 },
      )
      .toBe(true);
    const saved = await page.evaluate(() => window.systemsense!.listCases());
    expect(saved.cases).toHaveLength(2);
    expect(["cancelled", "interrupted", "complete"]).toContain(
      saved.cases[0].status,
    );
    expect(
      (await page.evaluate(() => window.systemsense!.capabilities()))
        .active_case_id,
    ).toBeNull();
  } finally {
    await reopened.close();
  }
});
