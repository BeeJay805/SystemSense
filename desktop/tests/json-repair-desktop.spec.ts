import { test, expect, _electron as electron } from "@playwright/test";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { BaseWindow, MessageBoxOptions } from "electron";

test("native approval creates and verifies only a corrected captured JSON copy", async () => {
  test.skip(
    process.env.DYAD_LOCAL_JSON_E2E !== "1",
    "Requires rebuilt native backend",
  );
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "dyad-copy-desktop-"));
  const source = path.join(root, "source-入力.json");
  const destination = path.join(root, "copy-入力.json");
  const original = Buffer.from('\ufeff{"PRIVATE_COPY_CANARY":true}', "utf8");
  await fs.writeFile(source, original);
  const env = Object.fromEntries(
    Object.entries({
      ...process.env,
      SYSTEMSENSE_DESKTOP_TEST_DATA: path.join(root, "data"),
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
        () =>
          page.evaluate(() =>
            window
              .systemsense!.capabilities()
              .then((c) => c.local_json_task?.enabled)
              .catch(() => false),
          ),
        { timeout: 30000 },
      )
      .toBe(true);
    await desktop.evaluate(({ dialog }, source) => {
      dialog.showOpenDialog = async () => ({
        canceled: false,
        filePaths: [source],
      });
    }, source);
    await page.getByRole("button", { name: "Check a JSON file" }).click();
    const copy = page.getByRole("button", {
      name: "Save corrected JSON copy…",
    });
    await expect(copy).toBeVisible({ timeout: 60000 });
    await desktop.evaluate(({ dialog }, destination) => {
      dialog.showSaveDialog = async () => ({
        canceled: false,
        filePath: destination,
      });
      dialog.showMessageBox = async () => ({
        response: 0,
        checkboxChecked: false,
      });
    }, destination);
    await copy.click();
    await expect(
      page.getByText("Copy cancelled.", { exact: true }),
    ).toBeVisible();
    await expect(fs.stat(destination)).rejects.toThrow();
    expect(await fs.readFile(source)).toEqual(original);
    await desktop.evaluate(({ dialog }) => {
      dialog.showMessageBox = async (
        _window: BaseWindow | MessageBoxOptions,
        options?: MessageBoxOptions,
      ) => {
        if (
          options?.defaultId !== 0 ||
          !options.detail?.includes("keep every remaining byte unchanged")
        )
          throw Error("Missing exact approval");
        return { response: 1, checkboxChecked: false };
      };
    });
    await copy.click();
    await expect(
      page.getByText("Corrected copy created and independently verified.", {
        exact: false,
      }),
    ).toBeVisible({ timeout: 15000 });
    expect(await fs.readFile(destination)).toEqual(original.subarray(3));
    expect(await fs.readFile(source)).toEqual(original);
    const report = await page.evaluate(async () =>
      window.systemsense!.getCase(localStorage.getItem("selectedCase")!),
    );
    expect(report.json_copy?.receipts[0].status).toBe("verified");
    expect(report.json_copy?.receipts[0].evidence_ids.length).toBeGreaterThan(
      0,
    );
    expect(JSON.stringify(report)).not.toContain("PRIVATE_COPY_CANARY");
    expect(JSON.stringify(report)).not.toContain(destination);
    // An existing destination cannot be overwritten, even after a new approval.
    await fs.writeFile(destination, "newer content");
    await copy.click();
    await expect(
      page.getByText("No copy was created.", { exact: false }),
    ).toBeVisible();
    expect(await fs.readFile(destination, "utf8")).toBe("newer content");
    const exited = new Promise<void>((resolve) =>
      desktop.process().once("exit", () => resolve()),
    );
    await page.evaluate(() => window.systemsense!.quit());
    await exited;
  } finally {
    if (desktop.process().exitCode === null) await desktop.close();
    // Delete only known test-owned fixtures; the case database remains as evidence.
    await fs.unlink(source);
    await fs.unlink(destination).catch(() => {});
  }
});
