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
  const model = process.env.DYAD_MODEL_COPY_E2E === "1";
  test.setTimeout(model ? 180000 : 90000);
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "dyad-copy-desktop-"));
  const source = path.join(root, "source-入力.json");
  const destination = path.join(root, "copy-入力.json");
  const original = Buffer.from('\ufeff{"PRIVATE_COPY_CANARY":true}', "utf8");
  await fs.writeFile(source, original);
  if (model) {
    await fs.mkdir(path.join(root, "data"));
    await fs.writeFile(
      path.join(root, "data", "investigation-mode.json"),
      JSON.stringify({ mode: "laya-sol" }),
    );
  }
  const env = Object.fromEntries(
    Object.entries({
      ...process.env,
      SYSTEMSENSE_DESKTOP_TEST_DATA: path.join(root, "data"),
    }).filter(
      (entry): entry is [string, string] =>
        typeof entry[1] === "string" && entry[0] !== "ELECTRON_RUN_AS_NODE",
    ),
  );
  const packaged = process.env.DYAD_PACKAGED_E2E === "1";
  const desktop = await electron.launch({
    ...(packaged
      ? {
          executablePath: path.resolve(
            process.env.DYAD_INSTALLED_EXE ?? "release/win-unpacked/Dyad.exe",
          ),
        }
      : {}),
    args: packaged ? [`--user-data-dir=${path.join(root, "data")}`] : ["."],
    cwd: process.cwd(),
    env,
  });
  const child = desktop.process();
  try {
    const page = await desktop.firstWindow();
    await expect
      .poll(
        () =>
          page.evaluate(
            (model) =>
              window
                .systemsense!.capabilities()
                .then(
                  (c) =>
                    c.local_json_task?.enabled &&
                    (!model || c.inference?.start_allowed),
                )
                .catch(() => false),
            model,
          ),
        { timeout: model ? 60000 : 30000 },
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
    await expect(copy).toBeEnabled({ timeout: model ? 105000 : 60000 });
    if (model) {
      const diagnosis = await page.evaluate(async () =>
        window.systemsense!.getCase(localStorage.getItem("selectedCase")!),
      );
      expect(diagnosis.status).toBe("complete");
      expect(diagnosis.stop_reason).toMatch(
        /captured-file parser task was checked/,
      );
      expect(
        diagnosis.evidence?.some(
          (item) => item.probe_id === "file.json_syntax",
        ),
      ).toBe(true);
      for (const provider of [
        "laya-local-decision",
        "codex-subscription-reasoning",
      ]) {
        expect(
          diagnosis.provider_calls?.some(
            (call) => call.provider_id === provider && !call.degraded,
          ),
        ).toBe(true);
      }
      await expect(
        page.getByText(/Recorded decisions:.*Laya.*Sol/),
      ).toBeVisible();
      await fs.writeFile(
        path.join(root, "diagnosis-before-copy.json"),
        JSON.stringify(diagnosis, null, 2),
      );
    }
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
    await fs.writeFile(
      path.join(root, "case-after-copy.json"),
      JSON.stringify(report, null, 2),
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
      child.once("exit", () => resolve()),
    );
    await page.evaluate(() => window.systemsense!.quit());
    await exited;
  } finally {
    if (child.exitCode === null) await desktop.close();
    // Delete only known test-owned fixtures; the case database remains as evidence.
    await fs.unlink(source);
    await fs.unlink(destination).catch(() => {});
  }
});
