import { test, expect, _electron as electron } from "@playwright/test";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import type { BaseWindow, MessageBoxOptions } from "electron";

test("native approved local setup cancels cleanly and installs on retry", async () => {
  test.skip(
    process.env.DYAD_LAYA_SETUP_E2E !== "1",
    "Downloads the pinned local runtime into a fresh owned directory",
  );
  test.setTimeout(1_200_000);
  const root = await fs.mkdtemp(
    path.join(
      process.env.DYAD_SETUP_E2E_ROOT ?? os.tmpdir(),
      "dyad-local-setup-",
    ),
  );
  const localData = path.join(root, "local");
  const data = path.join(root, "desktop");
  await fs.mkdir(localData);
  const env: Record<string, string> = Object.fromEntries(
    Object.entries({
      ...process.env,
      LOCALAPPDATA: localData,
      SYSTEMSENSE_DESKTOP_TEST_DATA: data,
    }).filter(
      (entry): entry is [string, string] =>
        typeof entry[1] === "string" && entry[0] !== "ELECTRON_RUN_AS_NODE",
    ),
  );
  const executablePath = path.resolve(
    process.env.DYAD_INSTALLED_EXE ?? "release/win-unpacked/Dyad.exe",
  );
  const packagedRoot = path.dirname(executablePath);
  const hashes: Record<string, string> = {};
  for (const relative of [
    "Dyad.exe",
    "resources/app.asar",
    "resources/investigator/investigator.exe",
    "resources/laya-setup/install-laya-runtime.ps1",
    "resources/laya-setup/PROVENANCE.json",
  ]) {
    hashes[relative] = createHash("sha256")
      .update(await fs.readFile(path.join(packagedRoot, relative)))
      .digest("hex");
  }
  await fs.writeFile(
    path.join(root, "package-provenance.json"),
    JSON.stringify({ executablePath, hashes }, null, 2),
  );
  const desktop = await electron.launch({
    executablePath,
    args: [`--user-data-dir=${data}`],
    cwd: process.cwd(),
    env,
  });
  const observations: object[] = [];
  const started = Date.now();
  try {
    const page = await desktop.firstWindow();
    await page.getByRole("button", { name: "Settings", exact: true }).click();
    const install = page.getByRole("button", {
      name: "Install local Laya",
      exact: true,
    });
    await expect(install).toBeEnabled({ timeout: 30_000 });
    // Only the native dialog response is controlled. Main, pipe, executor,
    // downloads, model validation and rollback remain the production path.
    await desktop.evaluate(({ dialog }) => {
      const audit = globalThis as typeof globalThis & {
        setupApprovalCalls: number;
      };
      audit.setupApprovalCalls = 0;
      dialog.showMessageBox = async (
        _window: BaseWindow | MessageBoxOptions,
        options?: MessageBoxOptions,
      ) => {
        if (options?.defaultId !== 0 || options.cancelId !== 0)
          throw Error("Setup approval must default to Cancel");
        audit.setupApprovalCalls++;
        return { response: 0, checkboxChecked: false };
      };
    });
    await install.click();
    await expect
      .poll(() =>
        desktop.evaluate(
          () =>
            (globalThis as typeof globalThis & { setupApprovalCalls: number })
              .setupApprovalCalls,
        ),
      )
      .toBe(1);
    await expect(install).toBeEnabled();
    const declined = await page.evaluate(() =>
      window.systemsense!.layaSetupStatus!(),
    );
    expect(declined.state).toBe("ready_to_install");
    observations.push({ phase: "declined", snapshot: declined });
    await expect(
      fs.stat(path.join(localData, "SystemSense", "runtimes", "laya-0.3.5")),
    ).rejects.toThrow();
    await desktop.evaluate(({ dialog }) => {
      dialog.showMessageBox = async () => {
        (globalThis as typeof globalThis & { setupApprovalCalls: number })
          .setupApprovalCalls++;
        return { response: 1, checkboxChecked: false };
      };
    });
    await install.click();
    await expect
      .poll(() =>
        desktop.evaluate(
          () =>
            (globalThis as typeof globalThis & { setupApprovalCalls: number })
              .setupApprovalCalls,
        ),
      )
      .toBe(2);
    const cancel = page.getByRole("button", {
      name: "Cancel setup",
      exact: true,
    });
    await expect(cancel).toBeEnabled({ timeout: 30_000 });
    const blocked = await page.evaluate(async () => {
      const api = window.systemsense!;
      const attempts = [
        () =>
          api.selectTarget({
            caseId: "case_not_dispatched",
            candidateId: "not_dispatched",
          }),
        () => api.saveJsonCopy!("case_not_dispatched"),
      ];
      return Promise.all(
        attempts.map(async (run) => {
          try {
            await run();
            return "unexpected success";
          } catch (error) {
            return String(error);
          }
        }),
      );
    });
    for (const message of blocked)
      expect(message).toContain("Wait for local setup");
    await cancel.click();
    await expect
      .poll(
        () =>
          page.evaluate(
            async () => (await window.systemsense!.layaSetupStatus!()).state,
          ),
        { timeout: 60_000 },
      )
      .toBe("cancelled");
    const cancelled = await page.evaluate(() =>
      window.systemsense!.layaSetupStatus!(),
    );
    expect(cancelled.can_install).toBe(true);
    observations.push({ phase: "cancelled", snapshot: cancelled });
    await expect(install).toBeEnabled();
    await install.click();
    await expect
      .poll(() =>
        desktop.evaluate(
          () =>
            (globalThis as typeof globalThis & { setupApprovalCalls: number })
              .setupApprovalCalls,
        ),
      )
      .toBe(3);
    await expect(cancel).toBeEnabled({ timeout: 30_000 });
    const installDeadline = Date.now() + 1_080_000;
    while (true) {
      const snapshot = await page.evaluate(() =>
        window.systemsense!.layaSetupStatus!(),
      );
      observations.push({ elapsed_ms: Date.now() - started, snapshot });
      await fs.writeFile(
        path.join(root, "setup-observations.json"),
        JSON.stringify(observations, null, 2),
      );
      if (
        ["failed", "cleanup_pending", "unavailable", "cancelled"].includes(
          snapshot.state,
        )
      )
        throw Error(`Local setup failed: ${JSON.stringify(snapshot)}`);
      if (snapshot.state === "installed") break;
      if (Date.now() >= installDeadline)
        throw Error("Local setup exceeded its deadline");
      await new Promise((resolve) => setTimeout(resolve, 5000));
    }
    observations.push({ phase: "installed", elapsed_ms: Date.now() - started });
    await expect(
      page.getByText(/The local runtime is installed/),
    ).toBeVisible();
    await test
      .info()
      .attach("setup-root", { body: root, contentType: "text/plain" });
  } finally {
    await fs.writeFile(
      path.join(root, "setup-observations.json"),
      JSON.stringify(observations, null, 2),
    );
    console.log(`Local setup artifacts: ${root}`);
    await desktop.close();
  }
});
