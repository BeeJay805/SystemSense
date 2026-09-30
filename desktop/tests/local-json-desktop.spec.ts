import { test, expect, _electron as electron } from "@playwright/test";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { Case } from "../src/types";

for (const outcome of ["accepted", "rejected"] as const) {
  test(`native JSON selection records ${outcome} evidence without file content or paths`, async () => {
    test.skip(
      process.env.DYAD_LOCAL_JSON_E2E !== "1",
      "Requires the rebuilt backend with native-pipe JSON task support",
    );
    const directory = await fs.mkdtemp(
      path.join(os.tmpdir(), "dyad-json-desktop-"),
    );
    const userData = path.join(directory, "app-data");
    const selectedPath = path.join(directory, "private-selected-config.json");
    const sentinel = "PRIVATE_JSON_CONTENT_MUST_NOT_LEAVE_CAPTURE";
    await fs.writeFile(
      selectedPath,
      outcome === "accepted"
        ? JSON.stringify({ credential: sentinel, enabled: true })
        : `{\n  "credential": "${sentinel}",\n  "enabled": }`,
      "utf8",
    );
    const env = Object.fromEntries(
      Object.entries({
        ...process.env,
        SYSTEMSENSE_DESKTOP_TEST_DATA: userData,
      }).filter(
        (entry): entry is [string, string] =>
          typeof entry[1] === "string" && entry[0] !== "ELECTRON_RUN_AS_NODE",
      ),
    );
    const packaged = process.env.DYAD_PACKAGED_E2E === "1";
    const installedExecutable = path.resolve(
      process.env.DYAD_INSTALLED_EXE ?? "release/win-unpacked/Dyad.exe",
    );
    const desktop = await electron.launch({
      ...(packaged ? { executablePath: installedExecutable } : {}),
      args: packaged ? [`--user-data-dir=${userData}`] : ["."],
      cwd: process.cwd(),
      env,
    });
    let report: Case;
    let id: string;
    try {
      const page = await desktop.firstWindow();
      await expect
        .poll(
          () =>
            page.evaluate(() =>
              window
                .systemsense!.capabilities()
                .then((caps) => caps.local_json_task?.enabled)
                .catch(() => false),
            ),
          { timeout: 30000 },
        )
        .toBe(true);
      // Stub only the OS dialog selection; renderer IPC, pipe and backend are real.
      await desktop.evaluate(({ dialog }) => {
        dialog.showOpenDialog = async () => ({ canceled: true, filePaths: [] });
      });
      const check = page.getByRole("button", { name: "Check a JSON file" });
      await check.click();
      await expect(check).toBeEnabled();
      expect(
        (await page.evaluate(() => window.systemsense!.listCases())).cases,
      ).toHaveLength(0);
      await desktop.evaluate(({ dialog }, selectedPath) => {
        dialog.showOpenDialog = async () => ({
          canceled: false,
          filePaths: [selectedPath],
        });
      }, selectedPath);
      await check.click();
      await expect
        .poll(() => page.evaluate(() => localStorage.getItem("selectedCase")))
        .toMatch(/^case_[0-9a-f]{32}$/);
      id = await page.evaluate(() => localStorage.getItem("selectedCase")!);
      await expect
        .poll(
          () =>
            page.evaluate(
              (id) =>
                window.systemsense!.getCase(id).then((value) => value.status),
              id,
            ),
          { timeout: 60000 },
        )
        .toBe("complete");
      report = await page.evaluate((id) => window.systemsense!.getCase(id), id);
      const task = report.evidence?.find(
        (item) => item.probe_id === "task.local_json",
      );
      expect(task?.facts?.outcome).toBe(outcome);
      expect(task?.facts?.action).toBe("Parse strict UTF-8 JSON");
      expect(task?.facts?.target_handle).toMatch(/^selected_file_[0-9a-f]+$/);
      expect(report.evidence?.map((item) => item.probe_id)).toEqual(
        expect.arrayContaining([
          "task.local_json",
          "file.utf8",
          "file.json_syntax",
        ]),
      );
      const syntax = report.evidence?.find(
        (item) => item.probe_id === "file.json_syntax",
      );
      const diagnostic = syntax?.facts?.selected_file_check as
        Record<string, unknown> | undefined;
      expect(diagnostic).toBeDefined();
      if (outcome === "rejected") {
        expect(diagnostic?.line).toBeGreaterThan(0);
        expect(diagnostic?.column).toBeGreaterThan(0);
      }
      const serialized = JSON.stringify(report);
      for (const privateValue of [
        selectedPath,
        path.basename(selectedPath),
        sentinel,
      ]) {
        expect(serialized.includes(privateValue)).toBe(false);
        expect(
          (await page.locator("body").innerText()).includes(privateValue),
        ).toBe(false);
      }
      expect(
        report.provider_calls?.some((call) =>
          ["laya-local-decision", "codex-subscription-reasoning"].includes(
            call.provider_id,
          ),
        ),
      ).not.toBe(true);
      await expect(
        page.getByRole("heading", {
          name:
            outcome === "accepted"
              ? "This JSON file parsed"
              : "The JSON file could not be parsed",
          exact: true,
        }),
      ).toBeVisible();
      // Removing only this test-owned file proves History reads persisted observations.
      await fs.unlink(selectedPath);
      await page.getByRole("button", { name: "History", exact: true }).click();
      await page
        .getByRole("dialog")
        .getByRole("button", { name: new RegExp(report.objective!) })
        .click();
      expect(
        (await page.evaluate((id) => window.systemsense!.getCase(id), id))
          .evidence,
      ).toEqual(report.evidence);
    } finally {
      await desktop.close();
    }
    const reopened = await electron.launch({
      ...(packaged ? { executablePath: installedExecutable } : {}),
      args: packaged ? [`--user-data-dir=${userData}`] : ["."],
      cwd: process.cwd(),
      env,
    });
    try {
      if (packaged) {
        expect(
          path
            .resolve(String(reopened.process().spawnfile ?? ""))
            .toLowerCase(),
        ).toBe(installedExecutable.toLowerCase());
      }
      const page = await reopened.firstWindow();
      await expect(
        page.getByRole("heading", {
          name:
            outcome === "accepted"
              ? "This JSON file parsed"
              : "The JSON file could not be parsed",
          exact: true,
        }),
      ).toBeVisible({ timeout: 30000 });
      const reopenedCases = await page.evaluate(() =>
        window.systemsense!.listCases(),
      );
      expect(reopenedCases.cases.some((item) => item.case_id === id)).toBe(
        true,
      );
      const reopenedCase = await page.evaluate(
        (caseId) => window.systemsense!.getCase(caseId),
        id!,
      );
      expect(reopenedCase.case_id).toBe(id);
      expect(reopenedCase.evidence).toEqual(report!.evidence);
    } finally {
      await reopened.close();
    }
  });
}
