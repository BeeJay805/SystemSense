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
    executablePath: path.resolve(
      process.env.DYAD_INSTALLED_EXE ?? "release/win-unpacked/Dyad.exe",
    ),
    args: [`--user-data-dir=${data}`],
    env,
  });
  try {
    expect(await app.evaluate(({ app }) => app.isPackaged)).toBe(true);
    expect(await app.evaluate(({ app }) => app.getPath("userData"))).toBe(data);
    const page = await app.firstWindow();
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

test("bundled investigator can read and cite its own process inventory", async () => {
  test.skip(
    process.env.SYSTEMSENSE_TEST_PACKAGE !== "1",
    "Run after building the Windows package.",
  );
  const data = await fs.mkdtemp(
    path.join(os.tmpdir(), "systemsense-packaged-process-"),
  );
  const env: Record<string, string> = Object.fromEntries(
    Object.entries(process.env).filter(
      (entry): entry is [string, string] =>
        typeof entry[1] === "string" && entry[0] !== "ELECTRON_RUN_AS_NODE",
    ),
  );
  const app = await electron.launch({
    executablePath: path.resolve("release/win-unpacked/Dyad.exe"),
    args: [`--user-data-dir=${data}`],
    env,
  });
  try {
    const page = await app.firstWindow();
    await expect
      .poll(
        async () =>
          page.evaluate(async () => {
            try {
              return (
                (await window.systemsense?.capabilities())?.read_only ?? false
              );
            } catch {
              return false;
            }
          }),
        { timeout: 30000 },
      )
      .toBe(true);
    await page
      .getByLabel("Describe the problem")
      .fill("Please check whether Dyad.exe is running right now.");
    await page
      .getByRole("button", { name: "Investigate", exact: true })
      .click();
    await expect
      .poll(
        async () =>
          page.evaluate(
            async () =>
              (await window.systemsense?.listCases())?.cases[0]?.status,
          ),
        { timeout: 45000 },
      )
      .toBe("complete");
    const result = await page.evaluate(async () => {
      const api = window.systemsense;
      if (!api) throw new Error("Desktop API unavailable");
      const id = (await api.listCases()).cases[0]?.case_id;
      if (!id) throw new Error("Saved case unavailable");
      return api.getCase(id);
    });
    const snapshot = result.evidence?.find(
      (item) => item.probe_id === "application.snapshot",
    );
    const facts = snapshot?.facts ?? {};
    const searches = facts.target_process_search as
      { status?: string }[] | undefined;
    const assessment = result.assessment as
      | {
          claim_kind?: string;
          root_cause_proven?: boolean;
          evidence_ids?: string[];
        }
      | undefined;
    expect(facts.collection_status).toBe("available");
    expect(searches?.[0]?.status).toBe("matching_process_observed");
    expect(result.outcome).toBe("supported_explanation");
    expect(assessment?.claim_kind).toBe("named_process_state");
    expect(assessment?.root_cause_proven).toBe(false);
    expect(assessment?.evidence_ids).toEqual([snapshot?.evidence_id]);
  } finally {
    await app.close();
  }
});
