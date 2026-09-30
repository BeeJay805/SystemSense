import {
  test,
  expect,
  _electron as electron,
  type ElectronApplication,
} from "@playwright/test";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { randomBytes, createHash } from "node:crypto";
import { createServer } from "node:http";
import { once } from "node:events";

test("selected Laya–Sol mode completes and saves an actual desktop investigation", async () => {
  test.skip(
    process.env.DYAD_MODEL_E2E !== "1",
    "Requires the pinned local Laya runtime and signed-in Codex subscription",
  );
  test.setTimeout(180000);
  const nonce = randomBytes(16).toString("hex");
  let mode: "healthy" | "http_503" = "healthy";
  const server = createServer((request, response) => {
    if (request.url !== `/health/${nonce}`) {
      response.writeHead(404).end();
      return;
    }
    if (mode === "http_503") {
      response.writeHead(503).end("temporarily unavailable");
      return;
    }
    response.writeHead(200, { "Content-Type": "text/plain" });
    response.end(`${nonce}\n`);
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string" || address.port < 49152)
    throw Error("A high-port local health fixture is required");
  const objective = `My local status page http://127.0.0.1:${address.port}/health/${nonce} is not working`;
  const data = await fs.mkdtemp(path.join(os.tmpdir(), "dyad-model-desktop-"));
  await fs.writeFile(
    path.join(data, "investigation-mode.json"),
    JSON.stringify({ mode: "laya-sol" }),
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
  const packaged = process.env.DYAD_PACKAGED_E2E === "1";
  const executable = packaged
    ? path.resolve(
        process.env.DYAD_INSTALLED_EXE ?? "release/win-unpacked/Dyad.exe",
      )
    : undefined;
  const receipt: Record<string, unknown> = {
    started_at: new Date().toISOString(),
    user_data: data,
    packaged,
    executable,
    local_app_data: process.env.LOCALAPPDATA,
    task_url: `http://127.0.0.1:${address.port}/health/${nonce}`,
    completed_checks: [],
  };
  const record = async () => {
    await fs.writeFile(
      path.join(data, "evaluator-receipt.json"),
      JSON.stringify(receipt, null, 2),
    );
  };
  const hashFile = async (file: string) =>
    createHash("sha256")
      .update(await fs.readFile(file))
      .digest("hex");
  const observeTask = async () => {
    const response = await fetch(
      `http://127.0.0.1:${address.port}/health/${nonce}`,
      {
        signal: AbortSignal.timeout(5000),
      },
    );
    return {
      at: new Date().toISOString(),
      status: response.status,
      nonce_match: (await response.text()).trim() === nonce,
    };
  };
  let desktop: ElectronApplication | undefined;
  try {
    if (executable) {
      const resources = path.join(path.dirname(executable), "resources");
      receipt.package_sha256 = {
        executable: await hashFile(executable),
        app_asar: await hashFile(path.join(resources, "app.asar")),
        backend: await hashFile(
          path.join(resources, "investigator", "investigator.exe"),
        ),
      };
    }
    receipt.healthy_before = await observeTask();
    expect(receipt.healthy_before).toMatchObject({
      status: 200,
      nonce_match: true,
    });
    await record();
    console.log(
      `Model desktop evidence: ${path.join(data, "evaluator-receipt.json")}`,
    );
    desktop = await electron.launch({
      ...(executable ? { executablePath: executable } : {}),
      args: packaged ? [`--user-data-dir=${data}`] : ["."],
      cwd: process.cwd(),
      env,
    });
    receipt.desktop_pid = desktop.process().pid;
    await record();
    const page = await desktop.firstWindow();
    await expect
      .poll(
        async () => {
          const readiness = await page.evaluate(async () => {
            try {
              return await window.systemsense!.capabilities();
            } catch {
              return null;
            }
          });
          receipt.readiness = readiness;
          await record();
          return readiness?.inference?.start_allowed ?? false;
        },
        { timeout: 60000 },
      )
      .toBe(true);
    receipt.readiness = await page.evaluate(() =>
      window.systemsense!.capabilities(),
    );
    await record();
    await expect(
      page.getByText("Laya + GPT-6 Sol investigation is selected.", {
        exact: false,
      }),
    ).toBeVisible();
    await page.getByLabel("Describe the problem").fill(objective);
    await page.getByRole("button", { name: "Investigate" }).click();
    await expect(
      page.getByRole("button", { name: "Stop investigation" }),
    ).toBeVisible();
    await expect
      .poll(
        async () =>
          page.evaluate(async () => {
            const cases = await window.systemsense!.listCases();
            return cases.cases[0]?.status;
          }),
        { timeout: 105000 },
      )
      .toBe("complete");
    const cases = await page.evaluate(() => window.systemsense!.listCases());
    expect(cases.cases).toHaveLength(1);
    const result = await page.evaluate(
      (id) => window.systemsense!.getCase(id),
      cases.cases[0].case_id!,
    );
    expect(
      result.provider_calls?.some(
        (call) => call.provider_id === "laya-local-decision" && !call.degraded,
      ),
    ).toBe(true);
    expect(
      result.provider_calls?.some(
        (call) =>
          call.provider_id === "codex-subscription-reasoning" && !call.degraded,
      ),
    ).toBe(true);
    expect(result.summary).toBeTruthy();
    receipt.healthy_case_id = result.case_id;
    await fs.writeFile(
      path.join(data, "healthy-product-result.json"),
      JSON.stringify(result, null, 2),
    );
    await record();
    expect(result.summary).toMatch(/exact .*GET.*HTTP 200/i);
    expect(result.summary).not.toMatch(/status page request.*unobserved/i);
    expect(result.outcome).toBe("awaiting_recurrence");
    expect(result.stop_reason).toMatch(/reported failure did not recur/i);
    expect(
      result.evidence?.some(
        (item) =>
          item.probe_id === "task.loopback_http" &&
          item.facts?.outcome === "http_200_nonce_match",
      ),
    ).toBe(true);
    await expect(
      page.getByText(result.summary!, { exact: true }),
    ).toBeVisible();
    await expect(page.getByText(/Provider log:.*Laya.*Sol/)).toBeVisible();
    await page.getByRole("button", { name: "History" }).click();
    const saved = page.getByRole("button", {
      name: /My local status page <redacted-url>/,
    });
    await expect(saved).toBeVisible();
    await saved.click();
    await expect(
      page.getByText(result.summary!, { exact: true }),
    ).toBeVisible();
    mode = "http_503";
    receipt.failure_before = await observeTask();
    await record();
    expect(receipt.failure_before).toMatchObject({
      status: 503,
      nonce_match: false,
    });
    await page.getByRole("button", { name: "New investigation" }).click();
    await page.getByLabel("Describe the problem").fill(objective);
    await page.getByRole("button", { name: "Investigate" }).click();
    await expect
      .poll(
        async () => {
          const all = await page.evaluate(() =>
            window.systemsense!.listCases(),
          );
          return all.cases.length === 2 ? all.cases[0]?.status : undefined;
        },
        { timeout: 105000 },
      )
      .toBe("complete");
    const faultCases = await page.evaluate(() =>
      window.systemsense!.listCases(),
    );
    expect(faultCases.cases).toHaveLength(2);
    const fault = await page.evaluate(
      (id) => window.systemsense!.getCase(id),
      faultCases.cases[0].case_id!,
    );
    receipt.fault_case_id = fault.case_id;
    await fs.writeFile(
      path.join(data, "fault-product-result.json"),
      JSON.stringify(fault, null, 2),
    );
    await record();
    expect(
      fault.evidence?.some(
        (item) =>
          item.probe_id === "task.loopback_http" &&
          item.facts?.outcome === "http_503",
      ),
    ).toBe(true);
    expect(fault.summary).toMatch(/exact .*GET.*HTTP 503/i);
    expect(fault.stop_reason).toMatch(
      /used in an applied deep review; handler-level cause remains unverified/i,
    );
    expect(
      fault.provider_calls?.some(
        (call) => call.provider_id === "laya-local-decision" && !call.degraded,
      ),
    ).toBe(true);
    expect(
      fault.provider_calls?.some(
        (call) =>
          call.provider_id === "codex-subscription-reasoning" && !call.degraded,
      ),
    ).toBe(true);
    await expect(page.getByText(fault.summary!, { exact: true })).toBeVisible();
    await page.getByRole("button", { name: "New investigation" }).click();
    await page.getByLabel("Describe the problem").fill(objective);
    await page.getByRole("button", { name: "Investigate" }).click();
    await page.getByRole("button", { name: "Stop investigation" }).click();
    await expect(
      page.getByRole("heading", { name: "Investigation stopped", exact: true }),
    ).toBeVisible({ timeout: 30000 });
    const cancelledCases = await page.evaluate(() =>
      window.systemsense!.listCases(),
    );
    expect(cancelledCases.cases).toHaveLength(3);
    expect(cancelledCases.cases[0].status).toBe("cancelled");
    receipt.cancelled_case_id = cancelledCases.cases[0].case_id;
    receipt.completed_checks = [
      "healthy_task",
      "http_503_task",
      "history_reopen",
      "cancelled_case",
    ];
  } catch (error) {
    receipt.failure = error instanceof Error ? error.message : String(error);
    throw error;
  } finally {
    mode = "healthy";
    try {
      receipt.restored = await observeTask();
      expect(receipt.restored).toMatchObject({
        status: 200,
        nonce_match: true,
      });
    } finally {
      try {
        if (desktop) {
          const desktopProcess = desktop.process();
          await desktop.close();
          receipt.desktop_exit_code = desktopProcess.exitCode;
          receipt.desktop_exit_signal = desktopProcess.signalCode;
          receipt.desktop_exit_confirmed =
            desktopProcess.exitCode !== null ||
            desktopProcess.signalCode !== null;
          expect(receipt.desktop_exit_confirmed).toBe(true);
          receipt.database_sha256 = await hashFile(path.join(data, "cases.db"));
        }
      } finally {
        try {
          await new Promise<void>((resolve, reject) =>
            server.close((error) => (error ? reject(error) : resolve())),
          );
        } finally {
          receipt.server_close_confirmed = !server.listening;
          receipt.finished_at = new Date().toISOString();
          await record();
        }
      }
    }
  }
});
