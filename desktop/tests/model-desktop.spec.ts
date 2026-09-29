import { test, expect, _electron as electron } from "@playwright/test";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { randomBytes } from "node:crypto";
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
  const desktop = await electron.launch({
    ...(packaged
      ? {
          executablePath: path.resolve(
            process.env.DYAD_INSTALLED_EXE ?? "release/win-unpacked/Dyad.exe",
          ),
        }
      : {}),
    args: packaged ? [`--user-data-dir=${data}`] : ["."],
    cwd: process.cwd(),
    env,
  });
  try {
    const page = await desktop.firstWindow();
    await expect
      .poll(
        async () =>
          page.evaluate(async () => {
            try {
              return (await window.systemsense!.capabilities()).inference
                ?.start_allowed;
            } catch {
              return false;
            }
          }),
        { timeout: 60000 },
      )
      .toBe(true);
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
    await expect(
      page.getByText(/Recorded decisions:.*Laya.*Sol/),
    ).toBeVisible();
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
    const url = `http://127.0.0.1:${address.port}/health/${nonce}`;
    expect((await fetch(url)).status).toBe(503);
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
    mode = "healthy";
    expect((await fetch(url)).status).toBe(200);
  } finally {
    mode = "healthy";
    await desktop.close();
    expect(
      (await fetch(`http://127.0.0.1:${address.port}/health/${nonce}`)).status,
    ).toBe(200);
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});
