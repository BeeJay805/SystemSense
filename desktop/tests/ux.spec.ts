import {
  test,
  expect,
  _electron as electron,
  type ElectronApplication,
  type Page,
} from "@playwright/test";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import type { Case, Capabilities } from "../src/types";
declare global {
  interface Window {
    fixtureControl: {
      setCase(value: Case): Promise<void>;
      setCapabilities(value: Capabilities): Promise<void>;
      startCount(): Promise<number>;
    };
  }
}
async function launch(state = "landing") {
  const data = await fs.mkdtemp(path.join(os.tmpdir(), "systemsense-ux-"));
  const env = Object.fromEntries(
    Object.entries(process.env).filter(
      (entry): entry is [string, string] =>
        typeof entry[1] === "string" && entry[0] !== "ELECTRON_RUN_AS_NODE",
    ),
  );
  const app = await electron.launch({
    args: ["tests/fixture-main.cjs", `--user-data-dir=${data}`],
    env: { ...env, SYSTEMSENSE_FIXTURE: state },
    cwd: process.cwd(),
  });
  const page = await app.firstWindow();
  await expect(
    page.getByRole("button", { name: "Settings", exact: true }),
  ).toBeVisible();
  return { app, page };
}
async function capture(app: ElectronApplication, page: Page, name: string) {
  await fs.mkdir("artifacts", { recursive: true });
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
    if (name === "dyad-landing") {
      expect(
        await page.evaluate(
          () => document.documentElement.scrollHeight <= window.innerHeight,
        ),
      ).toBe(true);
    }
    if (name === "dyad-settings") {
      expect(
        await page
          .getByRole("dialog")
          .evaluate(
            (el) =>
              el.scrollHeight <= el.clientHeight &&
              el.scrollWidth <= el.clientWidth,
          ),
      ).toBe(true);
    }
    await page.evaluate(
      () =>
        new Promise<void>((resolve) =>
          requestAnimationFrame(() => requestAnimationFrame(() => resolve())),
        ),
    );
    const png = await app.evaluate(async ({ BrowserWindow }) =>
      (await BrowserWindow.getAllWindows()[0].capturePage())
        .toPNG()
        .toString("base64"),
    );
    await fs.writeFile(
      `artifacts/ux-${name}-${zoom * 100}.png`,
      Buffer.from(png, "base64"),
    );
  }
}

test("direct submit respects composition, newlines, and capability revocation", async () => {
  const { app, page } = await launch();
  try {
    const input = page.getByLabel("Describe the problem");
    await input.fill("Chrome cannot load pages");
    await expect(
      page.getByText(/Open-page browser access is unavailable/),
    ).toBeVisible();
    await expect(
      page.getByRole("button", { name: "Investigate", exact: true }),
    ).toBeEnabled();
    await input.dispatchEvent("keydown", {
      key: "Enter",
      code: "Enter",
      isComposing: true,
      bubbles: true,
    });
    expect(await page.evaluate(() => window.fixtureControl.startCount())).toBe(
      0,
    );
    await input.press("Shift+Enter");
    await expect(input).toHaveValue("Chrome cannot load pages\n");
    await capture(app, page, "landing");
    // Revoke capability immediately before submit, without waiting for polling.
    await page.evaluate(() =>
      window.fixtureControl.setCapabilities({ read_only: false }),
    );
    await input.press("Enter");
    await expect(
      page.getByText(
        "No usable read-only check catalog was reported. Reconnect before starting.",
      ),
    ).toBeVisible();
    expect(await page.evaluate(() => window.fixtureControl.startCount())).toBe(
      0,
    );
    await page.evaluate(() =>
      window.fixtureControl.setCapabilities({ read_only: true }),
    );
    await expect(
      page.getByRole("button", { name: "Investigate", exact: true }),
    ).toBeEnabled();
    await input.press("Enter");
    await expect(
      page.getByRole("heading", {
        name: "Investigating your problem",
        exact: true,
      }),
    ).toBeVisible();
    await expect(page.getByRole("dialog")).toHaveCount(0);
    expect(await page.evaluate(() => window.fixtureControl.startCount())).toBe(
      1,
    );
  } finally {
    await app.close();
  }
});

test("Dyad has a blank settings shell that fits normal and 150 percent", async () => {
  const { app, page } = await launch();
  try {
    await expect(page).toHaveTitle("Dyad");
    await expect(page.locator(".wordmark")).toHaveText("Dyad");
    await expect(
      page.getByText(
        "Read-only checks. Evidence stays on this computer. No automatic repairs.",
      ),
    ).toHaveCount(0);
    await expect(page.getByText(/Enter to investigate/)).toHaveCount(0);
    await page.emulateMedia({ reducedMotion: "reduce" });
    await expect(page.locator(".intake-example")).toHaveText(
      "My game keeps freezing…",
    );
    await capture(app, page, "dyad-landing");
    await page.getByRole("button", { name: "Settings", exact: true }).click();
    await expect(page.getByRole("dialog")).toBeVisible();
    await expect(page.getByRole("dialog").getByRole("button")).toHaveCount(1);
    await expect(page.getByRole("dialog").getByRole("combobox")).toHaveCount(0);
    await expect(page.locator(".settings-content")).toHaveText("");
    await capture(app, page, "dyad-settings");
    expect(
      await page
        .getByRole("dialog")
        .evaluate((el) => el.scrollHeight <= el.clientHeight),
    ).toBe(true);
    await page.keyboard.press("Shift+Tab");
    expect(
      await page.evaluate(() =>
        document.querySelector("dialog")?.contains(document.activeElement),
      ),
    ).toBe(true);
    await page.keyboard.press("Escape");
    await expect(page.getByRole("dialog")).toHaveCount(0);
    await expect(
      page.getByRole("button", { name: "Settings", exact: true }),
    ).toBeFocused();
    expect(await page.evaluate(() => window.fixtureControl.startCount())).toBe(
      0,
    );
  } finally {
    await app.close();
  }
});

test("examples type gradually, dwell, and pause for focus or user text", async () => {
  const { app, page } = await launch();
  try {
    await page.clock.install();
    await page.emulateMedia({ reducedMotion: "no-preference" });
    await page.reload();
    const input = page.getByLabel("Describe the problem");
    const example = page.locator(".intake-example");
    await expect(example).toHaveText("");
    await page.clock.runFor(1400);
    await expect(example).toHaveText("M");
    await page.clock.runFor(90);
    await expect(example).toHaveText("My");
    await page.clock.runFor(2500);
    await expect(example).toHaveText("My game keeps freezing…");
    await page.clock.runFor(12000);
    await expect(example).toHaveText("My game keeps freezing…");
    await input.focus();
    await page.clock.runFor(20000);
    await expect(example).toHaveText("My game keeps freezing…");
    await input.fill("Unfinished description");
    await page.getByRole("button", { name: "Settings", exact: true }).focus();
    await page.clock.runFor(20000);
    await expect(example).toBeHidden();
    await expect(input).toHaveValue("Unfinished description");
    await expect(example).toHaveAttribute("aria-hidden", "true");
    await expect(input).toHaveAccessibleName("Describe the problem");
    await input.fill("");
    await page.getByRole("button", { name: "Settings", exact: true }).focus();
    await page.clock.runFor(18000);
    await expect(example).toHaveText("Chrome can’t open webpages…");
    await page.emulateMedia({ reducedMotion: "reduce" });
    await expect(example).toHaveText("My game keeps freezing…");
    await page.clock.runFor(40000);
    await expect(example).toHaveText("My game keeps freezing…");
    expect(
      await page
        .locator(".input-shell")
        .evaluate((el) => getComputedStyle(el, "::before").animationName),
    ).toBe("none");
  } finally {
    await app.close();
  }
});

test("new actual activity animates once and history stays truthful", async () => {
  const { app, page } = await launch("running");
  try {
    await expect(page.locator(".activity-event")).toHaveCount(4);
    await expect(page.locator(".event-arrival")).toHaveCount(0);
    await page.evaluate(() => {
      (window as unknown as { animationEvents: string[] }).animationEvents = [];
      document.addEventListener("animationstart", (event) => {
        if ((event as AnimationEvent).animationName === "event-arrival")
          (
            window as unknown as { animationEvents: string[] }
          ).animationEvents.push(
            (event.target as HTMLElement).dataset.eventId!,
          );
      });
    });
    const current = await page.evaluate(async () =>
      window.systemsense!.getCase(
        (await window.systemsense!.listCases()).cases[0].case_id!,
      ),
    );
    const updated: Case = {
      ...current,
      status: "complete",
      outcome: "insufficient_observability",
      created_at: "2026-09-27T00:00:00Z",
      updated_at: "2026-09-27T00:00:12Z",
      pending_probe_ids: [],
      timeline: [
        ...current.timeline!,
        {
          state_version: 2,
          event: "stopped",
          occurred_at: "2026-09-27T00:00:12Z",
          detail:
            "Development fixture: collection ended with insufficient evidence.",
        },
      ],
      evidence: [
        ...current.evidence!,
        {
          evidence_id: "new-denied",
          probe_id: "application.snapshot",
          status: "denied",
          captured_at: "2026-09-27T00:00:11Z",
          summary:
            "Development fixture: access denied. No process data collected.",
        },
      ],
    };
    await page.evaluate(
      (value) => window.fixtureControl.setCase(value),
      updated,
    );
    await expect(
      page.getByRole("heading", {
        name: "No supported answer yet",
        exact: true,
      }),
    ).toBeVisible();
    await expect
      .poll(() =>
        page.evaluate(
          () =>
            (window as unknown as { animationEvents: string[] }).animationEvents
              .length,
        ),
      )
      .toBe(2);
    await expect(page.locator(".event-arrival")).toHaveCount(0);
    await capture(app, page, "activity");
    await page.getByRole("button", { name: "History" }).click();
    await expect(
      page.getByText("Finished · insufficient evidence", { exact: true }),
    ).toBeVisible();
    await expect(
      page
        .getByRole("dialog")
        .getByText("12s elapsed · includes pauses", { exact: true }),
    ).toBeVisible();
    await capture(app, page, "history");
    await page
      .getByRole("button", { name: /Chrome can’t open webpages/ })
      .click();
    await expect(page.locator(".event-arrival")).toHaveCount(0);
    expect(
      await page.evaluate(
        () =>
          (window as unknown as { animationEvents: string[] }).animationEvents
            .length,
      ),
    ).toBe(2);
    expect(await page.evaluate(() => window.fixtureControl.startCount())).toBe(
      0,
    );
  } finally {
    await app.close();
  }
});
