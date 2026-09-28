import { test, expect, _electron as electron } from "@playwright/test";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { execFileSync } from "node:child_process";
const environment = () =>
  Object.fromEntries(
    Object.entries(process.env).filter(
      (entry): entry is [string, string] =>
        typeof entry[1] === "string" && entry[0] !== "ELECTRON_RUN_AS_NODE",
    ),
  );

test("native branding preserves the previous default storage identity", async () => {
  const data = await fs.mkdtemp(path.join(os.tmpdir(), "dyad-identity-"));
  const app = await electron.launch({
    args: ["tests/fixture-main.cjs"],
    cwd: process.cwd(),
    env: {
      ...environment(),
      DYAD_FIXTURE_APP_DATA: data,
      SYSTEMSENSE_FIXTURE: "landing",
    },
  });
  try {
    const actual = await app.evaluate(({ app }) => ({
      name: app.getName(),
      data: app.getPath("userData"),
    }));
    expect(actual).toEqual({
      name: "Dyad",
      data: path.join(data, "systemsense-desktop"),
    });
    await expect(await app.firstWindow()).toHaveTitle("Dyad");
  } finally {
    await app.close();
  }
});

test("packaged Dyad metadata, shell icon and storage identity without collection", async () => {
  test.skip(
    process.env.DYAD_TEST_PACKAGE !== "1",
    "Requires the built Dyad package and exclusive packaging slot.",
  );
  const data = await fs.mkdtemp(
    path.join(os.tmpdir(), "dyad-package-branding-"),
  );
  const app = await electron.launch({
    executablePath: path.resolve("release/win-unpacked/Dyad.exe"),
    args: [`--user-data-dir=${data}`],
    cwd: process.cwd(),
    env: environment(),
  });
  try {
    const actual = await app.evaluate(({ app, BrowserWindow }) => {
      const { createRequire } = process.getBuiltinModule("module");
      const load = createRequire(app.getAppPath() + "/package.json");
      const identity = load("./electron/identity.cjs");
      return {
        name: app.getName(),
        executable: app.getPath("exe"),
        data: app.getPath("userData"),
        appData: app.getPath("appData"),
        productionData: identity.legacyDataDirectory(app.getPath("appData")),
        packaged: app.isPackaged,
        title: BrowserWindow.getAllWindows()[0].getTitle(),
        windowHandle: BrowserWindow.getAllWindows()[0]
          .getNativeWindowHandle()
          .readBigUInt64LE()
          .toString(),
      };
    });
    expect(actual.name).toBe("Dyad");
    expect(actual.title).toBe("Dyad");
    expect(actual.packaged).toBe(true);
    expect(actual.data).toBe(data);
    expect(actual.productionData).toBe(
      path.join(actual.appData, "systemsense-desktop"),
    );
    const page = await app.firstWindow();
    await expect(page).toHaveTitle("Dyad");
    await expect
      .poll(() =>
        page.evaluate(() =>
          window
            .systemsense!.listCases()
            .then((value) => value.cases.length)
            .catch(() => -1),
        ),
      )
      .toBe(0);
    await fs.mkdir("artifacts", { recursive: true });
    const windowIcon = JSON.parse(
      execFileSync(
        "powershell.exe",
        [
          "-NoProfile",
          "-NonInteractive",
          "-File",
          "scripts/capture-window-icon.ps1",
          "-WindowHandle",
          actual.windowHandle,
          "-OutputPath",
          path.resolve("artifacts/dyad-window-icon.png"),
        ],
        { encoding: "utf8", windowsHide: true },
      ),
    );
    await fs.writeFile(
      "artifacts/dyad-native-identity.json",
      JSON.stringify({ ...actual, windowIcon, caseCount: 0 }, null, 2),
    );
    await page.screenshot({ path: "artifacts/dyad-packaged-idle.png" });
  } finally {
    await app.close();
  }
});
