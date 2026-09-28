import { describe, expect, it } from "vitest";
import { createRequire } from "node:module";
import fs from "node:fs";
import path from "node:path";
const require = createRequire(import.meta.url);
describe("Dyad identity preserves existing history", () => {
  it("keeps the existing package and app identities while wiring native icons", () => {
    const config = JSON.parse(fs.readFileSync("package.json", "utf8"));
    expect(config.name).toBe("systemsense-desktop");
    expect(config.build.appId).toBe("org.systemsense.desktop");
    expect(config.build.productName).toBe("Dyad");
    expect(config.build.win.icon).toBe("assets/dyad.ico");
    expect(config.build.win.signExecutable).toBe(false);
    expect(config.build.files).toContain("assets/**");
  });
  it("changes the visible app name without redirecting default or explicit data paths", () => {
    const { applyIdentity } = require("../electron/identity.cjs");
    for (const override of [false, true]) {
      const paths = {
        appData: "C:/test/Roaming",
        userData: "C:/explicit-data",
      };
      let name = "systemsense-desktop";
      let appId = "";
      applyIdentity({
        getPath: (key: keyof typeof paths) => paths[key],
        setPath: (key: keyof typeof paths, value: string) => {
          paths[key] = value;
        },
        setName: (value: string) => {
          name = value;
        },
        setAppUserModelId: (value: string) => {
          appId = value;
        },
        commandLine: { hasSwitch: () => override },
      });
      expect(name).toBe("Dyad");
      expect(appId).toBe("org.systemsense.desktop");
      expect(paths.userData).toBe(
        override
          ? "C:/explicit-data"
          : path.join(paths.appData, "systemsense-desktop"),
      );
    }
  });
});
