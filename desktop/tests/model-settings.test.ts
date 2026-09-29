import { describe, expect, test } from "vitest";
import { createRequire } from "node:module";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

const require = createRequire(import.meta.url);
const { readMode, saveMode } = require("../electron/settings.cjs");

describe("desktop model selection", () => {
  test("keeps an explicit model choice across restarts", async () => {
    const root = await fs.mkdtemp(
      path.join(os.tmpdir(), "dyad-model-setting-"),
    );
    try {
      const file = path.join(root, "mode.json");
      expect(await readMode(file)).toBe("deterministic");
      await saveMode(file, "laya-sol");
      expect(await readMode(file)).toBe("laya-sol");
      await saveMode(file, "deterministic");
      expect(await readMode(file)).toBe("deterministic");
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  test("invalid saved state never silently selects deterministic checks", async () => {
    const root = await fs.mkdtemp(
      path.join(os.tmpdir(), "dyad-model-setting-"),
    );
    try {
      const file = path.join(root, "mode.json");
      await fs.writeFile(file, '{"mode":"laya-sol","extra":true}');
      await expect(readMode(file)).rejects.toThrow(
        "Invalid saved investigation mode",
      );
      await expect(saveMode(file, "unknown")).rejects.toThrow(
        "Invalid investigation mode",
      );
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });
});
