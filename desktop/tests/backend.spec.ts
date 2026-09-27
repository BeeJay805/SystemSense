import { test, expect } from "@playwright/test";
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { createRequire } from "node:module";
import { once } from "node:events";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
const require = createRequire(import.meta.url);
const { LocalClient } = require("../electron/bridge.cjs");
test("bundled HTTP boundary retains cookie, CSRF and origin checks; EOF exits", async () => {
  const dir = await fs.mkdtemp(
    path.join(os.tmpdir(), "systemsense-desktop-auth-"),
  );
  const child = spawn(
    path.resolve("backend/dist/investigator/investigator.exe"),
    ["--database", path.join(dir, "case.db")],
    { windowsHide: true, stdio: ["pipe", "pipe", "pipe"] },
  );
  const exited = once(child, "exit");
  const lines = createInterface({ input: child.stdout });
  try {
    const [line] = await once(lines, "line");
    const { port } = JSON.parse(line);
    const origin = `http://127.0.0.1:${port}`;
    const session = await fetch(origin);
    const document = await session.text();
    const cookie = session.headers.get("set-cookie")!.split(";")[0];
    const csrf = document.match(
      /name="csrf-token" content="([A-Za-z0-9_-]+)"/,
    )![1];
    const mutation = {
      method: "POST",
      body: JSON.stringify({
        objective: "CPU usage",
        budget_ms: 60000,
        max_rounds: 4,
      }),
    };
    expect(
      (
        await fetch(origin + "/api/cases", {
          ...mutation,
          headers: { Origin: origin, "Content-Type": "application/json" },
        })
      ).status,
    ).toBe(403);
    expect(
      (
        await fetch(origin + "/api/cases", {
          ...mutation,
          headers: {
            Origin: "https://untrusted.example",
            Cookie: cookie,
            "X-CSRF-Token": csrf,
            "Content-Type": "application/json",
          },
        })
      ).status,
    ).toBe(403);
    expect(
      (
        await fetch(origin + "/api/cases", {
          ...mutation,
          headers: {
            Origin: origin,
            Cookie: cookie,
            "X-CSRF-Token": "wrong",
            "Content-Type": "application/json",
          },
        })
      ).status,
    ).toBe(403);
    const client = new LocalClient(port);
    expect((await client.request("capabilities")).read_only).toBe(true);
    expect((await client.request("listCases")).cases).toHaveLength(0);
  } finally {
    child.stdin.end();
    await exited;
    lines.close();
  }
  expect(child.exitCode).toBe(0);
});
