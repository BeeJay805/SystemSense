import { createRequire } from "node:module";
import { describe, it, expect } from "vitest";
const require = createRequire(import.meta.url);
const { routeFor } = require("../electron/bridge.cjs");
describe("native request boundary", () => {
  it("rejects arbitrary URLs, paths and case handles", () => {
    expect(() => routeFor("fetch", "https://example.com")).toThrow();
    expect(() =>
      routeFor("startJsonFileCheck", "C:\\private\\config.json"),
    ).toThrow();
    expect(() => routeFor("getCase", "../../private")).toThrow();
    expect(() =>
      routeFor("start", { objective: "ok", command: "cmd.exe" }),
    ).toThrow();
  });
  it("allows only fixed validated case actions", () => {
    const id = "case_" + "a".repeat(32);
    expect(routeFor("cancel", id)).toEqual({
      path: `/api/cases/${id}/cancel`,
      body: {},
    });
    expect(routeFor("start", { objective: "  Computer feels slow  " })).toEqual(
      {
        path: "/api/cases",
        body: {
          objective: "Computer feels slow",
          budget_ms: 60000,
          max_rounds: 4,
        },
      },
    );
  });
});
