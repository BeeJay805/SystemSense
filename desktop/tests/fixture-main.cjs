// Test-only app. Excluded from distributable files; never starts a backend.
const { app, BrowserWindow, ipcMain } = require("electron");
const path = require("node:path");
const { states } = require("./fixtures.cjs");
app.disableHardwareAcceleration();
let current = states[process.env.SYSTEMSENSE_FIXTURE] ?? states.empty;
let starts = 0;
app.whenReady().then(() => {
  const window = new BrowserWindow({
    width: 1100,
    height: 840,
    webPreferences: {
      preload: path.join(__dirname, "fixture-preload.cjs"),
      contextIsolation: true,
      sandbox: true,
    },
  });
  ipcMain.handle("fixture", (_event, method, args) => {
    if (process.env.SYSTEMSENSE_FIXTURE === "disconnected")
      throw Error("Development fixture: disconnected");
    if (method === "capabilities")
      return {
        read_only: true,
        active_case_id: ["running", "awaiting_target"].includes(current.status)
          ? current.case_id
          : null,
        probes: [{ probe_id: "core.system" }],
        inference: { enabled: false },
      };
    if (method === "listCases")
      return { cases: current.case_id ? [current] : [] };
    if (method === "cancel") {
      current = { ...current, status: "cancelled", outcome: "cancelled" };
      return current;
    }
    if (method === "selectTarget") {
      current = { ...current, status: "complete" };
      return current;
    }
    if (method === "start") {
      starts++;
      current = {
        ...states.running,
        case_id: "fixture-started",
        objective: args.objective,
        created_at: new Date().toISOString(),
      };
      return current;
    }
    if (method === "resume") {
      current = { ...current, status: "running", outcome: "investigating" };
      return current;
    }
    if (method === "exportCase") return { saved: true };
    if (method === "startCount") return starts;
    return current;
  });
  window.loadFile(path.resolve(__dirname, "../dist/index.html"));
});
app.on("window-all-closed", () => app.quit());
