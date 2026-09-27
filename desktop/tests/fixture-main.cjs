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
  ipcMain.handle("fixture", (_event, method) => {
    if (process.env.SYSTEMSENSE_FIXTURE === "disconnected")
      throw Error("Development fixture: disconnected");
    if (method === "capabilities")
      return {
        read_only: true,
        active_case_id:
          current.status === "awaiting_target" ? current.case_id : null,
        probes: [{ probe_id: "core.system" }],
        inference: { enabled: false },
      };
    if (method === "listCases") return { cases: [current] };
    if (method === "selectTarget") {
      current = { ...current, status: "complete" };
      return current;
    }
    if (method === "start") {
      starts++;
      return current;
    }
    if (method === "startCount") return starts;
    return current;
  });
  window.loadFile(path.resolve(__dirname, "../dist/index.html"));
});
app.on("window-all-closed", () => app.quit());
