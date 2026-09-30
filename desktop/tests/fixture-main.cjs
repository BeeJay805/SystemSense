// Test-only app. Excluded from distributable files; never starts a backend.
const { app, BrowserWindow, ipcMain } = require("electron");
const path = require("node:path");
const { states } = require("./fixtures.cjs");
const { applyIdentity } = require("../electron/identity.cjs");
if (process.env.DYAD_FIXTURE_APP_DATA)
  app.setPath("appData", process.env.DYAD_FIXTURE_APP_DATA);
applyIdentity(app);
app.disableHardwareAcceleration();
let current = states[process.env.SYSTEMSENSE_FIXTURE] ?? states.empty;
let starts = 0;
let capabilityOverride = {};
let modelMode = "deterministic";
let jsonFileOutcome = "cancelled";
let jsonFileRequests = 0;
let setup = {
  state: "ready_to_install",
  stage: "ready",
  reason_code: null,
  can_install: true,
  existing_install: false,
};
app.whenReady().then(() => {
  const window = new BrowserWindow({
    width: 1100,
    height: 840,
    title: "Dyad",
    icon: path.resolve(__dirname, "../assets/dyad.ico"),
    webPreferences: {
      preload: path.join(__dirname, "fixture-preload.cjs"),
      contextIsolation: true,
      sandbox: true,
    },
  });
  ipcMain.handle("fixture", (_event, method, args) => {
    if (method === "setCase") {
      current = args;
      return;
    }
    if (method === "setCapabilities") {
      capabilityOverride = args;
      return;
    }
    if (method === "setJsonFileOutcome") {
      jsonFileOutcome = args;
      return;
    }
    if (method === "jsonFileRequestCount") return jsonFileRequests;
    if (method === "startJsonFileCheck") {
      jsonFileRequests++;
      if (
        !capabilityOverride.local_json_task?.enabled ||
        jsonFileOutcome === "unavailable"
      )
        throw Error(
          "The local JSON check is unavailable. Reconnect before trying again.",
        );
      if (jsonFileOutcome === "cancelled") return { cancelled: true };
      starts++;
      current = {
        ...states.running,
        objective: "Check whether the selected JSON file opens and parses.",
      };
      return { case: current };
    }
    if (method === "desktopInfo")
      return {
        dataLocation: "Development fixture / cases.db",
        version: "0.1.0-fixture",
      };
    if (method === "modelSettings") return { mode: modelMode };
    if (method === "layaSetupStatus") return setup;
    if (method === "installLaya") {
      setup = {
        ...setup,
        state: "installing",
        stage: "installing_laya",
        can_install: false,
      };
      return setup;
    }
    if (method === "cancelLayaSetup") {
      setup = {
        ...setup,
        state: "cancelled",
        stage: "cancelled",
        can_install: true,
      };
      return setup;
    }
    if (method === "setModelMode") {
      if (["running", "awaiting_target"].includes(current.status))
        throw Error("Stop the active case before changing mode.");
      if (!["deterministic", "laya-sol"].includes(args))
        throw Error("Invalid investigation mode");
      modelMode = args;
      return { restarting: false };
    }
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
        ...capabilityOverride,
      };
    if (method === "listCases") {
      const { case_id, objective, status, outcome, created_at, updated_at } =
        current;
      return {
        cases: case_id
          ? [{ case_id, objective, status, outcome, created_at, updated_at }]
          : [],
      };
    }
    if (method === "cancel") {
      current = {
        ...current,
        status: "cancelled",
        outcome: "cancelled",
        updated_at: new Date().toISOString(),
      };
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
