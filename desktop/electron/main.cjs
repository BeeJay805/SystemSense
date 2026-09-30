const { app, BrowserWindow, ipcMain, dialog, Menu } = require("electron");
const { spawn } = require("node:child_process");
const path = require("node:path");
const fs = require("node:fs/promises");
const { pathToFileURL } = require("node:url");
const { createInterface } = require("node:readline");
const { LocalClient } = require("./bridge.cjs");
const { applyIdentity, productName } = require("./identity.cjs");
const { readMode, saveMode } = require("./settings.cjs");
const { LocalJsonRequests, createJsonFileAction } = require("./local-json.cjs");
applyIdentity(app);
let window,
  child,
  client,
  jsonRequests,
  exiting = false,
  stopped = false,
  startError = "Starting the local investigator…";
let childExit = Promise.resolve();
let inferenceMode = "deterministic";
let settingsError = null;
const desktopRoot = path.resolve(__dirname, "..");
const uiURL = pathToFileURL(path.join(desktopRoot, "dist", "index.html")).href;
if (!app.isPackaged && process.env.SYSTEMSENSE_DESKTOP_TEST_DATA)
  app.setPath("userData", process.env.SYSTEMSENSE_DESKTOP_TEST_DATA);
if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on("second-instance", () => {
    if (window) {
      if (window.isMinimized()) window.restore();
      window.focus();
    }
  });
  app
    .whenReady()
    .then(async () => {
      Menu.setApplicationMenu(null);
      const settingsPath = path.join(
        app.getPath("userData"),
        "investigation-mode.json",
      );
      try {
        inferenceMode = await readMode(settingsPath);
      } catch {
        settingsError =
          "Saved investigation mode is invalid. Choose a mode in Settings.";
        startError = settingsError;
      }
      window = new BrowserWindow({
        width: 1100,
        height: 840,
        minWidth: 620,
        minHeight: 540,
        title: productName,
        icon: path.join(desktopRoot, "assets", "dyad.ico"),
        backgroundColor: "#151b1b",
        webPreferences: {
          preload: path.join(__dirname, "preload.cjs"),
          nodeIntegration: false,
          contextIsolation: true,
          sandbox: true,
          webSecurity: true,
        },
      });
      window.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
      window.webContents.on("will-navigate", (event, url) => {
        if (url !== uiURL) event.preventDefault();
      });
      window.webContents.session.setPermissionRequestHandler(
        (_contents, _permission, callback) => callback(false),
      );
      window.webContents.session.setPermissionCheckHandler(() => false);
      window.on("close", (event) => {
        if (!stopped) {
          event.preventDefault();
          void shutdown();
        }
      });
      function trusted(event) {
        if (
          event.sender !== window.webContents ||
          event.senderFrame !== window.webContents.mainFrame ||
          event.senderFrame.url !== uiURL
        )
          throw Error("Untrusted desktop request");
      }
      for (const method of [
        "capabilities",
        "listCases",
        "getCase",
        "start",
        "cancel",
        "resume",
        "selectTarget",
        "exportCase",
      ]) {
        ipcMain.handle(method, async (event, value) => {
          trusted(event);
          if (exiting) throw Error("Stopping and saving the investigation.");
          if (!client) throw Error(startError);
          const result = await client.request(method, value);
          if (method !== "exportCase") return result;
          const chosen = await dialog.showSaveDialog(window, {
            title: "Save evidence report",
            defaultPath: `${value}.json`,
            filters: [{ name: "JSON evidence report", extensions: ["json"] }],
          });
          if (chosen.canceled || !chosen.filePath) return { saved: false };
          await fs.writeFile(
            chosen.filePath,
            JSON.stringify(result, null, 2),
            "utf8",
          );
          return { saved: true };
        });
      }
      const startJsonFileCheck = createJsonFileAction({
        chooseFile: (options) =>
          dialog.showOpenDialog(window, options).catch(() => {
            throw Error("The native file picker could not open. Try again.");
          }),
        capabilities: () => {
          if (exiting || !client) throw Error(startError);
          return client.request("capabilities");
        },
        startCase: (selectedPath) => {
          if (exiting || !jsonRequests) throw Error(startError);
          return jsonRequests.start(selectedPath);
        },
        getCase: (id) => {
          if (exiting || !client) throw Error(startError);
          return client.request("getCase", id);
        },
      });
      ipcMain.handle("startJsonFileCheck", (event, ...args) => {
        trusted(event);
        return startJsonFileCheck(...args);
      });
      ipcMain.handle("quit", (event) => {
        trusted(event);
        void shutdown();
      });
      ipcMain.handle("desktopInfo", (event) => {
        trusted(event);
        return {
          dataLocation: path.join(app.getPath("userData"), "cases.db"),
          version: app.getVersion(),
        };
      });
      ipcMain.handle("modelSettings", (event) => {
        trusted(event);
        return {
          mode: settingsError ? "invalid" : inferenceMode,
          error: settingsError,
        };
      });
      ipcMain.handle("setModelMode", async (event, mode) => {
        trusted(event);
        if (exiting) throw Error("Dyad is stopping.");
        if (mode !== "deterministic" && mode !== "laya-sol")
          throw Error("Invalid investigation mode");
        if (client) {
          const caps = await client.request("capabilities");
          if (caps.active_case_id)
            throw Error(
              "Stop or finish the active investigation before changing mode.",
            );
        }
        if (mode === inferenceMode && !settingsError)
          return { restarting: false };
        await saveMode(settingsPath, mode);
        inferenceMode = mode;
        settingsError = null;
        setImmediate(() => {
          app.relaunch();
          void shutdown();
        });
        return { restarting: true };
      });
      await window.loadURL(uiURL);
      if (settingsError) return;
      const executable = app.isPackaged
        ? path.join(process.resourcesPath, "investigator", "investigator.exe")
        : path.join(
            desktopRoot,
            "backend",
            "dist",
            "investigator",
            "investigator.exe",
          );
      await fs.mkdir(app.getPath("userData"), { recursive: true });
      child = spawn(
        executable,
        [
          "--database",
          path.join(app.getPath("userData"), "cases.db"),
          "--inference-mode",
          inferenceMode,
        ],
        { windowsHide: true, stdio: ["pipe", "pipe", "pipe"] },
      );
      jsonRequests = new LocalJsonRequests({
        send: (line) =>
          child.stdin.write(line, (error) => {
            if (error) jsonRequests.close();
          }),
      });
      childExit = new Promise((resolve) => {
        child.once("exit", resolve);
        child.once("error", resolve);
      });
      child.stdin.on("error", () => {
        /* An exited child cannot accept shutdown again. */
      });
      child.stderr.on("data", () => {
        /* Never expose private traceback payloads to renderer. */
      });
      child.on("error", () => {
        jsonRequests.close();
        startError =
          "The local investigator could not start. Reinstall the desktop package.";
        client = null;
      });
      child.on("exit", () => {
        jsonRequests.close();
        client = null;
        startError =
          "The local investigator stopped. Close and reopen Dyad to recover saved cases.";
      });
      const lines = createInterface({ input: child.stdout });
      let readyReceived = false;
      lines.on("line", (line) => {
        try {
          if (line.length > 65536) throw Error("Oversized backend response");
          const record = JSON.parse(line);
          if (!readyReceived) {
            if (
              !record ||
              typeof record !== "object" ||
              Object.keys(record).length !== 1 ||
              !Object.hasOwn(record, "port")
            )
              throw Error("Invalid backend readiness");
            client = new LocalClient(record.port);
            readyReceived = true;
          } else {
            jsonRequests.receive(record);
          }
        } catch {
          jsonRequests.invalidResponse();
          startError =
            "The local investigator returned an invalid startup response.";
        }
      });
    })
    .catch(() => {
      dialog.showErrorBox(
        "Dyad could not open",
        "Close the app and try again. No investigation has been requested.",
      );
      app.quit();
    });
  app.on("before-quit", (event) => {
    if (!stopped) {
      event.preventDefault();
      void shutdown();
    }
  });
}
async function shutdown() {
  if (exiting) return;
  exiting = true;
  if (window && !window.isDestroyed())
    window.setTitle("Dyad · Stopping and saving…");
  if (child && child.pid) {
    jsonRequests?.close();
    child.stdin.end(JSON.stringify({ type: "shutdown" }) + "\n");
    await childExit;
  }
  stopped = true;
  app.quit();
}
