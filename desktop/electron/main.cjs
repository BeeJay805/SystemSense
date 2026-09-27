const { app, BrowserWindow, ipcMain, dialog, Menu } = require("electron");
const { spawn } = require("node:child_process");
const path = require("node:path");
const fs = require("node:fs/promises");
const { pathToFileURL } = require("node:url");
const { createInterface } = require("node:readline");
const { LocalClient } = require("./bridge.cjs");
let window,
  child,
  client,
  exiting = false,
  stopped = false,
  startError = "Starting the local investigator…";
let childExit = Promise.resolve();
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
      window = new BrowserWindow({
        width: 1100,
        height: 840,
        minWidth: 620,
        minHeight: 540,
        title: "SystemSense",
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
      ipcMain.handle("quit", (event) => {
        trusted(event);
        void shutdown();
      });
      await window.loadURL(uiURL);
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
        ["--database", path.join(app.getPath("userData"), "cases.db")],
        { windowsHide: true, stdio: ["pipe", "pipe", "pipe"] },
      );
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
        startError =
          "The local investigator could not start. Reinstall the desktop package.";
        client = null;
      });
      child.on("exit", () => {
        client = null;
        startError =
          "The local investigator stopped. Close and reopen SystemSense to recover saved cases.";
      });
      const lines = createInterface({ input: child.stdout });
      lines.once("line", (line) => {
        try {
          client = new LocalClient(JSON.parse(line).port);
        } catch {
          startError =
            "The local investigator returned an invalid startup response.";
        }
      });
    })
    .catch(() => {
      dialog.showErrorBox(
        "SystemSense could not open",
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
    window.setTitle("SystemSense · Stopping and saving…");
  if (child && child.pid) {
    child.stdin.end("\n");
    await childExit;
  }
  stopped = true;
  app.quit();
}
