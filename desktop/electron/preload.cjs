const { contextBridge, ipcRenderer } = require("electron");
contextBridge.exposeInMainWorld(
  "systemsense",
  Object.freeze({
    desktopInfo: () => ipcRenderer.invoke("desktopInfo"),
    capabilities: () => ipcRenderer.invoke("capabilities"),
    listCases: () => ipcRenderer.invoke("listCases"),
    getCase: (id) => ipcRenderer.invoke("getCase", id),
    start: (value) => ipcRenderer.invoke("start", value),
    cancel: (id) => ipcRenderer.invoke("cancel", id),
    resume: (id) => ipcRenderer.invoke("resume", id),
    selectTarget: (value) => ipcRenderer.invoke("selectTarget", value),
    exportCase: (id) => ipcRenderer.invoke("exportCase", id),
    quit: () => ipcRenderer.invoke("quit"),
  }),
);
