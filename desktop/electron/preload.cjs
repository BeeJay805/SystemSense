const { contextBridge, ipcRenderer } = require("electron");
contextBridge.exposeInMainWorld(
  "systemsense",
  Object.freeze({
    desktopInfo: () => ipcRenderer.invoke("desktopInfo"),
    modelSettings: () => ipcRenderer.invoke("modelSettings"),
    setModelMode: (mode) => ipcRenderer.invoke("setModelMode", mode),
    capabilities: () => ipcRenderer.invoke("capabilities"),
    listCases: () => ipcRenderer.invoke("listCases"),
    getCase: (id) => ipcRenderer.invoke("getCase", id),
    start: (value) => ipcRenderer.invoke("start", value),
    startJsonFileCheck: () => ipcRenderer.invoke("startJsonFileCheck"),
    saveJsonCopy: (id) => ipcRenderer.invoke("saveJsonCopy", id),
    cancel: (id) => ipcRenderer.invoke("cancel", id),
    resume: (id) => ipcRenderer.invoke("resume", id),
    selectTarget: (value) => ipcRenderer.invoke("selectTarget", value),
    exportCase: (id) => ipcRenderer.invoke("exportCase", id),
    quit: () => ipcRenderer.invoke("quit"),
  }),
);
