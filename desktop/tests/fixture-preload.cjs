const { contextBridge, ipcRenderer } = require("electron");
const methods = [
  "capabilities",
  "listCases",
  "getCase",
  "start",
  "cancel",
  "resume",
  "selectTarget",
  "exportCase",
  "quit",
];
contextBridge.exposeInMainWorld(
  "systemsense",
  Object.fromEntries(
    methods.map((method) => [
      method,
      (args) => ipcRenderer.invoke("fixture", method, args),
    ]),
  ),
);
window.addEventListener("DOMContentLoaded", () => {
  localStorage.setItem("welcomed", "yes");
  const banner = document.createElement("aside");
  banner.textContent =
    "DEVELOPMENT FIXTURE · Simulated state, not computer observations";
  banner.style.cssText =
    "position:sticky;top:0;z-index:1000;padding:12px;background:#6d4321;color:white;text-align:center;font:16px Segoe UI";
  document.body.prepend(banner);
  // Reserve banner space inside the fixture viewport, without changing product CSS.
  const fitLanding = () => {
    const landing = document.querySelector(".landing");
    const header = document.querySelector(".topbar");
    if (landing && header)
      landing.style.minHeight = `calc(100vh - ${header.getBoundingClientRect().height + banner.getBoundingClientRect().height}px)`;
  };
  new ResizeObserver(fitLanding).observe(banner);
  new MutationObserver(fitLanding).observe(document.getElementById("root"), {
    childList: true,
    subtree: true,
  });
  window.addEventListener("resize", fitLanding);
  fitLanding();
});
