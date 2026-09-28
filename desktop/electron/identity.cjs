const path = require("node:path");
const productName = "Dyad";
const appId = "org.systemsense.desktop";
// This is the shipped storage identity, independently verified against the
// previous packaged backend's --database path. Branding must never migrate it.
const legacyDataDirectory = (appData) =>
  path.join(appData, "systemsense-desktop");
function applyIdentity(app) {
  const data = app.commandLine.hasSwitch("user-data-dir")
    ? app.getPath("userData")
    : legacyDataDirectory(app.getPath("appData"));
  app.setName(productName);
  app.setPath("userData", data);
  app.setAppUserModelId(appId);
}
module.exports = { productName, appId, legacyDataDirectory, applyIdentity };
