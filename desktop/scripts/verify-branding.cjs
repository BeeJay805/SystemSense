// Read-only PE resource verification. Does not execute the app or installer.
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const assert = require("node:assert/strict");
const {
  NtExecutable,
  NtExecutableResource,
  Resource,
  Data,
} = require("resedit");
const root = path.resolve(__dirname, "..");
const hash = (bytes) =>
  crypto.createHash("sha256").update(Buffer.from(bytes)).digest("hex");
const iconBytes = fs.readFileSync(path.join(root, "assets/dyad.ico"));
const icons = Data.IconFile.from(iconBytes).icons;
const expected = icons.map((item) => hash(item.data.bin)).sort();
const reports = [];
for (const relative of [
  "release/win-unpacked/Dyad.exe",
  "release/Dyad Setup 0.1.0.exe",
]) {
  const bytes = fs.readFileSync(path.join(root, relative));
  const resource = NtExecutableResource.from(NtExecutable.from(bytes));
  const groups = Resource.IconGroupEntry.fromEntries(resource.entries);
  const match = groups.find(
    (group) =>
      JSON.stringify(
        group
          .getIconItemsFromEntries(resource.entries)
          .map((item) => hash(item.bin))
          .sort(),
      ) === JSON.stringify(expected),
  );
  assert.ok(
    match,
    `${relative} must embed every original Dyad icon resolution`,
  );
  const version = Resource.VersionInfo.fromEntries(resource.entries)[0];
  const strings = version.getStringValues(
    version.getAllLanguagesForStringValues()[0],
  );
  assert.match(strings.ProductName, /^Dyad/);
  assert.match(strings.FileDescription, /^Dyad/);
  reports.push({
    file: relative,
    sha256: hash(bytes),
    bytes: bytes.length,
    productName: strings.ProductName,
    description: strings.FileDescription,
    iconGroup: match.id,
    iconSizes: icons.map((item) => item.data.width),
    iconPayloadsMatch: true,
  });
}
const report = { iconSha256: hash(iconBytes), artifacts: reports };
fs.mkdirSync(path.join(root, "artifacts"), { recursive: true });
fs.writeFileSync(
  path.join(root, "artifacts/dyad-branding-resources.json"),
  JSON.stringify(report, null, 2),
);
console.log(JSON.stringify(report, null, 2));
