const fs = require("node:fs/promises");
const path = require("node:path");
const { randomUUID } = require("node:crypto");

const MODES = new Set(["deterministic", "laya-sol"]);

async function readMode(file) {
  let raw;
  try {
    raw = await fs.readFile(file, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return "deterministic";
    throw error;
  }
  if (Buffer.byteLength(raw) > 128)
    throw Error("Invalid saved investigation mode");
  let value;
  try {
    value = JSON.parse(raw);
  } catch {
    throw Error("Invalid saved investigation mode");
  }
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).length !== 1 ||
    !MODES.has(value.mode)
  )
    throw Error("Invalid saved investigation mode");
  return value.mode;
}

async function saveMode(file, mode) {
  if (!MODES.has(mode)) throw Error("Invalid investigation mode");
  await fs.mkdir(path.dirname(file), { recursive: true });
  const pending = `${file}.${process.pid}.${randomUUID()}.pending`;
  try {
    await fs.writeFile(pending, JSON.stringify({ mode }) + "\n", {
      encoding: "utf8",
      flag: "wx",
    });
    await fs.rename(pending, file);
  } finally {
    await fs.rm(pending, { force: true });
  }
}

module.exports = { readMode, saveMode };
