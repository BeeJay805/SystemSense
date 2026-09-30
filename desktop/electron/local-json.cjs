const { randomUUID } = require("node:crypto");

const CASE = /^case_[0-9a-f]{32}$/;
const ERROR_MESSAGES = Object.freeze({
  busy: "Stop or finish the active investigation before checking a JSON file.",
  scope_blocked:
    "Choose one regular JSON file on a local drive. Network paths and linked files are not supported.",
  file_too_large: "Choose a JSON file no larger than 256 KiB.",
  file_unavailable:
    "The selected file could not be opened. Check its availability and choose it again.",
  changed_during_read:
    "The selected file changed during the check. Save it before choosing it again.",
  invalid_request:
    "The local file request was not recognized. Reopen Dyad before trying again.",
  unavailable:
    "The local JSON check is unavailable. Reconnect before trying again.",
});
const INVALID_RESPONSE =
  "The local file-check response was not recognized. Check History before trying again.";
const CONNECTION_LOST =
  "The local file-check connection was lost. Reconnect and check History before trying again.";

function exactKeys(record, keys) {
  return (
    record &&
    typeof record === "object" &&
    !Array.isArray(record) &&
    Object.keys(record).length === keys.length &&
    keys.every((key) => Object.hasOwn(record, key))
  );
}

class LocalJsonRequests {
  constructor({ send }) {
    this.send = send;
    this.pending = null;
    this.closed = false;
  }

  start(selectedPath) {
    return this.request(
      {
        type: "start_local_json_case",
        request_id: randomUUID(),
        selected_path: selectedPath,
      },
      false,
    );
  }

  request(command, raw = true) {
    if (this.closed) throw Error(CONNECTION_LOST);
    if (this.pending) throw Error("A local file check is already starting.");
    const requestId = command.request_id;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.finish(
          new Error(
            "The local file check may have started, but no confirmation arrived. Reconnect and check History before trying again.",
          ),
        );
      }, 10000);
      this.pending = { requestId, timer, resolve, reject, raw };
      try {
        this.send(JSON.stringify(command) + "\n");
      } catch {
        this.close();
      }
    });
  }

  receive(record) {
    if (!this.pending || record?.request_id !== this.pending.requestId)
      return false;
    if (this.pending.raw) {
      this.finish(null, record);
      return true;
    }
    if (
      exactKeys(record, ["type", "request_id", "case_id"]) &&
      record.type === "local_json_case_started" &&
      typeof record.case_id === "string" &&
      CASE.test(record.case_id)
    ) {
      this.finish(null, record.case_id);
    } else if (
      exactKeys(record, ["type", "request_id", "error_code"]) &&
      record.type === "local_json_case_error" &&
      typeof record.error_code === "string" &&
      Object.hasOwn(ERROR_MESSAGES, record.error_code)
    ) {
      this.finish(new Error(ERROR_MESSAGES[record.error_code]));
    } else {
      this.invalidResponse();
    }
    return true;
  }

  invalidResponse() {
    this.finish(new Error(INVALID_RESPONSE));
  }

  close() {
    this.closed = true;
    this.finish(new Error(CONNECTION_LOST));
  }

  finish(error, caseId) {
    const pending = this.pending;
    if (!pending) return;
    this.pending = null;
    clearTimeout(pending.timer);
    if (error) pending.reject(error);
    else pending.resolve(caseId);
  }
}

function checkAvailable(caps) {
  if (caps?.active_case_id) throw Error(ERROR_MESSAGES.busy);
  if (
    caps?.read_only !== true ||
    caps?.inference?.start_allowed === false ||
    caps?.local_json_task?.enabled !== true
  )
    throw Error(ERROR_MESSAGES.unavailable);
}

function createJsonFileAction({
  chooseFile,
  capabilities,
  startCase,
  getCase,
}) {
  let choosing = false;
  return async (...args) => {
    if (args.length) throw Error("Select a file using the native file picker.");
    if (choosing) throw Error("A local file check is already starting.");
    choosing = true;
    try {
      checkAvailable(await capabilities());
      const selected = await chooseFile({
        title: "Check one local JSON file (up to 256 KiB)",
        buttonLabel: "Check this JSON file",
        filters: [{ name: "JSON files", extensions: ["json"] }],
        properties: ["openFile"],
      });
      if (selected.canceled) return { cancelled: true };
      if (
        !Array.isArray(selected.filePaths) ||
        selected.filePaths.length !== 1 ||
        typeof selected.filePaths[0] !== "string" ||
        !selected.filePaths[0]
      )
        throw Error(ERROR_MESSAGES.scope_blocked);
      checkAvailable(await capabilities());
      const id = await startCase(selected.filePaths[0]);
      return { case: await getCase(id) };
    } finally {
      choosing = false;
    }
  };
}

module.exports = { LocalJsonRequests, createJsonFileAction };
