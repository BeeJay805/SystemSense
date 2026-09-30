const { createHash, randomUUID } = require("node:crypto");

const CASE = /^case_[0-9a-f]{32}$/;
const HASH = /^[0-9a-f]{64}$/;
const TOKEN = /^[A-Za-z0-9_-]{16,256}$/;
const ID = /^[a-z][a-z0-9_.-]{0,119}$/;
const PREVIEW_KEYS = [
  "case_id",
  "operation",
  "capture_sha256",
  "captured_at",
  "source_size_bytes",
  "output_sha256",
  "output_size_bytes",
  "expires_at",
];
const RESULT_KEYS = [
  "type",
  "request_id",
  "operation_id",
  "status",
  "verification",
  "capture_sha256",
  "source_size_bytes",
  "output_sha256",
  "output_size_bytes",
  "evidence_ids",
];
const INVALID =
  "The JSON copy response was not recognized. No copy was requested.";
const UNAVAILABLE =
  "The JSON copy could not be prepared. No copy was requested.";
const EXPIRED =
  "The JSON copy approval has expired. Check the file again before trying to save a copy.";
const ERRORS = Object.freeze({
  busy: "Finish the active operation before saving a JSON copy.",
  expired: EXPIRED,
  source_unavailable:
    "The captured version is no longer available. Check the file again before saving a copy.",
  ineligible:
    "This captured version does not support the verified JSON copy operation.",
  scope_blocked:
    "Choose a new file on a local drive. Linked files and network paths are not supported.",
  destination_exists:
    "The chosen file already exists. Choose a new filename; existing files cannot be replaced.",
  unavailable: UNAVAILABLE,
  invalid_request: INVALID,
});

class ApprovalError extends Error {}

function exactKeys(value, keys) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key))
  );
}

function matches(pattern, value) {
  return typeof value === "string" && pattern.test(value);
}

function timestamp(value) {
  if (
    typeof value !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/.test(value)
  )
    return NaN;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) &&
    new Date(parsed).toISOString().slice(0, 19) === value.slice(0, 19)
    ? parsed
    : NaN;
}

function checkExpiry(preview, now) {
  if (timestamp(preview.expires_at) <= now) throw new ApprovalError(EXPIRED);
}

function readPreview(value, caseId, now) {
  if (
    !exactKeys(value, PREVIEW_KEYS) ||
    value.case_id !== caseId ||
    value.operation !== "remove_utf8_bom_copy" ||
    !matches(HASH, value.capture_sha256) ||
    !matches(HASH, value.output_sha256) ||
    !Number.isSafeInteger(value.source_size_bytes) ||
    value.source_size_bytes > 262144 ||
    !Number.isSafeInteger(value.output_size_bytes) ||
    value.output_size_bytes < 1 ||
    value.source_size_bytes - value.output_size_bytes !== 3 ||
    !Number.isFinite(timestamp(value.captured_at)) ||
    timestamp(value.captured_at) > now ||
    !Number.isFinite(timestamp(value.expires_at)) ||
    timestamp(value.expires_at) > now + 300000
  ) {
    throw new ApprovalError(INVALID);
  }
  checkExpiry(value, now);
  return Object.freeze({ ...value });
}

function readResult(value, preview) {
  if (
    !exactKeys(value, RESULT_KEYS) ||
    value.type !== "json_repair_result" ||
    !matches(ID, value.operation_id) ||
    !["verified", "failed", "pending", "uncertain"].includes(value.status) ||
    ![null, "independent_output_read"].includes(value.verification) ||
    !Array.isArray(value.evidence_ids) ||
    value.evidence_ids.length > 32 ||
    !value.evidence_ids.every((id) => matches(ID, id)) ||
    new Set(value.evidence_ids).size !== value.evidence_ids.length ||
    ![
      "capture_sha256",
      "source_size_bytes",
      "output_sha256",
      "output_size_bytes",
    ].every((key) => value[key] === preview[key]) ||
    (value.status === "verified" &&
      (value.verification !== "independent_output_read" ||
        !value.evidence_ids.length))
  ) {
    throw new ApprovalError(INVALID);
  }
  // Project the receipt explicitly: authority tokens and native paths never leave main.
  return {
    operation_id: value.operation_id,
    status: value.status,
    verification: value.verification,
    capture_sha256: value.capture_sha256,
    source_size_bytes: value.source_size_bytes,
    output_sha256: value.output_sha256,
    output_size_bytes: value.output_size_bytes,
    evidence_ids: [...value.evidence_ids],
  };
}

/** Main-process-only adapter. request owns authenticated child transport, not retries. */
function createJsonRepairAction({
  request,
  showSaveDialog,
  showMessageBox,
  now = Date.now,
}) {
  let busy = false;

  async function rpc(type, fields) {
    const command = { type, request_id: randomUUID(), ...fields };
    let timer;
    try {
      const response = await Promise.race([
        Promise.resolve().then(() => request(command)),
        new Promise((_, reject) => {
          timer = setTimeout(
            () => reject(new ApprovalError(UNAVAILABLE)),
            10000,
          );
        }),
      ]);
      if (!response || response.request_id !== command.request_id)
        throw new ApprovalError(INVALID);
      if (response.type === "json_repair_error") {
        if (
          !exactKeys(response, ["type", "request_id", "error_code"]) ||
          !Object.hasOwn(ERRORS, response.error_code)
        )
          throw new ApprovalError(INVALID);
        throw new ApprovalError(ERRORS[response.error_code]);
      }
      return response;
    } finally {
      clearTimeout(timer);
    }
  }

  return async function begin(...args) {
    if (args.length !== 1 || !matches(CASE, args[0]))
      throw new ApprovalError(
        "Select a case only; the native dialogs choose and approve the copy.",
      );
    if (busy) throw new ApprovalError("A JSON copy approval is already open.");
    busy = true;
    let offerToken;
    let executionStarted = false;
    let abandonmentAttempted = false;

    async function abandon() {
      if (!offerToken || abandonmentAttempted) return;
      abandonmentAttempted = true;
      try {
        const response = await rpc("json_repair_abandon", {
          offer_token: offerToken,
        });
        if (
          !exactKeys(response, ["type", "request_id"]) ||
          response.type !== "json_repair_abandoned"
        )
          throw new ApprovalError(INVALID);
      } catch {
        throw new ApprovalError(
          "No copy was requested, but the local approval could not be closed. Reopen Dyad before trying again.",
        );
      }
    }

    try {
      const prepared = await rpc("json_repair_prepare", { case_id: args[0] });
      if (
        prepared.type === "json_repair_prepared" &&
        matches(TOKEN, prepared.offer_token)
      )
        offerToken = prepared.offer_token;
      if (
        !exactKeys(prepared, [
          "type",
          "request_id",
          "offer_token",
          "preview",
        ]) ||
        !offerToken
      )
        throw new ApprovalError(INVALID);
      const preview = readPreview(prepared.preview, args[0], now());
      const selected = await showSaveDialog({
        title: "Save a corrected copy of the captured JSON version",
        buttonLabel: "Choose new file",
        defaultPath: "corrected.json",
        filters: [{ name: "JSON files", extensions: ["json"] }],
      });
      if (selected?.canceled === true) {
        await abandon();
        return { cancelled: true };
      }
      if (
        selected?.canceled !== false ||
        typeof selected.filePath !== "string" ||
        !/^[A-Za-z]:\\/.test(selected.filePath) ||
        selected.filePath.length > 32767 ||
        [...selected.filePath].some(
          (char) => char.charCodeAt(0) < 32 || char.charCodeAt(0) === 127,
        ) ||
        /[\u202a-\u202e\u2066-\u2069]/.test(selected.filePath)
      )
        throw new ApprovalError(ERRORS.scope_blocked);
      const destination = selected.filePath;
      checkExpiry(preview, now());
      const bound = await rpc("json_repair_bind_destination", {
        offer_token: offerToken,
        destination_path: destination,
      });
      if (
        !exactKeys(bound, [
          "type",
          "request_id",
          "proposal_token",
          "proposal_digest",
          "destination_path_sha256",
          "preview",
        ]) ||
        bound.type !== "json_repair_bound" ||
        !matches(TOKEN, bound.proposal_token) ||
        !matches(HASH, bound.proposal_digest) ||
        bound.destination_path_sha256 !==
          createHash("sha256").update(destination, "utf8").digest("hex") ||
        !exactKeys(bound.preview, PREVIEW_KEYS) ||
        !PREVIEW_KEYS.every((key) => bound.preview[key] === preview[key])
      )
        throw new ApprovalError(INVALID);
      const proposalToken = bound.proposal_token;
      const proposalDigest = bound.proposal_digest;
      checkExpiry(preview, now());
      const confirmation = await showMessageBox({
        type: "question",
        title: "Approve a corrected JSON copy",
        message: "Create this new file from the captured version?",
        detail: `Case: ${preview.case_id}\n\nSave a corrected copy of the version captured at ${preview.captured_at} (${preview.capture_sha256}).\n\nRemove exactly 3 bytes (the UTF-8 BOM, EF BB BF); keep every remaining byte unchanged. The remaining bytes have passed strict UTF-8 and JSON checks.\n\nNew file:\n${destination}\n\nDyad will not modify the original. Existing files cannot be replaced. The new file must be independently read and verified before success is reported. A failed write may leave an incomplete new file.\n\nCurrent disk contents and application recovery are unverified.`,
        buttons: ["Cancel", "Create verified JSON copy"],
        defaultId: 0,
        cancelId: 0,
        noLink: true,
      });
      if (confirmation?.response !== 1) {
        await abandon();
        return { cancelled: true };
      }
      checkExpiry(preview, now());
      // From this transition onward, no retry or abandonment can undo an execution.
      executionStarted = true;
      try {
        return readResult(
          await rpc("json_repair_execute", {
            proposal_token: proposalToken,
            proposal_digest: proposalDigest,
          }),
          preview,
        );
      } catch {
        try {
          return readResult(
            await rpc("json_repair_status", { proposal_token: proposalToken }),
            preview,
          );
        } catch {
          return { status: "uncertain", operation_id: null, evidence_ids: [] };
        }
      }
    } catch (error) {
      if (!executionStarted && !abandonmentAttempted) {
        await abandon();
      }
      throw error instanceof ApprovalError
        ? error
        : new ApprovalError(UNAVAILABLE);
    } finally {
      busy = false;
    }
  };
}

module.exports = { createJsonRepairAction };
