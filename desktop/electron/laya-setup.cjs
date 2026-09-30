const STATES = new Set([
  "unavailable",
  "ready_to_install",
  "installing",
  "cancelling",
  "installed",
  "cancelled",
  "failed",
  "cleanup_pending",
]);
const KEYS = [
  "state",
  "stage",
  "reason_code",
  "can_install",
  "existing_install",
];
const CODE = /^[a-z][a-z0-9_]{0,79}$/;
const ACTIVE = new Set(["installing", "cancelling", "cleanup_pending"]);

function readSetupSnapshot(value) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).length !== KEYS.length ||
    !KEYS.every((key) => Object.hasOwn(value, key)) ||
    !STATES.has(value.state) ||
    typeof value.stage !== "string" ||
    !CODE.test(value.stage) ||
    !(
      value.reason_code === null ||
      (typeof value.reason_code === "string" && CODE.test(value.reason_code))
    ) ||
    typeof value.can_install !== "boolean" ||
    typeof value.existing_install !== "boolean" ||
    (value.can_install &&
      !["ready_to_install", "cancelled", "failed"].includes(value.state))
  )
    throw Error("The local setup status was not recognized.");
  return Object.freeze(
    Object.fromEntries(KEYS.map((key) => [key, value[key]])),
  );
}

/** Installation authority stays in main and its dedicated inherited pipe. */
function createLayaSetupAction({ request, checkIdle, confirm }) {
  let pending = false;
  let last = null;
  let uncertain = false;
  async function read(command) {
    last = readSetupSnapshot(await request(command));
    uncertain = false;
    return last;
  }
  function noArguments(args) {
    if (args.length) throw Error("Local setup accepts no arguments.");
  }
  return {
    get busy() {
      return pending || uncertain || ACTIVE.has(last?.state);
    },
    async status(...args) {
      noArguments(args);
      return read("status");
    },
    async install(...args) {
      noArguments(args);
      if (pending || uncertain || ACTIVE.has(last?.state))
        throw Error(
          "Local setup is already active or its cleanup is unresolved.",
        );
      pending = true;
      try {
        await checkIdle();
        const status = await read("status");
        if (!status.can_install) return status;
        const answer = await confirm({
          type: "question",
          title: "Install local Laya?",
          message: "Install the pinned local model for Dyad?",
          detail:
            "This setup requires a compatible NVIDIA GPU and driver. Dyad will install its bundled Python and download the pinned Laya model and CUDA dependencies into your per-user SystemSense runtime folder. This uses several GB of disk space and network downloads. It does not change system Python or install drivers. You can cancel; only files created by this setup attempt may be removed. Codex with a ChatGPT sign-in is also required.",
          buttons: ["Cancel", "Install local Laya"],
          defaultId: 0,
          cancelId: 0,
          noLink: true,
        });
        if (answer.response !== 1) return status;
        await checkIdle();
        // Lost acknowledgement cannot safely authorize another attempt.
        uncertain = true;
        return await read("install");
      } finally {
        pending = false;
      }
    },
    async cancel(...args) {
      noArguments(args);
      return read("cancel");
    },
  };
}

module.exports = { createLayaSetupAction, readSetupSnapshot };
