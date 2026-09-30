const { spawn } = require("node:child_process");
const { readSetupSnapshot } = require("./laya-setup.cjs");

/** One fixed executable, one inherited pipe, no HTTP or renderer-selected arguments. */
class LayaSetupClient {
  constructor(executable, launch = spawn) {
    this.executable = executable;
    this.launch = launch;
    this.child = null;
    this.queue = Promise.resolve();
    this.pending = null;
    this.failed = false;
    this.closing = false;
    this.exited = Promise.resolve();
  }

  open() {
    if (this.child) return;
    this.child = this.launch(this.executable, ["--laya-setup"], {
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"],
    });
    const child = this.child;
    let buffer = "";
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      buffer += chunk;
      if (buffer.length > 4096) return this.fail();
      let end;
      while ((end = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, end);
        buffer = buffer.slice(end + 1);
        try {
          if (!this.pending) throw Error("Unexpected setup response");
          const snapshot = readSetupSnapshot(JSON.parse(line));
          const pending = this.pending;
          this.pending = null;
          clearTimeout(pending.timer);
          pending.resolve(snapshot);
        } catch {
          this.fail();
        }
      }
    });
    child.stderr.on("data", () => {}); // Private diagnostics never reach the renderer.
    child.stdin.on("error", () => this.fail());
    this.exited = new Promise((resolve) => {
      child.once("exit", () => {
        this.fail();
        resolve();
      });
      child.once("error", () => {
        this.fail();
        resolve();
      });
    });
  }

  fail() {
    this.failed = true;
    if (this.pending) {
      clearTimeout(this.pending.timer);
      this.pending.reject(
        Error(
          "Local setup stopped responding. Close Dyad to cancel and recover setup.",
        ),
      );
      this.pending = null;
    }
    // EOF asks the child to cancel and prove its descendants exited before cleanup.
    if (this.child && !this.child.stdin.destroyed) this.child.stdin.end();
  }

  request(command) {
    if (!["status", "install", "cancel"].includes(command))
      return Promise.reject(Error("Invalid local setup request"));
    const operation = this.queue.then(() => {
      if (this.failed || this.closing)
        throw Error("Local setup is unavailable. Close and reopen Dyad.");
      this.open();
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => this.fail(), 30000);
        this.pending = { resolve, reject, timer };
        this.child.stdin.write(
          JSON.stringify({ type: command }) + "\n",
          (error) => {
            if (error) this.fail();
          },
        );
      });
    });
    this.queue = operation.catch(() => {});
    return operation;
  }

  async close() {
    this.closing = true;
    if (!this.child) return;
    // This is a request, never an acknowledgement that cancellation succeeded.
    this.child.stdin.end();
    let terminateTimer, deadlineTimer;
    try {
      await Promise.race([
        this.exited,
        new Promise((_resolve, reject) => {
          terminateTimer = setTimeout(() => {
            // The dedicated setup backend owns a kill-on-close lifetime Job
            // before any installer child can be created. Its journal remains
            // for recovery; termination is not a successful-cleanup receipt.
            try {
              this.child.kill();
            } catch {
              // The exit deadline below reports the unresolved shutdown.
            }
          }, 30000);
          deadlineTimer = setTimeout(
            () => reject(Error("Local setup shutdown could not be confirmed.")),
            35000,
          );
        }),
      ]);
    } finally {
      clearTimeout(terminateTimer);
      clearTimeout(deadlineTimer);
    }
  }
}

module.exports = { LayaSetupClient };
