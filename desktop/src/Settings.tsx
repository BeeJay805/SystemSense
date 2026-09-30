import { useEffect, useRef, useState } from "react";
import { Icon } from "./Icon";
import type { Capabilities, DesktopAPI, LayaSetupStatus } from "./types";

function setupMessage(status: LayaSetupStatus): string {
  switch (status.state) {
    case "installed":
      return "The local runtime is installed. Select Laya + Sol to verify model and ChatGPT readiness.";
    case "ready_to_install":
      return "Local setup requires a compatible NVIDIA GPU and driver, your approval, and several GB of downloads and disk space.";
    case "installing":
      return "Installing the local runtime and pinned model. Downloads can take several minutes. You can cancel below.";
    case "cancelling":
      return "Stopping setup and checking its files before cleanup. Keep Dyad open until this finishes.";
    case "cancelled":
      return "Setup was cancelled. Your existing files were preserved.";
    case "cleanup_pending":
      return "Setup could not confirm cleanup. Close and reopen Dyad to check recovery before trying again.";
    case "failed":
      if (status.reason_code === "python_runtime_name_too_long")
        return "Windows could not start the local runtime because its folder path exceeds the system limit. Setup needs a shorter supported runtime path; retrying the same setup will not resolve this.";
      return "Local setup failed. Check your connection, available disk space, and NVIDIA GPU driver, then retry if offered.";
    default:
      return "Local setup is unavailable in this package. Existing installations are preserved.";
  }
}

type Mode = "deterministic" | "laya-sol";

export function Settings({
  api,
  capabilities,
  active,
  onClose,
}: {
  api?: DesktopAPI;
  capabilities?: Capabilities;
  active: boolean;
  onClose: () => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [mode, setMode] = useState<string>("loading");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [setup, setSetup] = useState<LayaSetupStatus>();
  const [setupError, setSetupError] = useState("");
  const [setupBusy, setSetupBusy] = useState(false);
  useEffect(() => {
    dialog.current?.showModal();
    void api?.modelSettings?.().then(
      (value) => {
        setMode(value.mode);
        if (value.error) setMessage(value.error);
      },
      () => setMessage("Investigation settings could not be read."),
    );
  }, [api]);
  useEffect(() => {
    if (!api?.layaSetupStatus) return;
    let disposed = false;
    let timer: ReturnType<typeof setTimeout>;
    async function refresh() {
      try {
        const result = await api!.layaSetupStatus!();
        if (disposed) return;
        setSetup(result);
        timer = setTimeout(() => void refresh(), 1500);
      } catch {
        if (!disposed)
          setSetupError(
            "Local setup status could not be read. Close and reopen Dyad to check recovery.",
          );
      }
    }
    void refresh();
    return () => {
      disposed = true;
      clearTimeout(timer);
    };
  }, [api]);
  async function changeSetup(cancel: boolean) {
    const action = cancel ? api?.cancelLayaSetup : api?.installLaya;
    if (!action || setupBusy) return;
    setSetupBusy(true);
    setSetupError("");
    try {
      setSetup(await action());
    } catch (error) {
      setSetupError(
        error instanceof Error
          ? error.message
          : "Local setup could not continue.",
      );
    } finally {
      setSetupBusy(false);
    }
  }
  const installing =
    setup?.state === "installing" ||
    setup?.state === "cancelling" ||
    setup?.state === "cleanup_pending";
  async function choose(next: Mode) {
    if (!api?.setModelMode || active || busy || installing || setupBusy) return;
    setBusy(true);
    setMessage("");
    try {
      const result = await api.setModelMode(next);
      setMode(next);
      setMessage(
        result.restarting
          ? "Restarting Dyad with this mode…"
          : "This mode is already active.",
      );
    } catch (error) {
      setMessage(
        error instanceof Error
          ? error.message
          : "Investigation mode could not be changed.",
      );
    } finally {
      setBusy(false);
    }
  }
  const inference = capabilities?.inference;
  return (
    <dialog
      ref={dialog}
      className="settings-dialog"
      aria-labelledby="settings-title"
      onCancel={onClose}
    >
      <header className="dialog-heading">
        <h2 id="settings-title">Settings</h2>
        <button
          autoFocus
          className="icon-button"
          aria-label="Close settings"
          onClick={onClose}
        >
          <Icon name="close" />
        </button>
      </header>
      <div className="settings-content">
        <h3>Investigation mode</h3>
        <p>
          Basic checks use fixed read-only rules. Laya + GPT-6 Sol uses a pinned
          local model and your signed-in Codex ChatGPT subscription. Both modes
          save cases locally and never repair the computer.
        </p>
        <div className="setting-choice">
          <div>
            <strong>Basic read-only checks</strong>
            <p>
              No model investigation. Current:{" "}
              {mode === "deterministic" ? "yes" : "no"}.
            </p>
          </div>
          <button
            className="secondary"
            disabled={
              busy ||
              active ||
              installing ||
              setupBusy ||
              mode === "deterministic" ||
              !api?.setModelMode
            }
            onClick={() => void choose("deterministic")}
          >
            Use basic checks
          </button>
        </div>
        <div className="setting-choice">
          <div>
            <strong>Laya + GPT-6 Sol</strong>
            <p>
              Requires the pinned local Laya runtime and a ChatGPT sign-in in
              Codex.
            </p>
          </div>
          <button
            className="secondary"
            disabled={
              busy ||
              active ||
              installing ||
              setupBusy ||
              mode === "laya-sol" ||
              !api?.setModelMode
            }
            onClick={() => void choose("laya-sol")}
          >
            Use Laya + Sol
          </button>
        </div>
        {api?.layaSetupStatus && (
          <section aria-label="Local model setup">
            <h3>Local model setup</h3>
            <p role="status">
              {setup ? setupMessage(setup) : "Checking local setup…"}
            </p>
            {setup?.can_install && (
              <button
                className="secondary"
                disabled={
                  !capabilities ||
                  active ||
                  busy ||
                  setupBusy ||
                  mode !== "deterministic"
                }
                onClick={() => void changeSetup(false)}
              >
                Install local Laya
              </button>
            )}
            {(setup?.state === "installing" ||
              setup?.state === "cancelling") && (
              <button
                className="secondary"
                disabled={setupBusy || setup.state === "cancelling"}
                onClick={() => void changeSetup(true)}
              >
                Cancel setup
              </button>
            )}
            {setup?.can_install && mode !== "deterministic" && (
              <p>Switch to Basic checks before installing the local model.</p>
            )}
            {setupError && <p role="alert">{setupError}</p>}
          </section>
        )}
        {mode === "laya-sol" && inference?.start_allowed === false && (
          <p role="alert">
            Model setup blocked: {inference.reason ?? "check the local setup"}
          </p>
        )}
        {mode === "laya-sol" && inference?.start_allowed === true && (
          <p role="status">
            Laya is warm and ChatGPT login was reported. Sol identity is checked
            on each model response.
          </p>
        )}
        {active && <p>Finish or stop the active case before changing mode.</p>}
        {message && <p role="status">{message}</p>}
      </div>
    </dialog>
  );
}
