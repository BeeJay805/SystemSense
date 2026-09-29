import { useEffect, useRef, useState } from "react";
import { Icon } from "./Icon";
import type { Capabilities, DesktopAPI } from "./types";

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
  async function choose(next: Mode) {
    if (!api?.setModelMode || active || busy) return;
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
              busy || active || mode === "deterministic" || !api?.setModelMode
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
              busy || active || mode === "laya-sol" || !api?.setModelMode
            }
            onClick={() => void choose("laya-sol")}
          >
            Use Laya + Sol
          </button>
        </div>
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
