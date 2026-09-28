import { useEffect, useRef } from "react";
import { Icon } from "./Icon";

export function Settings({ onClose }: { onClose: () => void }) {
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    dialog.current?.showModal();
  }, []);
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
      <div className="settings-content" />
    </dialog>
  );
}
