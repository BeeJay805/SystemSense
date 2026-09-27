import { useEffect, useRef, useState } from "react";
import type { Capabilities, DesktopAPI } from "./types";
import { Icon } from "./Icon";

export type Preferences = {
  motion: "system" | "reduce";
  text: "standard" | "large";
};
const defaults: Preferences = { motion: "system", text: "standard" };
export function usePreferences() {
  const [preferences, setPreferences] = useState<Preferences>(() => {
    try {
      const saved = JSON.parse(
        localStorage.getItem("displayPreferences") ?? "null",
      );
      return {
        motion: saved?.motion === "reduce" ? "reduce" : "system",
        text: saved?.text === "large" ? "large" : "standard",
      };
    } catch {
      return defaults;
    }
  });
  const [storageError, setStorageError] = useState("");
  const [systemReduced, setSystemReduced] = useState(
    () => matchMedia("(prefers-reduced-motion: reduce)").matches,
  );
  useEffect(() => {
    const media = matchMedia("(prefers-reduced-motion: reduce)");
    const update = () => setSystemReduced(media.matches);
    media.addEventListener("change", update);
    return () => media.removeEventListener("change", update);
  }, []);
  const reducedMotion = preferences.motion === "reduce" || systemReduced;
  useEffect(() => {
    document.documentElement.dataset.motion = reducedMotion ? "reduce" : "full";
    document.documentElement.dataset.text = preferences.text;
  }, [reducedMotion, preferences.text]);
  function update(next: Preferences) {
    setPreferences(next);
    try {
      localStorage.setItem("displayPreferences", JSON.stringify(next));
      setStorageError("");
    } catch {
      setStorageError(
        "Applied for this window. Your preference could not be saved.",
      );
    }
  }
  return { preferences, update, reducedMotion, storageError };
}

export function Settings({
  api,
  caps,
  connected,
  preferences,
  update,
  storageError,
  onClose,
}: {
  api?: DesktopAPI;
  caps?: Capabilities;
  connected: boolean;
  preferences: Preferences;
  update: (value: Preferences) => void;
  storageError: string;
  onClose: () => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [info, setInfo] = useState<{ dataLocation: string; version: string }>();
  useEffect(() => {
    dialog.current?.showModal();
    let disposed = false;
    void api
      ?.desktopInfo?.()
      .then((value) => {
        if (!disposed) setInfo(value);
      })
      .catch(() => {});
    return () => {
      disposed = true;
    };
  }, [api]);
  return (
    <dialog
      ref={dialog}
      aria-labelledby="settings-title"
      onCancel={onClose}
      className="settings-dialog"
    >
      <div className="dialog-heading">
        <h2 id="settings-title">Settings</h2>
        <button
          autoFocus
          className="icon-button"
          aria-label="Close settings"
          onClick={onClose}
        >
          <Icon name="close" />
        </button>
      </div>
      <section className="settings-section" aria-labelledby="display-title">
        <h3 id="display-title">Make it comfortable</h3>
        <label className="setting-row">
          <span>
            Motion
            <small>
              Windows reduced-motion preferences are always respected.
            </small>
          </span>
          <select
            value={preferences.motion}
            onChange={(event) =>
              update({
                ...preferences,
                motion: event.target.value as Preferences["motion"],
              })
            }
          >
            <option value="system">Follow Windows</option>
            <option value="reduce">Reduce motion</option>
          </select>
        </label>
        <label className="setting-row">
          <span>
            Text size<small>Make body text and controls easier to read.</small>
          </span>
          <select
            value={preferences.text}
            onChange={(event) =>
              update({
                ...preferences,
                text: event.target.value as Preferences["text"],
              })
            }
          >
            <option value="standard">Standard</option>
            <option value="large">Larger</option>
          </select>
        </label>
        {storageError && <p role="alert">{storageError}</p>}
      </section>
      <section className="settings-section" aria-labelledby="access-title">
        <h3 id="access-title">Capabilities & access</h3>
        <dl className="capability-list">
          <dt>Local investigator</dt>
          <dd>{connected ? "Connected" : "Not connected"}</dd>
          <dt>Collection</dt>
          <dd>
            {connected && caps?.read_only === true
              ? "Read-only"
              : "Not verified"}
          </dd>
          <dt>Registered checks</dt>
          <dd>
            {connected
              ? `${caps?.probes?.length ?? 0} reported`
              : "Unavailable"}
          </dd>
          <dt>Advisory inference</dt>
          <dd>
            {!connected || !caps?.inference
              ? "Not reported"
              : caps.inference.enabled === true
                ? `Enabled${caps.inference.mode ? ` · ${caps.inference.mode}` : ""}`
                : "Not enabled"}
          </dd>
          <dt>Open browser pages</dt>
          <dd>Not connected · no page access</dd>
          <dt>Automatic repairs</dt>
          <dd>Not available in this app</dd>
        </dl>
        <p>
          Registered checks do not guarantee access. Windows restrictions,
          missing data and required app selections appear during the
          investigation. This app cannot grant Windows permissions.
        </p>
      </section>
      <section className="settings-section">
        <h3>On this computer</h3>
        <p>
          Investigations stay in the local case database. Opening History never
          starts collection.
        </p>
        <dl className="capability-list">
          <dt>Case database</dt>
          <dd className="data-location">
            {info?.dataLocation ?? "Location unavailable"}
          </dd>
          <dt>Desktop version</dt>
          <dd>{info?.version ?? "Not reported"}</dd>
        </dl>
      </section>
    </dialog>
  );
}
