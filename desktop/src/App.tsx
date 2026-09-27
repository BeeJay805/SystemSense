import { useEffect, useRef, useState } from "react";
import { Icon } from "./Icon";
import { CaseDetails } from "./CaseDetails";
import type { Case, Capabilities, DesktopAPI } from "./types";
import {
  caseHeading,
  elapsed,
  isActive,
  label,
  probeLabel,
  readiness,
} from "./presentation";

const errorText = (error: unknown) =>
  error instanceof Error
    ? error.message.replace(
        /^Error invoking remote method '[^']+': Error: /,
        "",
      )
    : "The request could not finish.";
const remember = (key: string, value: string) => {
  try {
    localStorage.setItem(key, value);
  } catch {
    /* Persistence of cases belongs to the backend. */
  }
};
const recalled = (key: string) => {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
};

export function App({ api = window.systemsense }: { api?: DesktopAPI }) {
  const [caps, setCaps] = useState<Capabilities>();
  const [connected, setConnected] = useState(false);
  const [objective, setObjective] = useState("");
  const [selected, setSelected] = useState<Case>();
  const selectedId = useRef<string | undefined>(undefined);
  const generation = useRef(0);
  const [history, setHistory] = useState<Case[]>([]);
  const [historyOpen, setHistoryOpen] = useState(false);
  const [review, setReview] = useState(false);
  const [details, setDetails] = useState(false);
  const [busy, setBusy] = useState(false);
  const busyRef = useRef(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [now, setNow] = useState(Date.now());
  const [connecting, setConnecting] = useState(true);
  const [stopRequested, setStopRequested] = useState<string>();
  const historyDialog = useRef<HTMLDialogElement>(null);
  const reviewDialog = useRef<HTMLDialogElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  useEffect(() => {
    if (review) reviewDialog.current?.showModal();
  }, [review]);
  useEffect(() => {
    if (historyOpen) historyDialog.current?.showModal();
  }, [historyOpen]);

  function showCase(value: Case) {
    selectedId.current = value.case_id;
    setSelected(value);
    setReview(false);
    if (value.case_id) remember("selectedCase", value.case_id);
    if (!isActive(value.status)) setStopRequested(undefined);
  }
  async function connect() {
    if (!api) {
      setConnecting(false);
      setError(
        "Open the SystemSense desktop app to connect to the local investigator.",
      );
      return;
    }
    setConnecting(true);
    try {
      const next = await api.capabilities();
      const saved = await api.listCases();
      setCaps(next);
      setHistory(saved.cases);
      setConnected(true);
      setError("");
      setStopRequested(undefined);
      const id =
        next.active_case_id ??
        selectedId.current ??
        (recalled("selectedCase") === "landing"
          ? undefined
          : recalled("selectedCase") || saved.cases[0]?.case_id);
      if (id && saved.cases.some((item) => item.case_id === id)) {
        generation.current++;
        showCase(await api.getCase(id));
      }
    } catch (error) {
      setConnected(false);
      setError(errorText(error));
    } finally {
      setConnecting(false);
    }
  }
  useEffect(() => {
    let disposed = false;
    async function initialize() {
      if (!api) {
        await connect();
        return;
      }
      for (let attempt = 0; attempt < 12 && !disposed; attempt++) {
        try {
          await api.capabilities();
          if (!disposed) await connect();
          return;
        } catch {
          await new Promise((resolve) => setTimeout(resolve, 700));
        }
      }
      if (!disposed) await connect();
    }
    void initialize();
    return () => {
      disposed = true;
    };
    // api is fixed for the lifetime of the window.
  }, [api]);
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);
  useEffect(() => {
    if (!connected || !api) return;
    let disposed = false;
    let timer: ReturnType<typeof setTimeout>;
    async function poll() {
      if (busyRef.current) {
        timer = setTimeout(poll, 1500);
        return;
      }
      const token = generation.current;
      const id = selectedId.current;
      try {
        const nextCaps = await api!.capabilities();
        const saved = await api!.listCases();
        const value = id ? await api!.getCase(id) : undefined;
        if (disposed || token !== generation.current) return;
        setCaps(nextCaps);
        setHistory(saved.cases);
        if (value) setSelected(value);
      } catch (error) {
        if (!disposed) {
          setConnected(false);
          setError(errorText(error));
        }
      } finally {
        if (!disposed) timer = setTimeout(poll, 1500);
      }
    }
    timer = setTimeout(poll, 1000);
    return () => {
      disposed = true;
      clearTimeout(timer);
    };
  }, [api, connected]);

  const activeId =
    caps?.active_case_id ??
    history.find((item) => isActive(item.status))?.case_id;
  const active = !!activeId;
  async function action(operation: () => Promise<Case | void>) {
    if (busyRef.current || !connected) return;
    busyRef.current = true;
    setBusy(true);
    setError("");
    setNotice("");
    generation.current++;
    try {
      const value = await operation();
      if (value) showCase(value);
      if (api) {
        setCaps(await api.capabilities());
        setHistory((await api.listCases()).cases);
      }
    } catch (error) {
      setError(errorText(error));
      setConnected(false);
      setReview(false);
    } finally {
      generation.current++;
      busyRef.current = false;
      setBusy(false);
    }
  }
  async function openCase(id: string) {
    if (!api) return;
    setHistoryOpen(false);
    setDetails(false);
    await action(async () => api.getCase(id));
  }
  async function preflight(event: React.FormEvent) {
    event.preventDefault();
    if (!objective.trim() || active || !api) return;
    await action(async () => {
      const value = await api.capabilities();
      setCaps(value);
      if (value.active_case_id) {
        showCase(await api.getCase(value.active_case_id));
        return;
      }
      setReview(true);
    });
  }

  function newInvestigation() {
    if (active || busy) return;
    generation.current++;
    selectedId.current = undefined;
    setSelected(undefined);
    setDetails(false);
    setReview(false);
    setObjective("");
    setNotice("");
    remember("selectedCase", "landing");
    requestAnimationFrame(() => inputRef.current?.focus());
  }
  const ready = caps ? readiness(objective, caps) : undefined;
  const shown =
    selected && stopRequested === selected.case_id
      ? { ...selected, cancellation_requested: true }
      : selected;
  const state = shown ? caseHeading(shown) : undefined;
  const selectedActive = !!shown && isActive(shown.status);
  const spinning = selectedActive && shown?.status !== "awaiting_target";
  const observations = shown?.evidence ?? [];
  const limited =
    !!shown &&
    (!!shown.coverage?.some(
      (item) =>
        !["ok", "complete", "completed", "succeeded", "not_collected"].includes(
          item.status,
        ),
    ) ||
      !!shown.measurement_gaps?.length ||
      !!shown.warnings?.length ||
      shown.retrieval?.truncated ||
      shown.evidence_view_truncated);
  return (
    <div className="app-shell">
      <header className="topbar">
        <span className="wordmark">SystemSense</span>
        <nav aria-label="Application">
          {shown &&
            !active &&
            ["cancelled", "interrupted", "failed"].includes(shown.status) && (
              <button
                className="icon-button"
                aria-label="New investigation"
                title="New investigation"
                disabled={busy}
                onClick={newInvestigation}
              >
                <Icon name="plus" />
              </button>
            )}
          <button
            className="icon-button"
            aria-label="Saved investigations"
            title="Saved investigations"
            onClick={() => setHistoryOpen(true)}
            aria-haspopup="dialog"
          >
            <Icon name="history" />
          </button>
        </nav>
      </header>
      <main className={shown ? "case-view" : "landing"}>
        {error && (
          <div className="alert" role="alert">
            <strong>We couldn’t finish that action.</strong>
            <p>{error}</p>
            <button
              className="text-button"
              onClick={() => void connect()}
              disabled={connecting}
            >
              {connecting ? "Connecting…" : "Reconnect"}
            </button>
          </div>
        )}
        {notice && (
          <p className="notice" role="status">
            {notice}
          </p>
        )}
        {!shown ? (
          <section className="landing-content" aria-labelledby="intake-heading">
            <h1 id="intake-heading">What’s not working?</h1>
            <form onSubmit={(event) => void preflight(event)}>
              <label className="sr-only" htmlFor="objective">
                Describe the problem
              </label>
              <div className="input-shell">
                <textarea
                  ref={inputRef}
                  id="objective"
                  placeholder="My game keeps freezing…"
                  rows={3}
                  maxLength={2000}
                  value={objective}
                  onChange={(event) => {
                    setObjective(event.target.value);
                    setReview(false);
                  }}
                  disabled={active || busy}
                  onKeyDown={(event) => {
                    if (
                      event.key === "Enter" &&
                      (event.ctrlKey || event.metaKey)
                    ) {
                      event.preventDefault();
                      event.currentTarget.form?.requestSubmit();
                    }
                  }}
                />
                <button
                  className="send-button"
                  aria-label="Investigate"
                  title="Investigate (Ctrl+Enter)"
                  type="submit"
                  disabled={!connected || busy || active || !objective.trim()}
                >
                  <Icon name="send" />
                </button>
              </div>
            </form>
            {connecting && (
              <p className="connection-note" role="status">
                Connecting…
              </p>
            )}
            {active && (
              <button
                className="text-button"
                onClick={() => void openCase(activeId!)}
              >
                Return to active investigation
              </button>
            )}
          </section>
        ) : (
          state && (
            <>
              <section className="problem-heading">
                <h1>{shown.objective}</h1>
                <p>
                  {selectedActive
                    ? shown.status === "awaiting_target"
                      ? "Waiting for your selection"
                      : stopRequested === shown.case_id
                        ? "Stopping…"
                        : "Investigating…"
                    : shown.status === "cancelled"
                      ? "Stopped"
                      : shown.status === "failed"
                        ? "Could not finish"
                        : shown.status === "interrupted"
                          ? "Interrupted"
                          : "Investigation finished"}
                  <span className="elapsed">{elapsed(shown, now)}</span>
                </p>
              </section>
              <section
                className="card investigation"
                aria-labelledby="case-heading"
              >
                <div className="case-top">
                  <span
                    className={`status-mark ${spinning ? "working" : ""}`}
                    aria-hidden="true"
                  >
                    {spinning ? "" : "···"}
                  </span>
                  <div>
                    <h2 id="case-heading" aria-live="polite">
                      {state.title}
                    </h2>
                    <p>
                      {shown.assessment?.disposition?.startsWith(
                        "supported_observed",
                      )
                        ? shown.assessment.explanation
                        : state.detail}
                    </p>
                    {shown.assessment?.disposition?.startsWith(
                      "supported_observed",
                    ) && <p className="muted">{state.detail}</p>}
                  </div>
                </div>
                <div className="activity-preview" aria-label="Recent evidence">
                  {observations.length ? (
                    observations.slice(-3).map((item, i) => (
                      <div className="activity-row" key={item.evidence_id ?? i}>
                        <span
                          className={`evidence-dot ${item.status === "observed" ? "" : "limited"}`}
                          aria-hidden="true"
                        />
                        <div className="row-copy">
                          <strong>
                            {probeLabel(item.probe_id ?? "Observation")}
                          </strong>
                          <p title={item.summary}>
                            {item.summary ?? "Observation recorded"}
                          </p>
                        </div>
                        <span className="row-status">
                          {label(item.status ?? "recorded")}
                        </span>
                      </div>
                    ))
                  ) : (
                    <p className="empty">
                      {selectedActive
                        ? "Waiting for the first observations."
                        : "No observations were reported."}
                    </p>
                  )}
                  {selectedActive &&
                    shown.pending_probe_ids?.slice(0, 2).map((id) => (
                      <div className="activity-row" key={`pending-${id}`}>
                        <span className="evidence-dot" aria-hidden="true" />
                        <div className="row-copy">
                          <strong>{probeLabel(id)}</strong>
                        </div>
                        <span className="row-status">Pending</span>
                      </div>
                    ))}
                </div>
                {limited && (
                  <p className="coverage-note">
                    Some evidence is limited or unavailable
                    <span className="muted">. See investigation details.</span>
                  </p>
                )}
                {shown.status === "awaiting_target" && (
                  <section className="target-panel">
                    <h3>Which app were you using?</h3>
                    <p>Select from the observed snapshot.</p>
                    {shown.process_target_inventory?.unavailable_reason && (
                      <p role="alert">
                        {shown.process_target_inventory.unavailable_reason}
                      </p>
                    )}
                    {(shown.process_target_inventory?.candidates ?? []).map(
                      (candidate) => (
                        <button
                          className="target"
                          disabled={busy || !connected}
                          key={candidate.candidate_id}
                          onClick={() =>
                            void action(() =>
                              api!.selectTarget({
                                caseId: shown.case_id!,
                                candidateId: candidate.candidate_id,
                              }),
                            )
                          }
                        >
                          <span>
                            {candidate.name}
                            <small>
                              Process {candidate.pid} · started{" "}
                              {new Date(
                                candidate.creation_time,
                              ).toLocaleString()}
                            </small>
                          </span>
                          <span>Choose →</span>
                        </button>
                      ),
                    )}
                    {!shown.process_target_inventory?.candidates?.length && (
                      <p>
                        No selectable process was reported. Stop and try again
                        with the app open.
                      </p>
                    )}
                    <p className="muted">
                      {shown.process_target_inventory?.omitted_process_count ??
                        0}{" "}
                      processes omitted.{" "}
                      {shown.process_target_inventory?.inventory_complete
                        ? "Inventory reported complete."
                        : "Inventory may be incomplete."}
                    </p>
                  </section>
                )}
                <div className="card-footer">
                  <button
                    className={`text-button detail-toggle ${details ? "expanded" : ""}`}
                    aria-expanded={details}
                    aria-controls="investigation-details"
                    onClick={() => setDetails(!details)}
                  >
                    <Icon name="chevron" />
                    {details ? "Hide details" : "Show details"}
                  </button>
                  {selectedActive ? (
                    <button
                      className="secondary stop"
                      aria-label="Stop investigation"
                      disabled={
                        busy || !connected || stopRequested === shown.case_id
                      }
                      onClick={() => {
                        setStopRequested(shown.case_id);
                        void action(() => api!.cancel(shown.case_id!));
                      }}
                    >
                      <span aria-hidden="true">■</span>
                      {stopRequested === shown.case_id ? "Stopping…" : "Stop"}
                    </button>
                  ) : ["cancelled", "interrupted", "failed"].includes(
                      shown.status,
                    ) ? (
                    <button
                      className="secondary"
                      disabled={busy || !connected || active}
                      onClick={() =>
                        void action(() => api!.resume(shown.case_id!))
                      }
                    >
                      Continue investigation
                    </button>
                  ) : (
                    <button
                      className="secondary"
                      disabled={busy || active}
                      onClick={newInvestigation}
                    >
                      New investigation
                    </button>
                  )}
                </div>
                {details && (
                  <CaseDetails
                    value={shown}
                    disabled={!connected || busy}
                    onExport={() =>
                      void action(async () => {
                        const result = await api!.exportCase(shown.case_id!);
                        setNotice(
                          result.saved
                            ? "Evidence report saved."
                            : "Export cancelled.",
                        );
                      })
                    }
                  />
                )}
              </section>
            </>
          )
        )}
      </main>
      {review && (
        <dialog
          ref={reviewDialog}
          className="review-dialog"
          aria-labelledby="ready-heading"
          onCancel={() => setReview(false)}
        >
          <div className="dialog-heading">
            <h2 id="ready-heading">Before this investigation</h2>
            <button
              className="icon-button"
              aria-label="Close readiness"
              title="Edit problem"
              onClick={() => setReview(false)}
            >
              <Icon name="close" />
            </button>
          </div>
          <p className="review-problem">{objective.trim()}</p>
          <p>
            Reads registered Windows information such as running apps, resource
            use, device status and network configuration. Evidence is saved on
            this computer.
          </p>
          <div className="access-notes">
            <h3>Access is not yet verified</h3>
            <p>
              Restricted or missing information will be shown in the results.
            </p>
            {ready?.browserMissing && (
              <>
                <h3>Open-page browser access is unavailable</h3>
                <p>
                  Local configuration checks can run, but cannot inspect or
                  verify your open page.
                </p>
              </>
            )}
            {ready?.needsTarget && (
              <>
                <h3>App selection may be needed</h3>
                <p>
                  After collecting a running-app snapshot, the investigator may
                  ask you to select the exact process.
                </p>
              </>
            )}
          </div>
          {!ready?.canStart && (
            <p role="alert">
              No usable read-only check catalog was reported. Reconnect before
              starting.
            </p>
          )}
          <div className="dialog-actions">
            <button className="quiet" onClick={() => setReview(false)}>
              Edit problem
            </button>
            <button
              className="primary"
              disabled={busy || !ready?.canStart || !connected || active}
              onClick={() => void action(() => api!.start({ objective }))}
            >
              {ready?.browserMissing
                ? "Investigate with these limits"
                : "Start investigation"}
            </button>
          </div>
        </dialog>
      )}
      {historyOpen && (
        <dialog
          ref={historyDialog}
          className="history-dialog"
          aria-labelledby="history-title"
          onCancel={() => setHistoryOpen(false)}
        >
          <div className="dialog-heading">
            <h2 id="history-title">Saved investigations</h2>
            <button
              autoFocus
              className="icon-button"
              aria-label="Close history"
              title="Close history"
              onClick={() => setHistoryOpen(false)}
            >
              <Icon name="close" />
            </button>
          </div>
          <p>Opening a saved case does not start it again.</p>
          {history.length ? (
            history.map((item) => (
              <button
                className="history-item"
                disabled={busy || !connected}
                key={item.case_id}
                onClick={() => void openCase(item.case_id!)}
              >
                <strong>{item.objective}</strong>
                <span>
                  {label(item.status)} ·{" "}
                  {item.created_at
                    ? new Date(item.created_at).toLocaleDateString()
                    : "Date unavailable"}
                </span>
              </button>
            ))
          ) : (
            <p>No saved investigations yet.</p>
          )}
          <div className="history-footer">
            <button
              className="quiet"
              onClick={() => {
                setNotice("Stopping and saving before closing…");
                void api?.quit();
              }}
            >
              Quit SystemSense
            </button>
          </div>
        </dialog>
      )}
    </div>
  );
}
