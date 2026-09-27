import { useEffect, useRef, useState } from "react";
import type { Case, Capabilities, DesktopAPI, Evidence } from "./types";
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
  const [onboarding, setOnboarding] = useState(recalled("welcomed") !== "yes");
  const [connectionInfo, setConnectionInfo] = useState(false);
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
  const [tab, setTab] = useState("observations");
  const [busy, setBusy] = useState(false);
  const busyRef = useRef(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [now, setNow] = useState(Date.now());
  const [connecting, setConnecting] = useState(true);
  const [stopRequested, setStopRequested] = useState<string>();
  const headingRef = useRef<HTMLHeadingElement>(null);
  const historyDialog = useRef<HTMLDialogElement>(null);
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
        recalled("selectedCase") ??
        saved.cases[0]?.case_id;
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
  function finishOnboarding() {
    remember("welcomed", "yes");
    setOnboarding(false);
  }
  const ready = caps ? readiness(objective, caps) : undefined;
  const shown =
    selected && stopRequested === selected.case_id
      ? { ...selected, cancellation_requested: true }
      : selected;
  const state = shown ? caseHeading(shown) : undefined;
  const selectedActive = shown && isActive(shown.status);
  const observations = shown?.evidence ?? [];
  const gaps = (shown?.coverage ?? []).filter(
    (item) =>
      !["ok", "complete", "completed", "succeeded", "not_collected"].includes(
        item.status,
      ),
  );

  return (
    <div className="app-shell">
      <header className="topbar">
        <span className="wordmark">SystemSense</span>
        <nav aria-label="Application">
          <button
            className="quiet"
            onClick={() => setHistoryOpen(!historyOpen)}
            aria-expanded={historyOpen}
          >
            Saved investigations <span className="count">{history.length}</span>
          </button>
          <button
            className="quiet quit"
            onClick={() => {
              setNotice("Stopping and saving before closing…");
              void api?.quit();
            }}
          >
            Quit
          </button>
        </nav>
      </header>
      <main>
        <div className="connection">
          <span className={`dot ${connected ? "live" : ""}`} />
          {connecting
            ? "Connecting to your computer…"
            : connected
              ? "On this computer · Read-only"
              : "Connection needs checking"}
          {!connected && !connecting && (
            <button className="text-button" onClick={() => void connect()}>
              Reconnect
            </button>
          )}
        </div>
        {error && (
          <div className="alert" role="alert">
            <strong>We couldn’t complete that request.</strong>
            <p>{error}</p>
            <p>
              Saved evidence stays on this computer. Reconnect to check the
              latest case state before trying again.
            </p>
          </div>
        )}
        {notice && (
          <p className="notice" role="status">
            {notice}
          </p>
        )}
        {onboarding ? (
          <section className="welcome card">
            <span className="eyebrow">A clearer picture of your computer</span>
            <h1>
              Let’s find out
              <br />
              what’s happening.
            </h1>
            <p>
              Describe the problem in your own words. SystemSense gathers
              evidence and shows what it can, and can’t, establish.
            </p>
            <div className="privacy-note">
              <strong>You stay in control.</strong>
              <p>
                Investigation reads registered Windows information such as
                running apps, resource use, device status and network
                configuration. It saves evidence locally. It does not change
                your settings or other files.
              </p>
              <p>
                This build uses local evidence checks. AI diagnosis and repairs
                are not enabled.
              </p>
            </div>
            <button
              className="text-button"
              onClick={() => setConnectionInfo(!connectionInfo)}
              aria-expanded={connectionInfo}
            >
              About browser connection <span aria-hidden="true">↗</span>
            </button>
            {connectionInfo && (
              <div className="soft-panel">
                <strong>Browser connection isn’t available yet</strong>
                <p>
                  There is no extension to install in this build. Existing
                  Windows and browser configuration checks may still help, but
                  they cannot inspect your open page or prove that it works.
                </p>
              </div>
            )}
            <div className="actions">
              <button className="primary" onClick={finishOnboarding}>
                Get started
              </button>
              <button className="quiet" onClick={finishOnboarding}>
                Do this later
              </button>
            </div>
          </section>
        ) : (
          <>
            <section className="intake" aria-labelledby="intake-heading">
              <h1 id="intake-heading">What’s not working?</h1>
              <p className="lead">
                Tell us what happened and which app you were using.
              </p>
              <form onSubmit={(event) => void preflight(event)}>
                <label className="sr-only" htmlFor="objective">
                  Describe the problem
                </label>
                <div className={`input-shell ${active ? "inactive" : ""}`}>
                  <textarea
                    id="objective"
                    placeholder="For example, Chrome says pages can’t be reached."
                    rows={2}
                    maxLength={2000}
                    value={objective}
                    onChange={(event) => {
                      setObjective(event.target.value);
                      setReview(false);
                    }}
                    disabled={active || busy}
                  />
                  <button
                    className="primary investigate"
                    disabled={!connected || busy || active || !objective.trim()}
                    type="submit"
                  >
                    {busy ? "Please wait…" : "Investigate"}{" "}
                    <span aria-hidden="true">→</span>
                  </button>
                </div>
              </form>
              <p className="assurance">
                <span aria-hidden="true">◇</span> Investigation doesn’t change
                your settings or files. Evidence is saved locally.
              </p>
              {active && (
                <p className="active-note">
                  One investigation at a time. Your draft will wait.
                  {activeId !== selected?.case_id && (
                    <button
                      className="text-button"
                      onClick={() => void openCase(activeId!)}
                    >
                      Return to active investigation
                    </button>
                  )}
                </p>
              )}
            </section>
            {review && (
              <section
                className="card readiness"
                aria-labelledby="ready-heading"
              >
                <span className="eyebrow">Before we begin</span>
                <h2 id="ready-heading">Here’s what can be checked</h2>
                <p>“{objective.trim()}”</p>
                <ul className="readiness-list">
                  <li>
                    <span className="dot live" />
                    <div>
                      <strong>
                        {ready?.canStart
                          ? "Local evidence checks are available"
                          : "Local checks could not be verified"}
                      </strong>
                      <p>
                        {caps?.probes?.length ?? 0} registered checks. Only
                        checks chosen by the investigator run.
                      </p>
                    </div>
                  </li>
                  <li>
                    <span className="dot amber" />
                    <div>
                      <strong>Access is not yet verified</strong>
                      <p>
                        Some Windows information may be restricted. Missing or
                        denied access will remain visible in your results.
                      </p>
                    </div>
                  </li>
                  {ready?.browserMissing && (
                    <li>
                      <span className="dot amber" />
                      <div>
                        <strong>Open-page browser access is unavailable</strong>
                        <p>
                          No browser extension is connected. This investigation
                          is limited to the registered local checks; it cannot
                          verify the page you are using.
                        </p>
                      </div>
                    </li>
                  )}
                  {ready?.needsTarget && (
                    <li>
                      <span className="dot amber" />
                      <div>
                        <strong>App selection may be needed</strong>
                        <p>
                          The engine may need to collect a running-app snapshot
                          first, then ask you to choose the exact process.
                          Evidence will be saved while it waits.
                        </p>
                      </div>
                    </li>
                  )}
                </ul>
                <p className="muted">
                  Checks may read system configuration, running apps, device
                  information and connection metadata. No repairs or AI model
                  calls are enabled in this desktop build.
                </p>
                {!ready?.canStart && (
                  <p role="alert">
                    No usable read-only check catalog was reported. Reconnect
                    before starting.
                  </p>
                )}
                <div className="actions">
                  <button
                    className="primary"
                    disabled={busy || !ready?.canStart || !connected || active}
                    onClick={() =>
                      void action(async () => api!.start({ objective }))
                    }
                  >
                    {ready?.browserMissing
                      ? "Investigate with these limits"
                      : "Start investigation"}
                  </button>
                  <button className="quiet" onClick={() => setReview(false)}>
                    Edit problem
                  </button>
                </div>
              </section>
            )}
            {!review && shown && state && (
              <section
                className="card investigation"
                aria-labelledby="case-heading"
              >
                <div className="case-top">
                  <span
                    className={`status-mark ${selectedActive && shown.status !== "awaiting_target" ? "working" : ""}`}
                    aria-hidden="true"
                  >
                    {selectedActive
                      ? ""
                      : shown.assessment?.disposition?.startsWith(
                            "supported_observed",
                          )
                        ? "✓"
                        : "·"}
                  </span>
                  <div>
                    <span className="eyebrow">
                      {selectedActive
                        ? "Current investigation"
                        : "Saved investigation"}
                    </span>
                    <h2
                      id="case-heading"
                      ref={headingRef}
                      tabIndex={-1}
                      aria-live="polite"
                    >
                      {state.title}
                    </h2>
                    <p className="case-description">{state.detail}</p>
                  </div>
                  <span className="elapsed">
                    {elapsed(shown, now)}
                    <small>since case opened</small>
                  </span>
                </div>
                <p className="case-objective">{shown.objective}</p>
                {shown.assessment?.disposition?.startsWith(
                  "supported_observed",
                ) && (
                  <div className="finding">
                    <span className="eyebrow">Supported by observations</span>
                    <p>{shown.assessment.explanation}</p>
                    {shown.assessment.limitations?.map((note, i) => (
                      <p className="muted" key={i}>
                        {note}
                      </p>
                    ))}
                  </div>
                )}
                {shown.status === "awaiting_target" && (
                  <div className="target-panel">
                    <h3>Which app were you using?</h3>
                    <p>
                      Select from the observed snapshot. Matching a name does
                      not identify the cause.
                    </p>
                    {shown.process_target_inventory?.unavailable_reason ? (
                      <p role="alert">
                        {shown.process_target_inventory.unavailable_reason}
                      </p>
                    ) : (
                      (shown.process_target_inventory?.candidates ?? []).map(
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
                      )
                    )}
                    {!shown.process_target_inventory?.candidates?.length && (
                      <p>
                        No selectable process was reported. Stop this
                        investigation and try again with the app open.
                      </p>
                    )}
                    <p className="muted">
                      {shown.process_target_inventory?.omitted_process_count ??
                        0}{" "}
                      processes omitted from this snapshot.{" "}
                      {shown.process_target_inventory?.inventory_complete
                        ? "Inventory reported complete."
                        : "Inventory may be incomplete."}
                    </p>
                  </div>
                )}
                <div className="activity-preview" aria-label="Recent evidence">
                  <div className="section-label">
                    <h3>
                      {observations.length
                        ? "Recent observations"
                        : "Evidence collection"}
                    </h3>
                    <span>
                      {shown.evidence_count ?? observations.length}{" "}
                      {(shown.evidence_count ?? observations.length) === 1
                        ? "record"
                        : "records"}{" "}
                      saved
                    </span>
                  </div>
                  {observations.length ? (
                    observations.slice(-3).map((item, i) => (
                      <div className="activity-row" key={item.evidence_id ?? i}>
                        <span
                          className={`dot ${item.status === "observed" ? "live" : "amber"}`}
                        />
                        <div>
                          <strong>
                            {probeLabel(item.probe_id ?? "Observation")}
                          </strong>
                          <p>
                            {item.summary ??
                              "An observation was recorded. Open details to inspect it."}
                          </p>
                        </div>
                        <span className="badge">
                          {label(item.status ?? "recorded")}
                        </span>
                      </div>
                    ))
                  ) : (
                    <p className="empty">
                      No observations reported yet. An empty result does not
                      establish that your computer is healthy.
                    </p>
                  )}
                </div>
                {!!shown.pending_probe_ids?.length && selectedActive && (
                  <p className="muted">
                    Pending:{" "}
                    {shown.pending_probe_ids.map(probeLabel).join(", ")}
                  </p>
                )}
                {(gaps.length > 0 ||
                  shown.measurement_gaps?.length ||
                  shown.warnings?.length ||
                  shown.retrieval?.truncated ||
                  shown.evidence_view_truncated) && (
                  <div className="coverage-note">
                    <strong>Some evidence is limited or unavailable</strong>
                    <p>
                      {gaps.length
                        ? `${gaps.length} checks reported a gap. `
                        : ""}
                      {shown.retrieval?.truncated ||
                      shown.evidence_view_truncated
                        ? "This is a bounded view; some evidence is omitted. "
                        : ""}
                      Open investigation details for missing access, coverage
                      and limitations.
                    </p>
                  </div>
                )}
                <div className="card-footer">
                  <button
                    className="text-button"
                    aria-expanded={details}
                    aria-controls="investigation-details"
                    onClick={() => setDetails(!details)}
                  >
                    {details
                      ? "Hide investigation details"
                      : "Investigation details"}{" "}
                    <span aria-hidden="true">{details ? "⌃" : "⌄"}</span>
                  </button>
                  {selectedActive ? (
                    <button
                      className="secondary"
                      disabled={
                        busy || !connected || stopRequested === shown.case_id
                      }
                      onClick={() => {
                        setStopRequested(shown.case_id);
                        void action(() => api!.cancel(shown.case_id!));
                      }}
                    >
                      ■{" "}
                      {stopRequested === shown.case_id
                        ? "Stopping…"
                        : "Stop investigation"}
                    </button>
                  ) : (
                    <div className="actions compact">
                      {["cancelled", "interrupted", "failed"].includes(
                        shown.status,
                      ) && (
                        <button
                          className="secondary"
                          disabled={busy || !connected || active}
                          onClick={() =>
                            void action(() => api!.resume(shown.case_id!))
                          }
                        >
                          Continue investigation
                        </button>
                      )}
                      <button
                        className="quiet"
                        disabled={!connected || busy}
                        onClick={() =>
                          void action(async () => {
                            const result = await api!.exportCase(
                              shown.case_id!,
                            );
                            setNotice(
                              result.saved
                                ? "Evidence report saved."
                                : "Export cancelled.",
                            );
                          })
                        }
                      >
                        Export evidence
                      </button>
                    </div>
                  )}
                </div>
                {details && (
                  <div id="investigation-details" className="detail-panel">
                    <div
                      className="tabs"
                      role="tablist"
                      aria-label="Investigation details"
                    >
                      {[
                        "observations",
                        "coverage",
                        "reasoning",
                        "activity",
                      ].map((name) => (
                        <button
                          key={name}
                          role="tab"
                          id={`tab-${name}`}
                          aria-controls="detail-content"
                          tabIndex={tab === name ? 0 : -1}
                          aria-selected={tab === name}
                          onClick={() => setTab(name)}
                          onKeyDown={(event) => {
                            const names = [
                              "observations",
                              "coverage",
                              "reasoning",
                              "activity",
                            ];
                            const index = names.indexOf(name);
                            const next =
                              event.key === "ArrowRight"
                                ? (index + 1) % 4
                                : event.key === "ArrowLeft"
                                  ? (index + 3) % 4
                                  : event.key === "Home"
                                    ? 0
                                    : event.key === "End"
                                      ? 3
                                      : -1;
                            if (next >= 0) {
                              event.preventDefault();
                              setTab(names[next]);
                              document
                                .getElementById(`tab-${names[next]}`)
                                ?.focus();
                            }
                          }}
                        >
                          {name === "reasoning"
                            ? "Interpretation"
                            : name[0].toUpperCase() + name.slice(1)}
                        </button>
                      ))}
                    </div>
                    <div
                      role="tabpanel"
                      id="detail-content"
                      aria-labelledby={`tab-${tab}`}
                      tabIndex={0}
                    >
                      {tab === "observations" &&
                        (observations.length ? (
                          observations.map((item, i) => (
                            <EvidenceCard
                              key={item.evidence_id ?? i}
                              item={item}
                            />
                          ))
                        ) : (
                          <p>No evidence was reported.</p>
                        ))}
                      {tab === "coverage" && (
                        <>
                          <p>
                            Not collected, denied and unavailable checks are not
                            healthy checks.
                          </p>
                          {shown.warnings?.map((item, i) => (
                            <p className="coverage-note" key={i}>
                              {item}
                            </p>
                          ))}
                          {shown.measurement_gaps?.map((item, i) => (
                            <p className="coverage-note" key={i}>
                              {item.reason}
                            </p>
                          ))}
                          {(shown.coverage ?? []).map((item) => (
                            <article
                              className="detail-item"
                              key={item.probe_id}
                            >
                              <h3>
                                {probeLabel(item.probe_id)}{" "}
                                <span className="badge">
                                  {label(item.status)}
                                </span>
                              </h3>
                              <p>{item.reason ?? item.summary}</p>
                            </article>
                          ))}
                          {!shown.coverage?.length && (
                            <p>Coverage has not been reported.</p>
                          )}
                        </>
                      )}
                      {tab === "reasoning" && (
                        <>
                          <h3>Interpretation, not proof</h3>
                          <p>
                            {shown.summary ?? "No interpretation reported."}
                          </p>
                          {shown.hypotheses?.map((item, i) => (
                            <article className="detail-item" key={i}>
                              <strong>
                                {item.statement ??
                                  item.summary ??
                                  "Advisory explanation"}
                              </strong>
                              <p>
                                Advisory status:{" "}
                                {label(item.status ?? "unresolved")}. A model
                                label is not a verified cause.
                              </p>
                              <p className="mono">
                                Supporting evidence:{" "}
                                {item.supporting_evidence_ids?.join(", ") ||
                                  "None reported"}
                              </p>
                              <p className="mono">
                                Counterevidence:{" "}
                                {item.contradicting_evidence_ids?.join(", ") ||
                                  "None reported"}
                              </p>
                            </article>
                          ))}
                          <p>No repair has been performed.</p>
                        </>
                      )}
                      {tab === "activity" && (
                        <>
                          {shown.timeline?.map((item, i) => (
                            <article className="detail-item" key={i}>
                              <strong>
                                {label(item.event ?? "Recorded event")}
                              </strong>
                              <p>{item.detail}</p>
                              <small>
                                {item.occurred_at ??
                                  item.created_at ??
                                  "Timestamp not reported"}
                              </small>
                            </article>
                          ))}
                          {!shown.timeline?.length && (
                            <p>No activity events were reported.</p>
                          )}
                          <p className="mono">
                            Case: {shown.case_id}
                            <br />
                            Outcome: {shown.outcome ?? "not reported"}
                            <br />
                            Stop reason: {shown.stop_reason ?? "not reported"}
                          </p>
                        </>
                      )}
                    </div>
                  </div>
                )}
              </section>
            )}
            {!review && !shown && (
              <div className="empty-state">
                <span className="empty-rule" />
                <h2>A good investigation starts with what you noticed.</h2>
                <p>
                  Include the app, the action you tried, and what happened
                  instead.
                  <br />
                  You’ll review the available checks before anything starts.
                </p>
              </div>
            )}
          </>
        )}
        <footer>Evidence first. Uncertainty stays visible.</footer>
      </main>
      {historyOpen && (
        <dialog
          ref={historyDialog}
          className="history-drawer"
          aria-labelledby="history-title"
          onCancel={() => setHistoryOpen(false)}
        >
          <div className="section-label">
            <h2 id="history-title">Saved investigations</h2>
            <button
              autoFocus
              className="quiet"
              onClick={() => setHistoryOpen(false)}
            >
              Close
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
            <p className="empty">No saved investigations yet.</p>
          )}
        </dialog>
      )}
    </div>
  );
}

function EvidenceCard({ item }: { item: Evidence }) {
  return (
    <article className="detail-item">
      <h3>
        {probeLabel(item.probe_id ?? "Observation")}{" "}
        <span className="badge">{label(item.status ?? "recorded")}</span>
      </h3>
      <p>{item.summary}</p>
      <p className="muted">
        {item.historical ? "Historical evidence · " : ""}
        {item.statement_kind
          ? label(item.statement_kind)
          : "Statement type not reported"}
      </p>
      <dl>
        <dt>Observed</dt>
        <dd>{item.observed_at ?? "Not reported"}</dd>
        <dt>Captured</dt>
        <dd>{item.captured_at ?? "Not reported"}</dd>
        <dt>Source</dt>
        <dd>{item.source_id ?? item.source_type ?? "Not reported"}</dd>
        <dt>Evidence ID</dt>
        <dd className="mono">{item.evidence_id ?? "Not reported"}</dd>
      </dl>
      {item.limitations?.map((note, i) => (
        <p className="coverage-note" key={i}>
          {note}
        </p>
      ))}
      {item.facts && Object.keys(item.facts).length > 0 && (
        <pre aria-label="Collected facts">
          {JSON.stringify(item.facts, null, 2)}
        </pre>
      )}
    </article>
  );
}
