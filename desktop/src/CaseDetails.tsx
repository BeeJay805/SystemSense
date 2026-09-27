import { useState } from "react";
import type { Case, Evidence } from "./types";
import { label, probeLabel } from "./presentation";
export function CaseDetails({
  value,
  onExport,
  disabled,
}: {
  value: Case;
  onExport: () => void;
  disabled: boolean;
}) {
  const [tab, setTab] = useState("observations");
  const tabs = ["observations", "coverage", "reasoning", "activity"];
  return (
    <div className="detail-panel" id="investigation-details">
      <div className="tabs" role="tablist" aria-label="Investigation details">
        {tabs.map((name, index) => (
          <button
            key={name}
            role="tab"
            id={`tab-${name}`}
            aria-controls="detail-content"
            tabIndex={tab === name ? 0 : -1}
            aria-selected={tab === name}
            onClick={() => setTab(name)}
            onKeyDown={(event) => {
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
                setTab(tabs[next]);
                document.getElementById(`tab-${tabs[next]}`)?.focus();
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
          ((value.evidence?.length ?? 0) > 0 ? (
            value.evidence!.map((item, i) => (
              <EvidenceCard key={item.evidence_id ?? i} item={item} />
            ))
          ) : (
            <p>No evidence was reported.</p>
          ))}
        {tab === "coverage" && (
          <>
            <p>
              Not collected, denied and unavailable checks are not healthy
              checks.
            </p>
            {value.warnings?.map((note, i) => (
              <p className="limitation" key={i}>
                {note}
              </p>
            ))}
            {value.measurement_gaps?.map((item, i) => (
              <p className="limitation" key={i}>
                {item.reason}
              </p>
            ))}
            {(value.coverage ?? []).map((item) => (
              <article className="detail-item" key={item.probe_id}>
                <h3>
                  {probeLabel(item.probe_id)}{" "}
                  <span className="badge">{label(item.status)}</span>
                </h3>
                <p>{item.reason ?? item.summary}</p>
              </article>
            ))}
            {!value.coverage?.length && <p>Coverage has not been reported.</p>}
            {(value.retrieval?.truncated || value.evidence_view_truncated) && (
              <p>This bounded view omits some evidence.</p>
            )}
          </>
        )}
        {tab === "reasoning" && (
          <>
            <h3>Interpretation, not proof</h3>
            <p>{value.summary ?? "No interpretation reported."}</p>
            {value.assessment?.limitations?.map((note, i) => (
              <p className="limitation" key={i}>
                {note}
              </p>
            ))}
            {value.hypotheses?.map((item, i) => (
              <article className="detail-item" key={i}>
                <strong>
                  {item.statement ?? item.summary ?? "Advisory explanation"}
                </strong>
                <p>
                  Advisory status: {label(item.status ?? "unresolved")}. A model
                  label is not a verified cause.
                </p>
                <p className="mono">
                  Supporting evidence:{" "}
                  {item.supporting_evidence_ids?.join(", ") || "None reported"}
                </p>
                <p className="mono">
                  Counterevidence:{" "}
                  {item.contradicting_evidence_ids?.join(", ") ||
                    "None reported"}
                </p>
              </article>
            ))}
          </>
        )}
        {tab === "activity" && (
          <>
            {value.timeline?.map((item, i) => (
              <article className="detail-item" key={i}>
                <strong>{label(item.event ?? "Recorded event")}</strong>
                <p>{item.detail}</p>
                <small>
                  {item.occurred_at ??
                    item.created_at ??
                    "Timestamp not reported"}
                </small>
              </article>
            ))}
            {!value.timeline?.length && (
              <p>No activity events were reported.</p>
            )}
            <p className="mono">
              Case: {value.case_id}
              <br />
              Outcome: {value.outcome ?? "not reported"}
              <br />
              Stop reason: {value.stop_reason ?? "not reported"}
            </p>
          </>
        )}
      </div>
      <div className="detail-footer">
        <button className="text-button" disabled={disabled} onClick={onExport}>
          Export evidence
        </button>
      </div>
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
        <p className="limitation" key={i}>
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
