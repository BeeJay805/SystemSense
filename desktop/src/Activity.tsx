import { useEffect, useRef, useState } from "react";
import type { Case } from "./types";
import { activityItems } from "./presentation";

export function Activity({ value }: { value: Case }) {
  const items = activityItems(value);
  const signature = JSON.stringify(items.map((item) => item.id));
  const previous = useRef<{ caseId?: string; ids: Set<string> } | undefined>(
    undefined,
  );
  const [arrivals, setArrivals] = useState<Set<string>>(new Set());
  const [expanded, setExpanded] = useState(false);
  useEffect(() => {
    const ids = JSON.parse(signature) as string[];
    const prior = previous.current;
    // Initial loads and history reopens are not new evidence arrivals.
    const next =
      prior && prior.caseId === value.case_id
        ? ids.filter((id) => !prior.ids.has(id))
        : [];
    previous.current = {
      caseId: value.case_id,
      ids: new Set([
        ...(prior && prior.caseId === value.case_id ? prior.ids : []),
        ...ids,
      ]),
    };
    setArrivals(new Set(next));
    const timer = setTimeout(() => setArrivals(new Set()), 700);
    return () => clearTimeout(timer);
  }, [signature, value.case_id]);
  const visible = expanded ? items : items.slice(-6);
  return (
    <section className="activity-preview" aria-label="Investigation activity">
      <div className="activity-heading">
        <h3>Activity</h3>
        <span>Recorded events & evidence</span>
      </div>
      {items.length ? (
        <ol className="activity-list">
          {visible.map((item) => (
            <li
              className={`activity-event state-${item.state} ${arrivals.has(item.id) ? "event-arrival" : ""}`}
              key={item.id}
              data-event-id={item.id}
            >
              <span className="event-marker" aria-hidden="true" />
              <div className="event-copy">
                <div className="event-heading">
                  <strong>{item.title}</strong>
                  <span className="event-state">{item.state}</span>
                </div>
                {item.detail && <p>{item.detail}</p>}
                <small>
                  {item.at && Number.isFinite(Date.parse(item.at)) ? (
                    <>
                      <span>{item.timeKind} </span>
                      <time dateTime={item.at} title={item.at}>
                        {new Date(item.at).toLocaleString()}
                      </time>
                    </>
                  ) : (
                    "Timestamp not reported"
                  )}
                </small>
              </div>
            </li>
          ))}
        </ol>
      ) : (
        <p className="empty">No activity or evidence has been reported yet.</p>
      )}
      {items.length > 6 && (
        <button
          className="text-button"
          onClick={() => setExpanded(!expanded)}
          aria-expanded={expanded}
        >
          {expanded
            ? "Show recent activity"
            : `Show all ${items.length} reported entries`}
        </button>
      )}
      <p className="activity-footnote">
        Chronological by event or capture time. Undated and pending entries
        follow. This is the reported view, not a complete audit log.
      </p>
    </section>
  );
}
