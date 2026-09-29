import type { Case, Capabilities } from "./types";
export const isActive = (status: string) =>
  [
    "queued",
    "running",
    "collecting",
    "resuming",
    "cancelling",
    "awaiting_target",
  ].includes(status);
function exactTaskOutcome(value: Case): string | undefined {
  const task = value.evidence?.filter(
    (item) =>
      item.probe_id === "task.loopback_http" && item.status === "observed",
  );
  const outcome = task?.length === 1 ? task[0].facts?.outcome : undefined;
  return typeof outcome === "string" ? outcome : undefined;
}
export function caseHeading(value: Case) {
  if (value.cancellation_requested && isActive(value.status))
    return {
      title: "Stopping investigation",
      detail:
        "Waiting for collection to stop. Evidence already collected is kept.",
    };
  if (value.status === "awaiting_target")
    return {
      title: "Choose the app to continue",
      detail:
        "Your evidence is saved. Select the process you were using below.",
    };
  if (isActive(value.status))
    return {
      title: "Investigating your problem",
      detail: "Checking your computer for clues.",
    };
  if (value.status === "cancelled")
    return {
      title: "Investigation stopped",
      detail:
        "Collected evidence is saved. Stopping does not mean the problem was resolved.",
    };
  if (value.status === "failed")
    return {
      title: "Investigation could not finish",
      detail:
        "Any collected evidence is saved. Review the details before trying again.",
    };
  if (value.status === "interrupted")
    return {
      title: "Investigation was interrupted",
      detail: "Saved evidence was recovered. Continue only when you are ready.",
    };
  if (value.assessment?.disposition === "supported_observed_finding")
    return {
      title: "An observed finding",
      detail:
        "This finding is supported by observations. The underlying cause is still unresolved.",
    };
  if (value.assessment?.disposition === "supported_observed_explanation")
    return {
      title: "An observed answer",
      detail:
        "The evidence supports this specific answer. It does not establish the root cause.",
    };
  const taskOutcome = exactTaskOutcome(value);
  if (value.status === "complete" && taskOutcome === "http_200_nonce_match")
    return {
      title: "This check worked",
      detail:
        "The exact local health request succeeded once. An earlier or intermittent failure remains unverified.",
    };
  if (value.status === "complete" && taskOutcome)
    return {
      title: "A failure was observed",
      detail:
        "The exact local health request did not meet its expected result. The underlying cause is still unresolved.",
    };
  if (value.outcome === "awaiting_recurrence")
    return {
      title: "Waiting for the problem to recur",
      detail:
        "This run has ended. Start a new investigation while the problem is happening.",
    };
  return {
    title: "No supported answer yet",
    detail:
      "The available evidence is inconclusive. This does not mean everything is working.",
  };
}
export function readiness(objective: string, cap: Capabilities) {
  const modelBlocked =
    cap.inference?.mode === "laya-sol" && cap.inference.start_allowed === false;
  return {
    canStart:
      (cap.probes?.length ?? 0) > 0 && cap.read_only === true && !modelBlocked,
    modelBlocked,
    browserMissing: /browser|chrome|edge|firefox|website|web page|safari/i.test(
      objective,
    ),
    needsTarget: /app|game|pdf|process|program/i.test(objective),
  };
}
export function elapsed(value: Case, now: number) {
  const start = Date.parse(value.created_at ?? "");
  const end = isActive(value.status) ? now : Date.parse(value.updated_at ?? "");
  if (!Number.isFinite(start) || !Number.isFinite(end) || end < start)
    return "Time unavailable";
  const seconds = Math.max(0, Math.floor((end - start) / 1000));
  return seconds >= 3600
    ? `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`
    : seconds >= 60
      ? `${Math.floor(seconds / 60)}m ${seconds % 60}s`
      : `${seconds}s`;
}
export const label = (value: string) => value.replaceAll("_", " ");
export const probeLabel = (id: string) =>
  ({
    "core.system": "Windows and computer information",
    "core.resources": "CPU, memory and storage",
    "network.snapshot": "Local network information",
    "application.snapshot": "Running apps and services",
    "browser.config": "Browser configuration",
    "devices.snapshot": "Devices and drivers",
    "display.mode": "Display mode",
    "storage.snapshot": "Storage information",
  })[id] ?? id.replaceAll(".", " · ").replaceAll("_", " ");

export function historyOutcome(value: Case) {
  if (value.status === "cancelled") return "Stopped · unresolved";
  if (value.status === "failed") return "Failed · evidence saved if collected";
  if (value.status === "interrupted") return "Interrupted · unresolved";
  if (value.status === "awaiting_target") return "Waiting for app selection";
  if (isActive(value.status))
    return value.status === "queued" ? "Queued" : "In progress";
  if (value.outcome === "insufficient_observability")
    return "Finished · insufficient evidence";
  if (value.outcome === "awaiting_recurrence")
    return "Finished · waiting for recurrence";
  if (["no_progress", "budget_exhausted"].includes(value.outcome ?? ""))
    return "Finished · unresolved";
  return "Finished · review evidence";
}

export interface ActivityItem {
  id: string;
  title: string;
  detail?: string;
  at?: string;
  timeKind: string;
  state:
    | "queued"
    | "running"
    | "observed"
    | "limited"
    | "failed"
    | "stopped"
    | "finished"
    | "recorded";
}
const eventStates: Record<string, ActivityItem["state"]> = {
  created: "queued",
  resumed: "queued",
  started: "running",
  collecting: "running",
  baseline_collecting: "running",
  reasoning: "running",
  attention: "running",
  awaiting_target: "limited",
  failed: "failed",
  cancelled: "stopped",
  interrupted: "stopped",
};
const eventTitles: Record<string, string> = {
  created: "Investigation queued",
  resumed: "Investigation queued to continue",
  started: "Read-only investigation started",
  collecting: "Collecting observations",
  baseline_collecting: "Collecting initial observations",
  reasoning: "Reviewing the evidence",
  attention: "Selecting evidence to review",
  awaiting_target: "Waiting for your app selection",
  failed: "Investigation could not finish",
  cancelled: "Investigation stopped",
  interrupted: "Investigation interrupted",
};
export function activityItems(value: Case): ActivityItem[] {
  const items: ActivityItem[] = (value.timeline ?? []).map((item, index) => {
    const event = item.event ?? "recorded";
    // A historical stopped event has no outcome in its DTO. Only the event
    // stamped with this terminal checkpoint can inherit its terminal status.
    const terminalState =
      event === "stopped" &&
      item.occurred_at &&
      item.occurred_at === value.updated_at
        ? value.status === "complete"
          ? "finished"
          : value.status === "failed"
            ? "failed"
            : ["cancelled", "interrupted"].includes(value.status)
              ? "stopped"
              : "recorded"
        : "recorded";
    return {
      id: `event:${item.state_version ?? `${item.occurred_at}:${event}:${index}`}`,
      title:
        eventTitles[event] ??
        (event === "stopped" ? "Investigation run ended" : label(event)),
      detail: item.detail,
      at: item.occurred_at ?? item.created_at,
      timeKind: "Event",
      state: eventStates[event] ?? terminalState,
    };
  });
  for (const [index, item] of (value.evidence ?? []).entries()) {
    items.push({
      id: `evidence:${item.evidence_id ?? `${item.probe_id}:${item.captured_at}:${index}`}`,
      title: probeLabel(item.probe_id ?? "Observation"),
      detail: `${item.historical ? "Historical evidence. " : ""}${item.summary ?? "Evidence recorded."}${item.observed_at && Number.isFinite(Date.parse(item.observed_at)) ? ` Source observed ${new Date(item.observed_at).toLocaleString()}.` : ""}`,
      at: item.captured_at,
      timeKind: "Captured",
      state:
        item.status === "observed"
          ? "observed"
          : item.status === "failed"
            ? "failed"
            : "limited",
    });
  }
  items.sort((a, b) => {
    const time = (item: ActivityItem) =>
      Number.isFinite(Date.parse(item.at ?? ""))
        ? Date.parse(item.at!)
        : Infinity;
    const left = time(a),
      right = time(b);
    return left === right ? 0 : left - right;
  });
  if (isActive(value.status))
    for (const id of value.pending_probe_ids ?? []) {
      items.push({
        id: `pending:${id}`,
        title: probeLabel(id),
        timeKind: "Queue time not reported",
        state: "queued",
        detail:
          "Pending in the current plan. Execution has not been confirmed.",
      });
    }
  return items;
}
