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
      detail:
        "Collecting read-only observations. Missing access will be shown here.",
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
  return {
    canStart: (cap.probes?.length ?? 0) > 0 && cap.read_only === true,
    browserMissing: /browser|chrome|edge|firefox|website|web page|safari/i.test(
      objective,
    ),
    needsTarget: /app|game|pdf|process|program/i.test(objective),
  };
}
export function elapsed(value: Case, now: number) {
  const start = Date.parse(value.created_at ?? "");
  const end =
    isActive(value.status) && value.status !== "awaiting_target"
      ? now
      : Date.parse(value.updated_at ?? "");
  if (!Number.isFinite(start) || !Number.isFinite(end))
    return "Time unavailable";
  const seconds = Math.max(0, Math.floor((end - start) / 1000));
  return seconds >= 60
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
