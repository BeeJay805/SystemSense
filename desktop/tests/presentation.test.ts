import { describe, it, expect } from "vitest";
import { caseHeading, elapsed, readiness, isActive } from "../src/presentation";
describe("truthful case presentation", () => {
  it("does not turn an advisory supported label into a diagnosis", () => {
    expect(
      caseHeading({
        status: "complete",
        outcome: "supported_explanation",
        hypotheses: [{ status: "supported" }],
      }).title,
    ).toBe("No supported answer yet");
  });

  it("distinguishes an observed exact-task result from an unresolved cause", () => {
    const healthy = {
      status: "complete",
      outcome: "insufficient_observability",
      evidence: [
        {
          probe_id: "task.loopback_http",
          status: "observed",
          facts: { outcome: "http_200_nonce_match" },
        },
      ],
    };
    expect(caseHeading(healthy).title).toBe("This check worked");
    expect(caseHeading(healthy).detail).toMatch(/earlier.*unverified/i);
    expect(
      caseHeading({
        ...healthy,
        evidence: [
          {
            probe_id: "task.loopback_http",
            status: "observed",
            facts: { outcome: "http_503" },
          },
        ],
      }).title,
    ).toBe("A failure was observed");
  });
  it("labels an admitted observed finding without claiming root cause", () => {
    expect(
      caseHeading({
        status: "complete",
        assessment: {
          disposition: "supported_observed_finding",
          explanation: "Listener observed",
        },
      }).title,
    ).toBe("An observed finding");
  });
  it("preserves waiting and cancellation distinctions", () => {
    expect(caseHeading({ status: "awaiting_target" }).title).toBe(
      "Choose the app to continue",
    );
    expect(
      caseHeading({ status: "running", cancellation_requested: true }).title,
    ).toBe("Stopping investigation");
    expect(isActive("awaiting_target")).toBe(true);
  });
  it("never treats empty capabilities as ready or browser as connected", () => {
    expect(
      readiness("Example problem", { probes: [{ probe_id: "core.system" }] })
        .canStart,
    ).toBe(false);
    expect(readiness("Chrome cannot load pages", { probes: [] }).canStart).toBe(
      false,
    );
    expect(
      readiness("Chrome cannot load pages", {
        probes: [{ probe_id: "core.system" }],
      }).browserMissing,
    ).toBe(true);
  });
  it("freezes terminal elapsed time rather than counting since reopen", () => {
    expect(
      elapsed(
        {
          status: "complete",
          created_at: "2026-09-27T00:00:00Z",
          updated_at: "2026-09-27T00:00:12Z",
        },
        Date.parse("2026-09-28"),
      ),
    ).toBe("12s");
  });
});
