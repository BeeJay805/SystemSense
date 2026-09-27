import { describe, it, expect } from "vitest";
import { activityItems, historyOutcome, elapsed } from "../src/presentation";
describe("desktop activity and history", () => {
  it("keeps cancelled, failed and finished events distinct without rewriting prior runs", () => {
    const at = "2026-09-27T00:00:12Z";
    for (const [status, expected] of [
      ["cancelled", "stopped"],
      ["failed", "failed"],
      ["complete", "finished"],
    ]) {
      expect(
        activityItems({
          status,
          updated_at: at,
          timeline: [{ event: "stopped", occurred_at: at }],
        })[0].state,
      ).toBe(expected);
    }
    expect(
      activityItems({
        status: "cancelled",
        updated_at: at,
        timeline: [{ event: "stopped", occurred_at: "2026-09-27T00:00:05Z" }],
      })[0].state,
    ).toBe("recorded");
  });
  it("orders real timestamps and leaves unfamiliar events as recorded", () => {
    const items = activityItems({
      status: "running",
      timeline: [
        {
          state_version: 2,
          event: "new_backend_event",
          occurred_at: "2026-09-27T00:00:02Z",
          detail: "Real event",
        },
        {
          state_version: 1,
          event: "started",
          occurred_at: "2026-09-27T00:00:01Z",
          detail: "Started",
        },
      ],
      evidence: [
        {
          evidence_id: "e1",
          status: "denied",
          captured_at: "2026-09-27T00:00:03Z",
        },
      ],
    });
    expect(items.map((x) => x.state)).toEqual([
      "running",
      "recorded",
      "limited",
    ]);
    expect(new Set(items.map((x) => x.id)).size).toBe(3);
  });
  it("never promotes a summary outcome to fixed", () => {
    expect(
      historyOutcome({ status: "complete", outcome: "supported_explanation" }),
    ).toBe("Finished · review evidence");
    expect(historyOutcome({ status: "cancelled" })).toBe(
      "Stopped · unresolved",
    );
    expect(
      historyOutcome({
        status: "complete",
        outcome: "insufficient_observability",
      }),
    ).toBe("Finished · insufficient evidence");
  });
  it("does not clamp a reversed clock to zero", () => {
    expect(
      elapsed(
        {
          status: "complete",
          created_at: "2026-09-27T00:00:02Z",
          updated_at: "2026-09-27T00:00:01Z",
        },
        0,
      ),
    ).toBe("Time unavailable");
  });
  it("never invents pending probe timestamps", () => {
    const items = activityItems({
      status: "running",
      pending_probe_ids: ["core.system"],
    });
    expect(items[0].state).toBe("queued");
    expect(items[0].at).toBeUndefined();
  });
});
