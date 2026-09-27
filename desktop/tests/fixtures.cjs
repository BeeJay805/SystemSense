const id = "case_" + "a".repeat(32);
const base = {
  case_id: id,
  objective: "Development fixture: Example app is not responding",
  status: "complete",
  outcome: "insufficient_observability",
  created_at: "2026-09-27T00:00:00Z",
  updated_at: "2026-09-27T00:00:12Z",
  evidence: [],
  coverage: [],
  timeline: [],
  warnings: [],
};
const states = {
  empty: base,
  denied: {
    ...base,
    evidence: [
      {
        evidence_id: "fixture-evidence",
        probe_id: "application.snapshot",
        status: "denied",
        summary: "Development fixture: access was denied",
        observed_at: base.created_at,
        captured_at: base.updated_at,
        source_id: "development-fixture",
        limitations: ["No process data was collected."],
      },
    ],
    coverage: [
      {
        probe_id: "application.snapshot",
        status: "denied",
        reason: "Development fixture: access denied",
      },
    ],
  },
  supported: {
    ...base,
    assessment: {
      disposition: "supported_observed_finding",
      explanation:
        "Development fixture: a listener was observed. This is not a real computer observation.",
      limitations: ["The cause is unresolved."],
    },
  },
  uncertain: {
    ...base,
    hypotheses: [
      {
        status: "supported",
        statement: "Development fixture: an advisory explanation",
        supporting_evidence_ids: [],
        contradicting_evidence_ids: [],
      },
    ],
  },
  failed: {
    ...base,
    status: "failed",
    outcome: "failed",
    summary: "Development fixture: collection failed",
  },
  waiting: {
    ...base,
    status: "awaiting_target",
    outcome: "awaiting_target",
    process_target_inventory: {
      inventory_complete: false,
      omitted_process_count: 3,
      candidates: [
        {
          candidate_id: "proc_" + "b".repeat(32),
          name: "Development fixture app",
          pid: 123,
          creation_time: base.created_at,
          evidence_id: "fixture-source",
        },
      ],
    },
  },
  disconnected: base,
};
module.exports = { states };
