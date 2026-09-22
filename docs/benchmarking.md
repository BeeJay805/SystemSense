# Evaluation and benchmarking

SystemSense has four distinct evaluation classes. They must not be combined into
one performance claim.

## 1. Fixture contract checks

`benchmarks/scenarios` and `benchmarks/ground_truth` contain static engineering
fixtures labelled `engineering_fixture`. Running:

```powershell
.\.venv\Scripts\python.exe -m benchmarks.runner
```

checks schema validation, quality-score arithmetic, savings formulas, report
determinism, and invalidation when the fixture quality regresses. It does not run
an investigator, Windows fault, model, or real client. Its percentages are not
diagnostic-performance or AI-savings measurements.

## 2. Component benchmarks

These measure implemented foundations in isolation:

- probe collection latency, output size, failure/timeout coverage, and host impact;
- scheduler overlap, queue tails, resource limits, cancellation, deduplication, and
  stale-task rejection;
- provider contract validation, baseline determinism, bounded response size, and
  unavailable-provider behavior;
- typed temporal graph validation, durable relation storage, projection, and bounded
  retrieval correctness.

The current resource runner reports idle application-service and case-operation
measurements. Idle sampling runs in an owned clean subprocess and validates its
actual interpreter PID and creation time, including Windows launcher descendants.
It excludes the pytest process, browser/HTTP serving and loaded inference models;
the 128 MiB test budget is not a budget for Qwen and Laya. Before any component
result is published as comparative evidence, its
schema must also record code revision, platform, provider identity, evidence catalog,
budgets, warm/cold state, and measurement limitations.

## 3. Recorded coordinator episodes

Run:

```powershell
.\.venv\Scripts\python.exe -m benchmarks.local_episodes
```

The runner executes five deterministic synthetic journeys through the actual
coordinator: memory pressure, pending restart, a reported device problem, missing
telemetry, and invalid provider output. All use the same 2,000 ms, two-round,
two-probe settings. The artifact records actual wall time, probe attempts,
execution-status and failure denominators, directly counted evidence/coverage,
attempted and skipped probe IDs, provider calls and failures, effective
provider/model IDs, terminal outcomes, and unknown review labels. It validates
recording and failure accounting only, not diagnostic performance.

A compact checked-in sample is at
`benchmarks/results/local-episodes.json`. Its `measurement_source` remains
`simulation`, and its integrity hash covers the versioned episode payload. Re-run
the command to make a new measurement; elapsed times are measured, not fixture
constants.

## 4. Diagnostic qualification

A diagnostic-performance claim requires reviewed, reproducible investigation
episodes rather than prefilled arm measurements. Each episode needs:

- a frozen objective, machine/configuration/version split, and fault or healthy case;
- the same typed probe catalog, evidence access, resource budgets, and timeout rules
  across comparisons;
- evidence and coverage traces, useful/redundant probes, provider calls, wall time,
  collection overhead, host resource impact, and failures;
- accepted supported explanations, missed causes, uncertainty quality, and
  multi-cause handling scored against reviewed labels;
- held-out machines, versions, workloads, fault combinations, and unknown cases;
- explicit provider/model/procedure versions and redacted raw audit artifacts.

Useful comparisons include the keyword baseline, deterministic routing, retrieval
without a learned fast policy, a local reasoning provider, and the complete system.
No arm receives a broader probe catalog or hidden authority.

## Reporting rules

Failures, timeouts, unavailable evidence, and provider errors remain in success
denominators. Missing token data stays missing. Report median, p95, minimum,
maximum, sample count, quality, and host overhead separately. A faster route that
misses evidence or overstates certainty is not a successful diagnostic result.

Do not publish the current fixture percentages as measured diagnostic performance.
No paid-model A/B workflow is part of the current product acceptance path.
