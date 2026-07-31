# Benchmarking

SystemSense uses a hybrid validation strategy:

1. deterministic engineering fixtures run on every change;
2. paired recorded AI runs measure real token, time, and tool-call savings before a
   savings claim is published.

Savings are invalid whenever diagnostic quality regresses.

## Metrics

For a positive baseline measurement `B` and SystemSense measurement `S`:

```text
savings_percent = 100 * (B - S) / B
```

The harness records:

- input characters;
- provider-reported input tokens when available;
- elapsed wall time, including SystemSense overhead;
- tool calls;
- evidence IDs recovered;
- accepted diagnosis codes.

Quality is:

```text
quality = 0.4 * required_evidence_recall + 0.6 * diagnosis_correct
```

A case contributes to aggregate savings only when SystemSense quality is equal to or
better than its manual-inspection baseline. Reports include minimum, median, mean,
p95, maximum, invalid cases, and measurement source.

## Current deterministic result

Run:

```powershell
.\.venv\Scripts\python.exe -m benchmarks.runner
```

The six checked-in engineering fixtures cover core, application, devices and audio,
network, servicing, and local AI:

| Measure | Median |
|---|---:|
| Context characters | 72.36% savings |
| Fixture token field | 68.09% savings |
| Elapsed time | 75.54% savings |
| Tool calls | 66.67% savings |
| Quality-valid cases | 6/6 |

These numbers test the schema, formulas, quality gate, and report determinism. They
are not measured Claude savings.

## Recorded Claude A/B protocol

Use at least 30 paired cases drawn from real, redacted failures across all six
families.

For each case:

1. Freeze the symptom, ground-truth required evidence, accepted diagnosis codes, and
   Windows evidence snapshot.
2. Use the same Claude model version, system prompt, tool permissions, and timeout
   for both arms.
3. In the baseline arm, allow the normal manual inspection tools but no SystemSense.
4. In the SystemSense arm, provide the six-tool MCP server and the same non-SystemSense
   permissions.
5. Start each arm in a fresh conversation and randomize arm order.
6. Record provider-reported input tokens, wall time, tool calls, evidence citations,
   diagnosis, failures, and SystemSense collection overhead.
7. Have diagnosis correctness scored against the frozen accepted codes without
   revealing the arm.
8. Import each arm as `recorded_model_run`, run the report, and publish paired
   medians plus bootstrap 95% confidence intervals.

Do not mix fixture token estimates with provider-reported tokens. Record missing
token data as missing. Do not discard timeouts or failed diagnoses.

## Claim policy

A public percentage claim needs:

- recorded model runs, not engineering fixtures;
- equal or better diagnostic quality;
- scenario and model-version disclosure;
- paired sample count and confidence interval;
- SystemSense overhead included in elapsed time;
- raw redacted measurement records available for audit.

Running the recorded arm requires the user's model credentials, incurs external
model usage, and is intentionally not part of local or CI automation.
