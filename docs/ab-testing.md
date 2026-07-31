# ChatGPT debugger A/B test

This protocol measures whether SystemSense reduces verified Windows repair time and
provider-billed tokens compared with normal manual inspection.

The primary experiment uses the OpenAI Responses API, not the ChatGPT UI. API runs
provide response IDs, returned model IDs, token usage, tool calls, and exact raw
traces. ChatGPT UI replays may be reported separately as product-realism checks, but
they cannot be mixed into the proof-grade token result.

The product MCP remains read-only and offline. The arbitrary PowerShell repair tool
and outbound OpenAI transport exist only under `benchmarks/ab` and are exposed
identically to both experimental arms.

## What is frozen

Each pair uses:

- one stopped clean parent snapshot and two clones created from it;
- the same deterministic fault injector after every restore;
- the same human prompt, agent instructions, requested API model, timeout, and
  repair tool;
- a fresh API conversation and fresh SystemSense database;
- a hidden repair oracle that the model cannot read;
- a ten-category guest fingerprint captured after fault injection;
- only six additional treatment tools: the real SystemSense MCP surface.

The fingerprint covers the parent snapshot ID, OS, PowerShell, Python packages,
installed software, drivers, policies, services, scenario files, fault state, and
SystemSense installation. Clone IDs and process IDs are deliberately excluded from
the comparison.

For a process fault such as the port-conflict canary, do not expect a normally
powered-off snapshot to preserve the process. Restore the clean parent and run the
same checked-in injector in each clone before capturing the fingerprint.

## Two paid-run locks

The experiment has two distinct readiness artifacts:

| Artifact | What it authorizes |
|---|---|
| `READY_FOR_CANARY.json` | One non-study canary in each arm |
| `READY_TO_BENCHMARK.json` | Pilot or final enrolled runs |

The second artifact cannot exist until both canaries pass and both VMs restore to
their original fingerprint. `run-arm` also requires `--allow-paid-run` and an
`OPENAI_API_KEY` environment variable. No local check, CI job, or default command
can make a model call.

## 1. Freeze the experiment

Install the development environment, then create the config:

```powershell
uv sync --frozen

$Scenario = "benchmarks\ab\scenarios\port_conflict"
.\.venv\Scripts\systemsense-ab.exe init `
  --scenario $Scenario `
  --model "gpt-5.6-sol" `
  --experiment-id "port-conflict-canary-v1" `
  --output "experiment.json"

.\.venv\Scripts\systemsense-ab.exe meter-check
.\.venv\Scripts\systemsense-ab.exe scenario-check `
  --scenario $Scenario `
  --state-directory "$env:TEMP\systemsense-ab-state"
```

The scenario check must report three broken reproductions, three reference repairs,
three fixed-oracle passes, and successful cleanup.

Do not use a moving convenience alias such as `chat-latest` for the primary
experiment. Record the returned model ID from every response. If it changes within
a frozen cohort, stop and split or restart the cohort. See the official
[model guide](https://developers.openai.com/api/docs/models) and
[Responses API guidance](https://developers.openai.com/api/docs/guides/latest-model).

## 2. Build and prove the two VM arms

1. Install the same SystemSense commit in the golden VM.
2. Keep the API key out of the image and snapshot.
3. Take one stopped clean parent snapshot.
4. Create baseline and treatment clones from that exact parent.
5. Restore each clone, run `inject.ps1`, and capture its fingerprint.
6. Restore and reinject once more, then capture the restore-proof fingerprint.

Set the injector environment inside each clone:

```powershell
$env:SYSTEMSENSE_AB_STATE_DIR = "$env:TEMP\systemsense-ab-state"
$env:SYSTEMSENSE_AB_PYTHON = (Resolve-Path ".\.venv\Scripts\python.exe").Path
& "$Scenario\inject.ps1"
```

Capture and compare:

```powershell
.\.venv\Scripts\systemsense-ab.exe capture-fingerprint `
  --scenario $Scenario --arm baseline `
  --clone-id "baseline-clone" --parent-snapshot-id "parent-checkpoint-id" `
  --output "baseline-fingerprint.json"

.\.venv\Scripts\systemsense-ab.exe capture-fingerprint `
  --scenario $Scenario --arm systemsense `
  --clone-id "systemsense-clone" --parent-snapshot-id "parent-checkpoint-id" `
  --output "systemsense-fingerprint.json"

.\.venv\Scripts\systemsense-ab.exe compare-fingerprints `
  --baseline "baseline-fingerprint.json" `
  --systemsense "systemsense-fingerprint.json"
```

Any difference is a failed setup, not noise to average away.

## 3. Qualify SystemSense and create the canary gate

Use a dedicated fresh qualification database:

```powershell
.\.venv\Scripts\systemsense-ab.exe qualify `
  --scenario $Scenario `
  --state-directory "$env:TEMP\systemsense-ab-qualification-state" `
  --database "$env:TEMP\systemsense-ab-qualification.db" `
  --original-broken-fingerprint "baseline-fingerprint.json" `
  --restored-broken-fingerprint "baseline-restored-fingerprint.json" `
  --output "qualification.json"
```

This checks the real six-tool MCP protocol, database health, case-to-audit count,
recorder calibration, the hidden oracle, and either a predefined discriminating
fact or explicit coverage. Unsupported evidence is a recorded coverage gap.

Before running a canary, capture each arm's empty state:

```powershell
.\.venv\Scripts\systemsense-ab.exe arm-evidence `
  --config "experiment.json" --arm baseline `
  --fingerprint "baseline-fingerprint.json" `
  --database "$env:TEMP\baseline-fresh.db" `
  --study-answer-directory "$env:TEMP\empty-study-answers" `
  --output "baseline-preflight.json"

.\.venv\Scripts\systemsense-ab.exe arm-evidence `
  --config "experiment.json" --arm systemsense `
  --fingerprint "systemsense-fingerprint.json" `
  --database "$env:TEMP\systemsense-fresh.db" `
  --study-answer-directory "$env:TEMP\empty-study-answers" `
  --output "systemsense-preflight.json"

.\.venv\Scripts\systemsense-ab.exe build-ready `
  --stage canary --config "experiment.json" `
  --qualification "qualification.json" `
  --baseline "baseline-preflight.json" `
  --systemsense "systemsense-preflight.json" `
  --output "READY_FOR_CANARY.json"
```

## 4. Run and finalize the non-study canaries

Only now set the key in the process environment:

```powershell
$env:OPENAI_API_KEY = "set-in-the-shell-not-in-a-file"

.\.venv\Scripts\systemsense-ab.exe run-arm `
  --mode canary --arm baseline --pair-id "canary-01" `
  --config "experiment.json" --ready "READY_FOR_CANARY.json" `
  --scenario $Scenario --before-fingerprint "baseline-fingerprint.json" `
  --database "$env:TEMP\baseline-canary.db" `
  --state-directory "$env:TEMP\baseline-canary-state" `
  --output "runs\baseline-canary.json" --allow-paid-run
```

Run the treatment from its restored and reinjected clone with its own fresh
database. Then restore and reinject each clone again, capture its restored
fingerprint, and finalize:

```powershell
.\.venv\Scripts\systemsense-ab.exe finalize-arm `
  --evidence "baseline-preflight.json" `
  --canary-trace "runs\baseline-canary.json" `
  --restored-fingerprint "baseline-restored-after-canary.json" `
  --output "baseline-finalized.json"

.\.venv\Scripts\systemsense-ab.exe build-ready `
  --stage benchmark --config "experiment.json" `
  --qualification "qualification.json" `
  --baseline "baseline-finalized.json" `
  --systemsense "systemsense-finalized.json" `
  --output "READY_TO_BENCHMARK.json"
```

The benchmark artifact is refused if either canary, hidden oracle, restore, tool
manifest, prompt, database, or fingerprint gate differs.

## 5. Pilot, freeze sample size, then run the final cohort

Create and commit a balanced arm-order schedule before inspecting savings:

```powershell
.\.venv\Scripts\systemsense-ab.exe schedule `
  --scenario-id "application.port_conflict" `
  --repetitions 2 --random-seed 20260730 `
  --output "pilot-schedule.json"
```

The full pilot uses two pairs per scenario family. Keep pilot outcomes in a
separate directory and never reuse them in the final estimate. Convert the pilot's
paired savings values and observed failure rate into a frozen final size:

```powershell
.\.venv\Scripts\systemsense-ab.exe pilot-size `
  --paired-savings-file "pilot-paired-token-savings.json" `
  --observed-failure-rate $PilotFailureRate `
  --minimum-detectable-savings-pct $PreregisteredMdePercent `
  --minimum-final-pairs $PreregisteredMinimumPairs `
  --output "final-sample-size.json"
```

The minimum detectable effect and minimum cohort are product decisions and must be
set before looking at final results. The command computes the normal-approximation
paired sample size from observed standard deviation, then inflates it by the pilot
failure rate.

Every enrolled arm uses `run-arm --mode study`, a restored clone, a reinjected
fault, a fresh database, and the frozen `READY_TO_BENCHMARK.json`.

## 6. Analyze without dropping failures

Each run writes:

- the raw response bodies and response IDs;
- requested and returned model IDs;
- input, cached input, output, reasoning, and total tokens;
- every command, MCP call, result, byte count, and elapsed time;
- the hidden-oracle result and collateral fingerprint result;
- a compact `*.outcome.json` record.

Analyze only after the frozen enrollment count is reached:

```powershell
.\.venv\Scripts\systemsense-ab.exe analyze `
  --results-directory "final-runs" `
  --required-pair-count $FrozenFinalPairs `
  --bootstrap-resamples 10000 `
  --random-seed 20260730 `
  --output "final-analysis.json"
```

A savings claim is allowed only when:

- enrolled pair count reaches the frozen target;
- at least two pairs are quality-valid;
- SystemSense repair success is not lower than baseline;
- SystemSense collateral-change rate is not higher than baseline;
- the bootstrap 95% interval for that savings metric excludes zero.

Failures, timeouts, API errors, and unsuccessful repairs remain in success-rate
denominators. Fixture estimates and recorded API results are always reported
separately.
