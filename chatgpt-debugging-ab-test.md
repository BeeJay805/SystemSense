# ChatGPT debugging A/B test

## Goal

Measure whether SystemSense reduces verified Windows repair time, billed model tokens,
and manual inspection calls without reducing repair success or safety.

## Experimental decision

- Primary evidence uses a fixed OpenAI API model in a controlled debugger harness so
  usage, model identity, tool calls, and wall time are recorded exactly.
- Both arms receive identical PowerShell and VM repair authority. The treatment arm
  receives only one additional capability: the six SystemSense MCP tools.
- SystemSense is installed in both VM clones but disabled in the baseline, keeping
  guest bytes and dependencies identical.
- ChatGPT UI replays are reported separately because UI runs cannot be mixed with
  proof-grade API token measurements.

## Tasks

- [ ] Define each scenario as `manifest.json`, `inject.ps1`,
  `verify-broken.ps1`, `verify-fixed.ps1`, and `repair-reference.ps1`.
  Verify: broken oracle fails three times, reference repair passes, snapshot restore
  makes it fail again.
- [ ] Create one stopped clean VM snapshot per scenario and two clones from that
  same snapshot, then run the same deterministic injector in both. Verify: OS,
  package, file, policy, fault-state, and parent-snapshot fingerprints match before
  both arms. A memory-inclusive checkpoint may instead preserve process faults.
- [ ] Build the debugger recorder around fresh API sessions. Record every response
  ID, returned model ID, input/cached/output/reasoning tokens, tool call, tool-result
  bytes, command, elapsed time, final answer, and oracle result. Verify with a
  synthetic metering test before connecting a study VM.
- [ ] Add a setup verifier that checks equal repair tools, exact prompt hash, empty
  conversation state, fresh SystemSense database, six treatment-only MCP tools,
  `doctor` health, case/audit integrity, and absence of study answers. Verify: it
  emits `READY_TO_BENCHMARK.json`; the runner refuses paid calls without that file.
- [ ] Qualify every scenario before enrollment. Verify: the fault reproduces, the
  model can operate the VM, the hidden oracle can score the fix, and SystemSense
  captures at least one predefined discriminating fact. Explicit coverage is
  reported as a gap but cannot authorize a paid run in place of the expected signal.
- [ ] Run one non-study canary through both arms from restored clones. Verify:
  complete traces, identical starting fingerprints, exact tool-set difference,
  successful oracle scoring, no state leakage, and clean restore after each run.
- [ ] Run a two-per-family pilot, estimate paired variance and failure rate, then set
  the final sample size before looking at savings. Verify: frozen analysis file,
  balanced randomized arm order, and no pilot cases reused in the final estimate.
- [ ] Run the final paired cohort and publish repair success, collateral-change rate,
  verified time-to-fix, billed tokens, tool calls, SystemSense overhead, paired
  savings, and 95% confidence intervals. Verify: no savings claim unless repair
  success is at least the baseline rate, no additional safety failure appears, and
  the paired-savings interval excludes zero.

## Human prompt

> My Windows PC started having **[visible symptom]** after **[ordinary context]**.
> Please diagnose and fix it. You may inspect the machine and make safe local
> changes, but preserve my files and installed applications. When you think it is
> fixed, reproduce the original action and verify that it works. If you cannot fix
> it, explain exactly what blocked you.

The prompt is identical in both arms and contains only facts a normal user could
observe. It never names the injected root cause or tells the model to use
SystemSense.

First non-study canary: a hidden background process owns port 8000, causing a local
development app to fail with the real Windows address-in-use message. The repair
oracle starts the app and checks its health endpoint after the debugger exits.

## Done when

- [ ] No study run can start without all setup gates passing.
- [ ] Every result can be reproduced from a scenario snapshot, prompt hash, model
  identifier, tool manifest, and raw trace.
- [ ] Fixture metrics remain labeled separately from recorded model-run metrics.
- [ ] Failed and timed-out repairs remain in the dataset.
