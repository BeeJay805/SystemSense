# SystemSense: next steps toward a fast, trusted Windows fixer

## Product position

SystemSense is currently a read-only Windows investigator. It can collect and cite bounded evidence, keep gaps visible, and support a few narrow observed findings. The repair runner and consent contracts are disconnected groundwork; the application cannot change Windows, and there is no held-out diagnostic-accuracy or verified-repair result. Treat the aspiration to scan and fix autonomously as a staged product direction, not a current capability.

The credible first promise is: **fast, evidence-backed diagnosis and, eventually, verified correction for specific qualified Windows software faults.** For unsupported hardware, application, or external failures, give a useful explanation and escalation. Do not market SystemSense as replacing IT generally. Any repair requires exact human approval, a narrowly scoped operation, and independent before/after verification. Standing consent is a later, separately qualified policy for narrowly reversible actions; it is not implied by an investigation or prior approval.

## Recommended sequence

### 1. Qualify the benchmark lane before changing models

First obtain authenticated guest access, a restorable VM checkpoint, independent fault injection, and an oracle outside the investigator and its harness. Freeze probe/catalog, code and model versions, budgets, permissions, and workload measurements. Admit only episodes whose injected condition and independent symptom oracle reproduce; retain arm errors, timeouts, invalid injections, and unresolved answers in the records and denominators.

Start with these software VM lanes:

1. **Proxy fault:** wrong current-user WinINet proxy against an owned external HTTPS endpoint, with separate affected-route and DIRECT controls. Verify actual route behavior and recovery independently; a stored setting or loopback result is not an oracle.
2. **Slow PDF:** pinned viewer, document, and page-turn task with a repeatable bounded CPU contention fault. Measure page latency before and after. Initially this is diagnosis-only; do not add a process-kill repair without its own exact safety case.
3. **External failure:** shared lab DNS outage seen by two clients. Correct behavior is to identify the external failure and avoid a local repair.
4. **Healthy control:** same workload without injection. Correct behavior is supported uncertainty/no local cause and no repair.

These lanes test local faults, external faults, and false-positive restraint while remaining resettable. Physical Wi-Fi association faults require a real AP/adapter and second-client oracle; schedule that after the VM lane. A pinned game/scene on the physical RTX 4090 is later still: capture frame-time distributions and interference, since virtual GPU evidence cannot qualify a 4090 claim.

Compare randomized, counterbalanced **A/B/C** arms on the same episodes: A deterministic/keyword baseline; B deep reasoner without learned fast ranking; C both brains. Give all arms the same observations, probe catalog, reference knowledge, time/resource budgets, and maximum authority. Keep the fault label and oracle sealed from each arm. Reviewers blinded to arm identity should adjudicate cited diagnosis, alternatives, contradictions, and justified uncertainty against separately held fault labels; a separate oracle evaluates symptom reproduction, recovery, recurrence, collateral effects, target binding, and consent.

Report paired p50/p95 time to first useful evidence, supported answer, and verified recovery; coverage and useful-probe yield; unsupported claims and false repairs; CPU/RAM/GPU, model calls/tokens, power where available, and interference with the target workload. Include cold/warm state and total inference, collection, and verification time. A fast unanswered arm is not a fast answer. Promote an arm only if quality and uncertainty handling do not regress; any repair on a healthy or external control blocks promotion. Repeat across held-out cases, machines, versions, and fault families before making public performance claims. Include multiple causes for the same symptom and matched no-fault controls, so a system cannot score well by memorizing one recipe or always proposing a fix.

The existing VM admission and scorecard code checks consistency of submitted records but cannot authenticate a rig or oracle. The current clone lacks a verified guest login, restorable snapshot, and independent oracle. Until those prerequisites are met, there is no measured Windows VM outcome. Fixture benchmarks and the five synthetic journeys validate contracts and report math only; they are not diagnostic-performance evidence.

The PDF lane now has a read-only selected-process path: the browser shows
candidates from a persisted current-case snapshot, binds the user's choice to
its evidence ID, PID, and creation time, and resumes an internal-only pressure
probe. Missing, reused, expired, or inaccessible identity becomes unavailable
coverage, not a guessed target. The probe does not measure page-turn latency or
root cause. Next, add a pinned viewer/document/page-turn task with an independent
latency oracle, reproducible contention injection, and before/after controls.
Only then can the investigator's explanation be scored against actual task
behavior; a process-kill repair needs a separate safety case.

### 2. Make the fast brain practical on ordinary laptops

Keep the local deterministic collector, policy, evidence store, and action boundary in control. Treat attention as a replaceable ranking component that can select only registered probes. Today's Laya typed-decisions checkpoint was trained on four non-Windows workflows, and its upstream card warns about out-of-domain use ([Laya model card](https://huggingface.co/convaiinnovations/laya-typed-decisions)). On this desktop, warm CPU attention over 54 previews and 17 probes took about 102–105 seconds; this is not an ordinary-laptop measurement and is far from the proposed three-second p95 cycle. The optional CUDA pass is fast on a 4090, but that does not establish laptop fit. Upstream CPU figures do not specify an ordinary Windows laptop configuration and memory footprint; Laya's suitability for everyday laptops remains unknown.

Next compare the transparent CPU typed-feature challenger, optimized/exported Laya, and incumbent Laya on identical frozen requests and, later, held-out VM episodes. Measure cold start and warm p50/p95, RAM/VRAM, power, target-workload interference, useful-probe recall, supported answers, and unjustified confidence on representative 8 GB CPU and 16 GB integrated-graphics laptops. Use the deterministic path when the optional model is unavailable or declines admission. Do not assume 421M Laya or an NVIDIA GPU is the right ordinary-PC answer.

**Do not fine-tune yet.** There are no admitted expert-reviewed field labels or held-out quality scores. First collect blinded next-probe judgments tied to exact visible evidence, candidate catalogs, outcomes, and reviewer attestations. Split by case, machine, application/version, and fault family to prevent leakage; include abstention and negative-control behavior. Fine-tune or train a compact ranker only if those labels are sufficiently diverse, then compare it to deterministic features and Laya on untouched episodes. A smaller model is valuable only if it preserves or improves useful-probe recall and answer quality while meeting device limits.

### 3. Qualify one repair end to end

Keep the WinINet prototype unmounted until the owned endpoint, affected/direct route oracle, managed-policy coverage, trusted same-user interactive approval, cross-process exclusion, crash recovery/reconciliation, and restorable VM trial all pass. Then test a single exact proposal through explicit human approval, live precondition recheck, one-shot authorization, journaled adapter write, independent affected-task retry, collateral checks, and recurrence observation. Failed or unavailable verification is a failed/unknown repair outcome, never success. Only after this narrowly scoped path is safe should a separately reviewed standing-consent policy be considered.

## Model deployment direction

The current optional deep brain is local Qwen3.8 27B, pinned through the official [Qwen model repository](https://huggingface.co/Qwen/Qwen3.8-27B). Its Q4 artifact is about 18 GB, and measured 8K-context residency is about 17.3 GB on the development RTX 4090. That profile is a desktop experiment, not an ordinary-laptop recommendation; the 4090 also has tight headroom when Laya is resident. No cloud provider is implemented or authorized as a current stage, and there is no automatic paid API fallback.

After local benchmark and privacy gates, a replaceable cloud deep reasoner may be tested as an optional advisory provider. Send only a redacted, user-approved focused evidence map; it may propose explanations or registered next probes, never collect on its own or authorize repairs. Cloud availability, price, retention, consent, and failure behavior need separate evaluation. Offline and disconnected PCs must retain a useful local deterministic path.

## Stage gates

| Gate | Evidence required before moving on |
| --- | --- |
| Repeatable software benchmark | Authenticated/restorable VM episodes; independent oracles; randomized matched A/B/C trials across proxy, PDF, external, and healthy lanes; blinded adjudication; complete latency, quality, safety, and overhead report. |
| Laptop fast brain | Same-request component profiles plus held-out episode results on representative ordinary laptops; no regression in useful-probe recall, answer quality, or abstention; acceptable latency, memory, power, and interference. |
| First repair family | Exact human approval and target binding; qualified policy and endpoint scope; one-shot journaled action; independent recovery and collateral checks; crash/reconciliation behavior; zero unauthorized/false repairs in the pilot. |
| Domain expansion | Separate physical qualification and outcome benchmark for Wi-Fi, then gaming/4090; no extrapolation from VM or desktop model results. |
| Optional cloud | Separate redaction/export and retention review; paired quality, latency, price, and availability evaluation; local behavior remains useful when offline. |

Passing one gate qualifies only that fault family, workload, device scope, and action. Broader marketing claims require diverse held-out machines and incidents with uncertainty intervals. The near-term message should stay narrow: SystemSense is building toward measured, specific software-fault recovery, and currently provides read-only investigation.
