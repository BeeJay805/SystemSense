# Benchmarks and acceptance

The [product-observed loopback trials](#product-observed-loopback-trials-2026-09-28) tested code `caa4970`. The [2026-09-28 overnight scorecard](#overnight-measured-result-2026-09-28) used `12990ad`; [reversible Windows checks](#reversible-local-windows-checks-2026-09-28) exercised process routing at `0b83e0f`. The [first controlled affected-task trial](#controlled-affected-task-trial-2026-09-28) used `868b94c`; the [repair and breadth trials](#controlled-task-repair-and-breadth-2026-09-28) used `e02fb72` through `6c278e4`. Earlier checkpoints preserve historical evidence and are not current product qualification. [Current state](CURRENT_STATE.md) is the current capability summary.

Report fixture contracts, component timings, fake overlap, real-model local runs, real Windows episodes, and held-out diagnostic outcomes as different evidence classes. None substitutes for another. Record code/model revision, effective model IDs and artifact hashes, hardware/load, case fixtures or fault injection, probe catalog, evidence access, budgets, exclusions, failures, and uncertainty. Configured model names are not proof of executed models.

## Frozen owned-process qualification (2026-09-29)

The read-only exact-name process path at `420e5c7` has a second blinded
real-Windows suite. `benchmarks/fixtures/private_alpha_host_cases.json`
freezes 16 descriptions, 90-second budgets and an eight/eight
development/holdout split. The private-to-evaluator recipe file is
`benchmarks/ground_truth/private_alpha_host_recipes.json`; only the harness
reads it. Their SHA-256 hashes are
`5f31aed79a5ae77fe8133fc428b10b9848da085de65bdfe9436e8bcee28faabd`
and `366f3c52791ac26dfe0397cd2a71caa7a97abffcbb1123bc2bcd098787e818ca`.
The test-owned process source is `benchmarks/fixtures/owned_cpu_process.cs`
with SHA-256
`c6c5926ee05f208c1c708e6f148f1067aaf5fe85be55da0053b2c643b147971c`.
The evaluator uses a unique executable name per case, measures target and
healthy control before, during, halfway through and after the product run,
restores an idle state, then terminates only its owned helpers. Product prompts
contain no recipe or expected answer. Product cases and independent evaluator
readings remain in separate files outside the repository.

The interpretation was frozen before the runs: a complete saved process table
supports presence or absence of the exact executable only at its sample time;
it cannot explain an earlier exit. Two identity-bound CPU delta samples must
show activity for a busy case or near-zero use for an idle case. A busy
separate control must not be attributed to the idle target. Generic unknown is
not success when these readings are available; sampled activity alone is not
a verified cause of perceived slowness. Healthy and misleading controls must
not become false failure claims. The paired Basic route gets the same case
budgets and read-only access. `benchmarks/private_alpha_host_score.py` checks
the mechanical observations, clean source identity, restoration, time and
evaluator process-tree RSS. It reports Laya provider-call receipts and
candidate-ranking receipts separately because they can describe the same
invocation. Saved summaries still require independent semantic
review for usefulness and unsupported claims. Exploratory single-case runs
are excluded from the clean-source rate.

The exploratory development run `host-development-model-01` exposed two
separate real failures: late Sol request validation rejected a completed
target-pressure probe that had vanished from its capability catalog, and a
psutil/JSON creation-time round trip differed by one microsecond, falsely
marking a same-identity sample as PID reuse. The next eight-case development
run completed with correct mechanical observations and restoration, but warm
median/p90 were 47.266/62.797 seconds. A later CPU run reported that a
completed target-specific sample had not been reviewed; the focused packet
had omitted it. Exact target samples now have reserved space. A further
40-second CPU run still launched irrelevant storage work because the
event-driven candidate catalog bypassed the narrower streaming filter.
At `420e5c7`, a focused busy/idle pair measured 24.062/23.469 seconds, used
the target samples in the summaries, omitted storage, and independently
restored every owned process. The first broad non-MCP run at `420e5c7` failed
nine tests after 3,805 passes; `ab01826` restored broad concurrent follow-ups
and the ordinary application resource baseline, with the affected focused
tests passing. The full-suite repeat, clean paired development repeat and
untouched host holdout remain qualification gates;
these exploratory fixes are not final scorecard results. Every failed attempt
and its original case database remain under
`%LOCALAPPDATA%/SystemSense/private-alpha-20260928`.

## Private-alpha local health-task qualification (2026-09-28)

This candidate supports one exact high-port loopback nonce health GET from a
normal desktop problem description. The suite in
`benchmarks/fixtures/private_alpha_cases.json` freezes 26 descriptions and
budgets; `benchmarks/ground_truth/private_alpha_recipes.json` holds independent
fixture modes and expected task outcomes. Their SHA-256 values are
`362361ec13b1483aae2cbc206f937683ede0714bf7a0ae57eeb2c19b1b056112`
and `bf87350b945af82a85b62e83fc91db1bb273fe10fb34546f1fed72c210cd85be`.
The first 13 are development cases; the reserved 13-case holdout is not used
to tune the mechanism. Earlier v1 attempts and manifests remain archived by
the executable suite rather than relabeled as final trials.

Before holdout execution, the per-case interpretation is: a healthy exact GET
must be reported as working despite the misleading complaint; HTTP 503 must
be reported as a failed response without claiming its internal cause; a
wrong-nonce HTTP 200 must be reported as an unexpected body; no-listener and
stall cases must distinguish the product GET from the later listener sample
without claiming that sample proves the request-time cause. An intermittent
case is judged against the outcome Dyad actually measured, not against the
earlier evaluator sample. The access-denied control must report the real 503
task result and a specific listener-evidence gap; its listener denial is
synthetic and excluded from real-access diagnostic rates. Every case requires
a healthy independent control, before/during/midpoint and restored target
checks, and the affected-task outcome saved inside the product. A generic
unknown is not a useful finding when these facts were available. Unsupported
definitive causes and healthy false-failure claims are zero-tolerance errors.

`benchmarks/private_alpha_loopback.py` runs either the actual subscription
Laya–Sol path or a basic rule route with the same registered access and case
budgets. The mode and independent oracle never enter the case or model prompt.
`benchmarks/private_alpha_score.py` preserves failures and timeouts in the
latency denominator and marks only *automated candidates* for specific
findings; semantic and causal review is separate. Warm time starts before
product service creation and excludes one cold provider setup, which is
reported separately. Resource sampling is evaluator process plus descendants
at 200 ms, not whole-host or attributable GPU load. The local report is kept
outside the repository because case evidence may be sensitive.

The current evaluation proves only this local HTTP task family. It does not
yet qualify three materially different families, adaptive useful-check
selection across them, or any verified application-internal root cause. The
private alpha is not ready until the remaining acceptance gates below are
met; a scoped response finding is not equivalent to a root-cause diagnosis.

The final development pair before the held-out run is preserved privately as
`v2-development-model-04`, `v2-development-basic-04`, and
`v2-development-scorecard-04.json`. The actual model path completed all 13
cases with one nondegraded Laya mixed-frontier choice and one acknowledged Sol
review each. It selected the registered listener measurement from the exact
task event, saved the task's HTTP outcome, and independently restored every
owned target. The automated scorer marked all 12 real-access model cases as
specific-finding candidates versus 7 of 12 for the task-aware basic route;
the one model access-gap control used a real HTTP 503 task and synthetic
listener denial. Manual review of the saved development summaries found no
unsupported definitive cause and no healthy false-failure claim. It assessed
the 12 real cases as useful *scoped response and follow-up findings*, not
verified causes. These development observations do not estimate general
diagnostic accuracy or replace the unseen holdout.

Warm model time across all 13 development cases, including the synthetic
access control, had median 13.516 s, p90 17.640 s, maximum 17.641 s. Basic
median was 0.360 s, p90 2.375 s, maximum 2.375 s. Cold model admission and
startup took 15.610 s separately. The peak sampled model evaluator process
tree RSS was 2,292 MiB, versus 73 MiB for the basic route. A whole-GPU sample
during an earlier model run read 2,596 MiB used and 1,280 MiB after its owned
runtime closed; other host work can change those figures, so the difference
is not attributed GPU memory. No case in this pair failed or exceeded its
90-second budget; these are single-run distributions, not confidence bounds.

Preserved failed attempts matter here. The first v1 development run missed
scoped HTTP 503 closure. The first complete non-MCP suite for this candidate
failed three tests: the scoped speed edit removed a legacy common resource
probe in broad cases, and one factory test expected the old managed-runtime
callback shape. The baseline was restored and the test now checks the new
callback explicitly. In `v2-development-model-03`, removing the irrelevant
`core.system` collection without emitting the already observed task as a
frontier event caused an early Sol review before listener collection. All 13
cases still completed and restored, but Sol calls doubled to 26, warm median
rose to 28.906 s and p90 to 32.375 s. The repaired task observer now appends
the exact evidence/execution event atomically with the observation. The
development-04 pair measured one Sol call per case after that repair. Neither
the passing scoped check nor the speed gain alone proves alpha acceptance.

### Clean-source reserved evaluation at `aa5520a`

The first reserved holdout and a repeated development pair used the exact
same clean source revision, frozen manifest/key, read-only catalog and
90-second case budgets for model and Basic. The paired scorer rejects a
different source revision or dirty diff. Its development and holdout JSON
reports have SHA-256 values
`91fc57226f90eb767727cdfcd36873f97a32472356be7fd08912a776ab68ecd2`
and `d550c7d72f8b9be0f0ede71b909b08e6a765019ced8ca39ec4700fb28ba1fade`.
The private manual holdout review has SHA-256
`61c42441122977c03eabae0d376b45539618d304c45cfd9a01eab4fc7a616ee6`;
it records every case's scoped finding and gap.

| Paired clean-source result | Actual Laya–Sol | Basic rules |
|---|---:|---:|
| Cases completed / all cases | 26/26 | 26/26 |
| Automated specific-finding candidates, real access | 24/24 | 14/24 |
| Independently restored controlled targets | 26/26 | 26/26 |
| Warm median / p90 / maximum, including all cases | 14.485 / 17.906 / 19.688 s | 0.344 / 2.375 / 2.391 s |
| Peak sampled evaluator process-tree RSS | 2,295 MiB | 73 MiB |

Cold Laya admission/startup was 15.438 s for development and 15.422 s for
holdout, excluded from warm case time. Both model sets had one nondegraded
Laya catalog choice and one applied Sol review per case. The private installed
candidate passed startup, healthy and 503 model runs, cancellation and
uninstall; installer SHA-256 is
`38771cf9bb82eac9ce4aecfcffbac540712aba6b034729645d5bc03f2965a3db`.
The non-MCP Python suite passed 3,785 tests with 32 opt-in/environment skips
and one deselection; Pyright, Ruff lint/format, desktop unit/lint/type/format
and packaged actual-model checks passed. Installation was private on this
host, not a clean-machine qualification.

Manual review of the saved holdout summaries found zero unsupported
definitive causes and zero false failure claims on healthy or observed-success
intermittent controls. Five real transport cases gained a time-bound later
listener distinction over Basic; response and healthy cases were already
largely answerable from the exact GET. The denied-listener controls use real
HTTP 503 tasks but **synthetic** access denial and are excluded from the 24
real-access cases. The scorer's positive count means a useful scoped
observation or next check, not a verified root cause or broad diagnostic
accuracy. Model and Basic were offered the same registered access and
budgets; Basic chose not to take the later listener check.

The bounded catalog offered Laya only **one** measurement candidate per
case, `network.listeners`. Its selection therefore does not show adaptive
choice among several useful checks. Sol's rivals often named
`application.snapshot`, `incident.events` or `pressure.sample`, but those
were unexecuted in this exact scope. The final prose is deterministic
coordinator closure after an applied Sol review, not freely generated Sol
diagnosis. The 26 cases all belong to one local HTTP health-task family;
independently unknown causes, real missing-access controls, three-family
adaptive behavior, and root-cause accuracy remain unqualified. These are
failed alpha gates despite the narrow reliability and latency results.

## Controlled affected-task trial (2026-09-28)

At product revision `868b94c`, a private operator runner used two test-owned
loopback HTTP tasks with different nonce paths on ports 55277 and 55278. A
preregistered rubric (SHA-256 `0986a96d0bdc6332d46ac58e0083d11a8cd2821a1a0cd5939f56b0f922a9fd86`)
required independent before/during/after outcomes, model blinding, the actual
Laya–Sol route, and final use of a complete exact-target listener observation for
diagnostic utility. Trial 01 stopped before any model call because the runner
expected connection refusal but Windows returned a timeout; its artifact was
preserved. Trial 02 used the corrected oracle and completed. Private receipts
are under `%LOCALAPPDATA%/SystemSense/controlled-task-20260928/trial-02`.

Before intervention, both exact nonce GETs returned HTTP 200 with one listener
each. During the test, only the owned target service was stopped: its GET timed
out in 2.016 s and no target listener existed in the independent socket table;
the control still returned exact HTTP 200 with one listener. A midpoint readback
confirmed the same split. After restart, the original target URL and nonce
returned HTTP 200, as did the control. Both temporary services were then
intentionally removed; cleanup reported no errors, and a separate read-only
check found neither fixture listener nor process. These receipts prove task
failure and recovery within the fixture lifetime, not persistent availability.

The failed case ran for 50.531 s with 87 completed Laya rank protocol calls and
three acknowledged GPT-6 Sol subscription calls (13.531, 17.781, 16.766 s).
The healthy control ran for 42.547 s with 17 completed Laya calls and three Sol
calls (8.281, 13.188, 16.891 s); neither case reported a Laya call failure.
The Codex adapter acknowledged `gpt-6-sol`, `authentication=chatgpt`, no
environment access and zero MCP tools. Saved Laya requests and all six Sol
prompts showed no operator stop/restart action, oracle or rubric. A model sees
the reported target failure, which remains correctly labeled unverified inside
the case. The independent task oracle was outside model input.

**Diagnostic utility failed the frozen gate.** A registered `network.listeners`
observation in the failed-case database at 16:43:23 UTC captured 41 listeners,
zero omitted, no listener on target port 55277, and the healthy control on
55278. Its evidence ID and summary appeared in Sol's final catalog, but the
focused facts and omission count did not reach that prompt. Sol finished with
`no_progress`, no assessment, and a careful statement that the visible data
could not distinguish a missing listener from a stalled HTTP handler. That
avoided a false cause claim but missed the supported sampled-time listener
finding. The healthy case ended `insufficient_observability` with no assessment
or unsupported failure claim. The cause of the listener's disappearance was
known only to the operator and was not a model-visible observation. The target
GET and listener sample occurred at different times, so even complete listener
facts would support absence at sample time, not at the exact GET instant.

The failed-case database SHA-256 is
`ea078ca36b79bf3b1dcf9ebd62da71ee406d2ac497dfb93557585c03ea37d58b`;
the during-failure and after-restoration oracle SHA-256 values are
`27b09a645a8a447b6c788cfd47ef0c79d35859c0ef5d6016c68f675d136de94d`
and `06288f8f1a591c66fa6e3cb4d416f4959c5dfea93ce17440925260a229a345cf`.
One paired trial does not establish diagnostic accuracy, throughput, p95 speed,
or comparative superiority. The next engineering gate is to deliver relevant
completed exact-target probe facts to the deep focused packet, then assess a
new blinded trial without rewriting this failed result.

## Controlled task repair and breadth (2026-09-28)

At `e02fb72`, the saved listener table's exact target-port search became a
bounded, source-linked excerpt. It records the sampled port, collection interval,
omission count, and limits. It reports no listener only when the saved table and
retrieval scan are complete. A positive listener match still retains its source
row. At `45d5d96`, a literal loopback IPv4 target starts with the registered
`network.listeners` check. `e9cf872` excludes already selected mixed-frontier
items after an idempotent upsert, and `575ab7f` reserves exact-target evidence
inside every bounded Sol brief. These changes do not observe the user's GET or
grant the models new machine access.

The private, frozen no-listener protocol SHA-256 is
`59a777cc1663b27aa786ccda9004d9c87e4119e05b4ece1907f6412f957a1532`.
Its fresh randomized development and heldout cases at `e02fb72` each
independently verified exact nonce HTTP 200 for target and control, then target
timeout with no target listener and control HTTP 200, then both HTTP 200 after
restoration. The two temporary services were removed. Actual pinned Laya and
subscription GPT-6 Sol ran blind on the failed task and a healthy control in
each cohort. The failed-case final state cited the saved exact-port listener
evidence and stated absence at the later sample time, without claiming why the
service stopped or its precise request-time state. Both healthy cases avoided
false failure claims. Warm failed-case times were 67.047 and 51.266 s, mean
59.157 s; cold Laya startup was not measured separately in this first pair.
The source-linked listener finding is narrower than a confirmed root cause.

Efficiency was frozen separately before each candidate. The first routing
attempt at `45d5d96` crashed on an already-selected mixed item; its target
was restored, and the fault and crash remain in the private record. The
`e9cf872` development case completed, but its final brief evicted the
target-port fact, so its 62.156 s was rejected for correctness; no v2 heldout
case was run. After `575ab7f`, development and heldout ran without a source
change under protocol SHA-256
`b6fd13bffaccf8a3a7f23a23a6f536a88e86d134c1af67d1bfacc53abeed7003`.
Every final Sol prompt kept the complete target-port excerpt; both final
states reported later sampled-time absence and retained uncertainty. All
before/during/midpoint/after independent checks and healthy controls passed.

| Correct no-listener pair | Failed case, warm | Healthy case, warm | Sol calls, failed / healthy | Laya rank calls, failed / healthy | Cold Laya startup |
|---|---:|---:|---:|---:|---:|
| First development | 67.047 s | 39.031 s | 4 / 3 | 97 / 17 | Not measured |
| First heldout | 51.266 s | 36.922 s | 3 / 3 | 17 / 15 | Not measured |
| Optimized development | 45.484 s | 38.859 s | 3 / 3 | 85 / 22 | 13.891 s |
| Optimized heldout | 51.469 s | 41.813 s | 3 / 3 | 80 / 23 | 13.969 s |

The matched correct failed-case mean fell from 59.157 to 48.477 s, an
**18.05% reduction**, below the frozen 25% target (44.367 s mean). These
are two pairs, not a throughput or statistical speed claim. The dominant
observed cost is three Sol calls per optimized failed case: 41.422 and
48.546 s summed call latency, respectively. Laya still made 80–85 rank
protocol calls and pursued pressure/storage checks with little direct value
for this exact task. Listener collection was useful but was seeded by
deterministic routing, so this does not prove Laya chose the decisive check.
The completed check list includes broader probes whose utility remains
unproven. Cold startup is excluded from the warm comparison.
The optimized failed cases each executed nine registered probes. Their summed
execution durations were 17.106 and 17.475 s, including 7.315 and 7.352 s
pressure samples; probes overlap Sol calls, so these sums cannot be added to
case wall time. Wall time outside the captured Sol calls was 4.062 and
2.923 s, containing selection, scheduling, collection outside model calls,
and local waiting; this runner did not separately time those subphases.
All captured Sol calls returned, with no validation retry in this pair.

At `6c278e4`, an additional bounded-packet change removed the duplicate raw
listener list from Sol briefs that already carry the deterministic
`target_listener_search` excerpt. The saved table remains available for
explicit detail retrieval. The first failed-case Sol prompt shrank from
25,080 to 21,015 bytes in the matched development pair, and the new
development and heldout prompts retained the exact target, source time,
omission count and limits. The v4 protocol was frozen first (SHA-256
`3944df1031731cdbe3674fe8b21e4bfdde2044b5e98d167843fb9e2d126f621a`).
Both fresh v4 target/control cases passed the before/during/midpoint/after
oracles, supported sampled-time absence in the final state, and restored
then removed the fixtures. The controls made no false failure claim.
However, warm failed-case times were **47.563 and 76.188 s** (mean
61.876 s), **4.60% slower** than the first correct 59.157 s baseline.
One heldout Sol call took 45.625 s; three Sol calls still ran in each
failed case. The packet is smaller, but the frozen 25% speed target was
not met. No speed gain is attributed to this change.

The separate `resource-01` run at `6c278e4` used the same guarded fault
and restoration procedure, with a private 200 ms process-tree sampler
(protocol SHA-256
`5330f2c2f8fa8a6e4750c84aa6c4928ce397551e81805f6e2cdfdcdffb49a755`).
It is excluded from the matched speed calculation. Across 513 samples,
the runner and descendants, excluding fixture HTTP services, peaked at
**3,142,295,552 bytes RSS** and **17 processes**. Observed process CPU time
was at least **85.078 s**; two sample reads failed. Polling can miss
short-lived processes, and GPU memory and system-wide interference were
not measured. The 51.375 s failed case retained the narrow listener finding,
its healthy control made no false claim, both tasks returned 200 after
restoration, and no fixture listener remained. The resource profile SHA-256
is `46694b6ddaee2d4a4a37124f9dc56ed4a4c3fa37728ac1cea07a45b1e3def6af`.
The three new failed-case database SHA-256 values are
`28ecda0b8c3029ebc045f9ac3a89f7a2e4695863754d281affe50428099d4663`
(v4 development),
`d200869bbc5b0c8e2140b6ae83be9e5becfa536aaa43a738d290e8f02f4fd441`
(v4 heldout), and
`48ea2d530662520682f8f5909a91e134a1b74c67c32b906c999aab9ebe235df0`
(resource run).

Across the two v3 optimized failed cases, registered execution records show
nine distinct probes each and **zero repeated executions**. Six probe types
in each case had no evidence ID cited in the final hypotheses; this is an
uncited-collection count, not proof the observations were useless during
search. Recorded provider calls sum to 1.828 / 1.421 s for Laya catalog
attention and 2.356 / 0.501 s for keyword fast decisions in the v3
development / heldout failed cases. These are selection-related calls,
not complete Laya rank wall time. Sol-call wall, 41.422 / 48.546 s,
includes both service waiting and reasoning; it does not separate them.
Probe-execution intervals and provider calls overlap, so their sums cannot
be added. The remaining 4.062 / 2.923 s outside Sol-call wall includes
local selection, scheduling, collection and waiting that this runner
cannot partition. These are explicit timing gaps, not measured zeros.

The saved Sol prompts bind the listener findings to these exact source
observations on 2026-09-28 (UTC). Each no-listener search reported zero
omitted listener rows; positive cases preserved the matched listener row.

| Case | Exact target | Listener evidence ID | Observed at UTC | Finding at sample |
|---|---|---|---|---|
| First development | 127.0.0.1:56788 | `ev_9a05cb2f378944cb90c4b236ad919f04` | 17:00:23.541636 | No listener |
| First heldout | 127.0.0.1:60353 | `ev_6b48ac025348460989268ec67f6b3ba1` | 17:04:17.247607 | No listener |
| v3 development | 127.0.0.1:55687 | `ev_ae6f8bb48c884e07904c1fa55f1d567c` | 17:20:49.866504 | No listener |
| v3 heldout | 127.0.0.1:56128 | `ev_fee86707f3a44aea989771781f88b850` | 17:22:55.551826 | No listener |
| v4 development | 127.0.0.1:55013 | `ev_2ebbad7bf3004fb0b920850e0101555d` | 17:48:33.533962 | No listener |
| v4 heldout | 127.0.0.1:55814 | `ev_8aa8d1cdf917404784d717a3c958fdc0` | 17:50:38.644355 | No listener |
| HTTP 503 | 127.0.0.1:49177 | `ev_b8bdcface96947e881e76ce709c5a5ab` | 17:33:19.836832 | Listener present |
| Stalled GET | 127.0.0.1:65104 | `ev_0dacad989e1b406aaf6a96fe151db162` | 17:35:45.626842 | Listener present |
| Resource run | 127.0.0.1:49183 | `ev_a128ee66aed340e89e5d6fab2178bd3a` | 17:54:10.887305 | No listener |

These are later collector samples, not observations at the exact GET instant.

Across the seven completed no-listener cases that met the frozen
correctness rules after the evidence repair (the first two, v3 pair,
v4 pair, and resource run), the final failed-task summaries identified
the exact-port later listener absence in **7/7** cases without inventing
a deeper cause. Across their seven healthy controls and the two
additional fault-family controls, **0/9**
final summaries falsely called the healthy task broken. The crashed
optimization attempt, incorrect v2 development result, unrun v2 heldout,
and original pre-repair miss are excluded from those denominators and
reported above. The repeated fixture family, small sample and unverified
model-side HTTP outcome prohibit a general diagnostic-accuracy claim.

A second private protocol, SHA-256
`6cdd20d4d1f1e2f93845506b48f68de76e36616e5c147f17b47b32639f4d31fa`,
used the same test-owned loopback service and separate healthy control for two
different failure mechanisms at `575ab7f`. The operator-only fault mode and
independent oracle were never passed to the case. Model-visible intake had the
reported result, explicitly unverified. Both cases independently measured
target and control HTTP 200 before, target failure with a target listener and
control HTTP 200 during and at midpoint, both HTTP 200 after restoration,
then confirmed fixture removal:

| Fault observed by independent oracle | Failed / healthy warm time | Sol calls | Laya rank calls | Final model finding |
|---|---:|---:|---:|---|
| Target HTTP 503, listener present | 47.359 / 41.609 s | 3 / 3 | 70 / 22 | Exact-port listener observed later; reported 503 unverified to model; handler cause unknown |
| Target GET timeout, listener present | 55.406 / 35.422 s | 3 / 3 | 74 / 23 | Exact-port listener observed later; no HTTP exchange measured by product; server/client cause unknown |

The positive listener row reached all three Sol prompts in each failed case,
with exact target port and observation time. Both final states separated a
listening endpoint from an observed HTTP outcome and made no unsupported
definitive diagnosis. Neither healthy control was called broken. The 503 and
stall results distinguish two fault mechanisms in the independent oracle;
the product's current registered checks do not distinguish their deeper
causes. It did not independently replay the GET. Complete Laya input capture
remains absent, although protocol call counts and the captured Sol requests
confirm the actual pinned Laya plus acknowledged `gpt-6-sol` ChatGPT route
with no tool or environment access. These are bounded real-fixture
investigations, not general Windows diagnostic qualification.

All new raw prompts, model returns, custody, private databases and independent
oracles are under
`%LOCALAPPDATA%/SystemSense/controlled-task-repair-20260928`. The breadth
failed-case database SHA-256 values are
`42b113be9ca880bd109c0e9b6161c860c556cf7f600cc8d9d2cc67cdda4a2b31`
(503) and
`b192654420e3028ec5ed1cddd8f86914c4f0448180ef738f96e98a576f92d752`
(stall). The v3 development and heldout failed-case databases are
`7a00d82cde9e369ab76fdd39b029addd466db4939288d5c7b052a081713ccecf`
and
`b2f7897ff7045a5ea2a3b82c33ccd066b3fa4b7bf79363316abe7a0c2eefed5f`.
Every attempted new fault was independently restored, and cleanup reported
no errors. The opt-in live-model test suite was not run as part of the broad
automated gate; these preserved trials supply the live-model evidence.

## Product-observed loopback trials (2026-09-28)

Code `caa49704cc0dddfe1952e12c8f9042e8c9033056` adds an internal,
exact-scope product GET observer. A private one-shot runner first verified a
test-owned target and separate control returned HTTP 200, applied one fault,
and independently measured the fault and healthy control. It then opened a
fresh Dyad case with neutral reported outcome text and let the product replay
the exact GET. The independent fault mode and oracle files were outside the
case databases and model prompts. After each fault case, the runner checked
that the fault and control had not drifted, ran a healthy-control case, restored
the target to HTTP 200, independently verified both endpoints and listener
state, then stopped only its two owned fixtures. A final socket check found no
listener on any of the 12 trial ports.

Two fresh paired runs per family were made without changing the code or
protocol between runs. The evaluator checked product task facts against its
oracle only after cases finished. It also checked the Laya-ranked candidate
snapshot, exact candidate admission and listener execution, applied Sol
mailbox, source IDs and citations, acknowledged `gpt-6-sol`/ChatGPT runtime,
zero model tools/environment access, and absence of oracle fields in prompts.
Each case had one source-bound useful candidate, `network.listeners`, so this
is evidence that Laya selected and executed that check, **not** a broad
candidate-ranking result. Sol's six raw fault responses were separately read
for unsupported causal claims; all kept the request-time gap explicit.

| Fault family and repeat | Product-observed fault | Listener later | Fault / healthy warm seconds | Sol calls, fault / healthy |
|---|---|---|---:|---:|
| No listener 1 | GET timeout | Absent | 17.063 / 10.953 | 1 / 1 |
| No listener 2 | GET timeout | Absent | 16.422 / 11.594 | 1 / 1 |
| HTTP 503 1 | HTTP 503 | Present | 14.016 / 13.203 | 1 / 1 |
| HTTP 503 2 | HTTP 503 | Present | 12.375 / 11.891 | 1 / 1 |
| Stalled response 1 | GET timeout | Present | 16.094 / 12.984 | 1 / 1 |
| Stalled response 2 | GET timeout | Present | 14.375 / 13.188 | 1 / 1 |

All **6/6** fault cases completed product task observation, a Laya-selected
registered listener check, an applied Sol review that used both evidence IDs,
and a supported narrow observation with a specific unresolved causal gap.
All **6/6** healthy controls observed HTTP 200 with a matching nonce and made
no false failure claim. All **6/6** independent restorations passed; fixture
cleanup reported no error. The median warm case was **15.235 s** for faults
(range 12.375–17.063) and **12.438 s** for controls (10.953–13.203).
All 12 cases were below the 30-second warm target, with one nondegraded Sol
call and 10 completed, nonfailed Laya rank protocol requests each. Cold Laya
provider construction before each pair took 14.094–14.250 s and is excluded
from those warm times. These are small related fixtures, not a general
diagnostic success rate, workload p95 or cold-start claim.

The product proved an HTTP 503 response, which rules out simple connection
failure for that replay, but not why a handler returned 503. A listener seen
after a stalled GET does not prove it accepted that request. Later listener
absence in the no-listener case does not prove absence during the earlier GET.
All cases therefore ended `insufficient_observability` for application cause,
with different observed outcomes and exact missing links. Sol proposed other
host checks in some raw responses; this exact-scope trial did not run them,
and their possible value for a broader investigation remains unmeasured.

All development attempts remain under
`%LOCALAPPDATA%/SystemSense/controlled-task-repair-20260928`, including the
pre-repair `product-no-listener-dev-01` through `-09`, 503/stall development
runs, a 90.219 s no-listener attempt with six Sol calls, and controls that
missed 30 seconds. They are excluded from the fixed-code repeated denominator,
not erased or counted as successes. The final private evaluator artifact is
`frozen-scorecard.json` (SHA-256
`1b85a89f054a38ca55ca16d120926109d389bbc2a8608e29a3033a42a12766b6`).
The one-shot no-listener protocol SHA-256 is
`1dad7724a3568f88d48cfb1ff0cbc1a299166f0ded29d266019de8a17d51be31`;
the 503/stall protocol is
`e9576ffd7d9fbe4afde3469b3bd422c0aa1ab5ffee59c7e7f45b82e34984344c`.
The evaluator script is saved beside them. The desktop/default route and any
non-test-owned task were not qualified by these runs.

## Reversible local Windows checks (2026-09-28)

These five single-run cases used live read-only Windows probes, an isolated case
database for each intervention, the `keyword-baseline` decision provider, and
deterministic reasoning. The changes were bounded and reversed in the same
guarded run. The cases do not include an independently measured affected task
or a supported diagnosis. Source reports and read-only database captures remain
under `%LOCALAPPDATA%/SystemSense/live-*-20260928`; the private combined
`live-investigations-20260928-scorecard.json` has SHA-256
`b33ff109fbdfaab278f37821719441abbb846e1fbb2e0f9a5069a98b151d9368`.

| Change and revision | Case elapsed | CLI wall | Registered result | Outcome |
|---|---:|---:|---|---|
| Duplicate of active High performance plan, `25fab23` | 2.55 s | Not sampled | `power.snapshot` saved temporary scheme ID | Unknown cause |
| Dormant WinINet proxy-server string with `ProxyEnable=0`, `25fab23` | 1.80 s | 2.91 s | `network.configuration` saved server and disabled state | Unknown cause |
| Temporary background process before fix, `25fab23` | 1.33 s | 2.36 s | `application.snapshot` was not selected | Unknown; routing failure |
| Same process class after fix, `0b83e0f` | 7.04 s | 8.51 s | Snapshot saved exact PID and creation time | Unknown cause |
| Process-exited control, `0b83e0f` | 6.12 s | 7.31 s | Earlier exact process identity absent | Unknown cause |

Each case recorded five provider calls, zero degraded calls, zero unrecorded
attempts and no definitive assessment. The longer process case reflects the
new registered collection. The pre-fix process named PowerShell; the post-fix
process named Python and also selected `local_ai.snapshot`. These are not
matched workloads or a performance improvement claim.
The post-change process and control cases sampled the CLI process tree every
50 ms: 201 MB and 221 MB maximum observed RSS, respectively, with up to 9 and
11 live sampled processes. This excludes exited children, external servers,
host and GPU peaks. Five cases cannot establish a latency percentile.

The collector accepted 688 process rows in the positive scan; it saved 256
and explicitly reported 432 omitted. The exact temporary identity ranked 11th
by creation time in saved source evidence. The
compact report displayed only 21 process entries and marked retrieval as
truncated, so report-only inspection did not show that identity. An independent
read-only database check found it in the positive case and absent in the
post-exit control. The collector can still miss a process outside its recent
slice, and candidate paging can omit one outside its 16 recent slots. The
active power plan and all 354 recorded AC/DC indices matched their baseline
in a saved after-restoration readback; the duplicate plan was deleted. The
proxy server value was removed and `ProxyEnable` stayed 0. The temporary
process exited; the existing Dyad and Ollama processes were alive at the
post-intervention readback. No fault, repair, broad network change or user case
database mutation was introduced.

## Immediate integrated pre-training gate

An ordinary local investigation must show **both actual models** available together: Laya remains warm and can decide while the deep model reasons. Sequential swapping is reported only as a low-memory fallback. The frozen menu must contain genuine competing relevant choices; not every case needs all four action kinds. Important nested GPU/process values must reach Laya as structured input. Distinct target, parameters, and observation window must define candidate identity.

Capture one reproducible end-to-end trace: relevant evidence persists; Laya ranks several meaningful alternatives; a selected read-only measurement is admitted and launched before an unrelated probe ends; further evidence changes the frontier; Laya redirects on counterevidence while the actual deep model is still running; the deep model updates competing hypotheses without stopping the fast lane. Include provider fallback, stale decisions, failures, and case-budget behavior. Report every stage from persistence through invalidation, queueing, batch, inference, validation, admission, dispatch, probe completion, deep response, and diagnosis.

With enough eligible work, target **at least 20 distinct useful candidate judgments per second** on this RTX 4090 and **under 400 ms p95** from relevant evidence persistence to admitted follow-up. Count all eligible events/attempts, including queue misses, timeouts, failures, and abstentions. Report cold and warm runs; p50/p95/min/max/sample size; foreground load, RAM/VRAM, and the fraction of candidates that produced useful information. A synthetic packet microbenchmark or non-isolated small sample cannot qualify these targets. Do not optimize throughput by ranking duplicates or hiding skipped events.

Produce one small replayable Windows pilot using exact runtime inputs and independent outcomes described in [Training plan](TRAINING_PLAN.md), or record the exact consent/environment blocker. Do not train yet.

## Historical two-turn evidence (2026-09-27)

At code `5d9cd53` (and integrated ordering fix `d010b46`), B's preregistered
one-cell, 52-source synthetic replay first failed because a bounded 48-record
packet dropped the source cited by two
predicted rivals; the next 12-context reasoning request then omitted both
rivals. A retained that failed artifact, prioritized task, explicit demand and
one selected source, then rotated rival citations inside both existing bounds;
B reran the same test. C's blind
score and independent SQLite/receipt readback confirm one accepted source-cited
prediction turn, one subsequently admitted registered read-only observation,
an exact later fact that contests a prediction, and a second applied reasoning
turn whose resulting state retains both rivals and the original citation/stamp.
Terminal state is `no_progress`, assessment is absent, and both rivals remain
contested. The
new scripted mechanism passes 1/1; the original 16-cell provider's
prediction/next-test gate remains failed 0/16.

A separate pinned local-Qwen call on the first synthetic request needed a
bounded output-token retry in its one nondegraded attempt; two earlier attempts
degraded on owned Ollama endpoint startup. It proposed a probe and two
categorical predictions, but their fact name and values did not match that
probe's declared/observed output. Therefore the real-model prospective
discrimination gate remains unmet. None of these runs is a matched policy
comparison, real affected-task outcome, supported cause, or speed result.
The final `d010b46` combined non-MCP gate passed 3,369 with 31 opt-in skips;
the desktop and offline packaging gates also passed. Private artifact hashes
and exact failed attempts are in [Build history](BUILD_HISTORY.md).

## Session A evidence checkpoint (2026-09-26)

At `38a3909`, the alternate deep-only search policy is built on the existing
`FrontierRankRequestV1` rather than a separate search tree. Its opt-in v4
factory shares one owned pinned local model across decision, frontier, and
reasoning. CPU tests exercised complete, omitted, duplicated, foreign,
unconsidered, unfit, and worker-capture refusal paths; 132 focused tests and
34 adjacent investigator/storage tests passed. No actual-model alternate-policy
cell or matched speed experiment has run at this revision. B found that a
fresh-case first decision has a slightly different *remaining* budget even
under the same frozen initial budget and menu; strict byte-identical
model-visible request parity and diagnostic gain cannot yet be claimed.

At integrated `840596f`, one actual local-model four-arm frozen
`toy-network-002` execution completed all cells, and the exact checkout's
artifact verifier passed. This is execution completeness only. Independent
readback found no `local_deep` frontier rank and no Laya decision/frontier
rank in any model arm. The deep-only Ollama decision degraded to keyword
fallback, while both mixed arms made keyword fast choices and one actual Qwen
reasoning call. Each arm acquired one useful toy evidence item and three
wasted probes, missed one offered opportunity, and made no supported cause
assessment. The frozen report has no exact affected-task target or expected
outcome; first-request content, remaining budget, and raw bytes also differ.
Wall times were 0.250 seconds deterministic, 27.297 deep-only, 9.906 mixed
Scout-off, and 10.047 mixed Scout-on. These are **not search-policy speed or
accuracy estimates**. The private manifest SHA-256 is
`5966051A9FCA779C3C881B38279AC60528608CCF82C02327789C8AF705BFF19B`;
driver SHA-256 `F7570DF260A67165199A863A08E0A43284319D9A7E12E709DEBA745EE8F5746D`.
The resource slot was released after no owned Python/Ollama worker or managed
listener remained. At integrated `ee16b1f`, B's comparison gate requires
nondegraded durable provider calls for the named decision, frontier ranker,
and reasoner, with the frontier call tied to a source-backed menu at the same
state version. A completed fallback run cannot count as a realized policy.
The exact-code eight-case CPU replay verified artifact integrity and completed
eight deterministic cells; 24 model cells were unavailable and zero pairs
were realized or admissible. Private manifest SHA-256
`879C1E115659CEB0034E7DFADBED47598DB15C938F5EC136877B3E28303C5C1B`.
The original toy case databases have no source-backed event menu or candidate
snapshot, and the model arms did not execute the named frontier rankers.
The held second model episode needs a suitable source menu, matched first
request/budget, and a bound independent affected-task result before any
policy speed or cause-quality conclusion.

At integrated `5a294c2`, a separate versioned CPU-only source-backed
pilot exercises the existing durable event frontier directly. In each of
four synthetic cells across network/browser and application/performance
families, six accounted no-new-fact catalog pages precede one menu with four
distinct source-backed retrieval IDs. A scripted provider makes one
nondegraded `catalog_attention` call at the menu state version; source facts
are read only after selection. The exact-code verifier passed 4/4 cells on
A's checkout; 22 integrated focused benchmark tests and scoped Pyright/Ruff
passed. C found no exact hidden fact or cause label in rank requests, but
source titles/order cue relevance. Selected `ev49` reduces two declared toy
recipes while abnormal `ev50` reduces neither. This is evaluator-only recipe
compatibility, not an investigator-supported cause or an independent real
affected-task result. The direct event-turn fixture seeds 48 synthetic
background records so four target records fall outside the ordinary 48-row
context; its setup cost is artificial. The corrected Windows
`perf_counter` artifact recorded 170.943–174.302 ms across the six setup
pages, 322.607–326.441 ms to the first menu, and 494.183–505.544 ms for a
whole direct cell. These are **CPU paging stress timings, not policy speed**.
An ordinary `app.run` prototype reached scripted rank calls after a fixture
probe-count error was corrected, but its menu/selected IDs differed from the
frozen direct-turn case. No matched whole-trajectory or model-arm comparison
was admitted. Private corrected manifest SHA-256
`AE5E91ED3ECA8633ADCBA4D7089913E9DD3AB3A13C001CB6F21CAF98EA58C65B`;
the earlier coarse-clock artifact remains historical and is superseded for
timing. The separate full-run fixture below tests a stable postbaseline
source state and precise synthetic target/window across two hidden recipes
per family; a real independently observed task remains an open gate.

At integrated `97a241b`, B's separate CPU-only full-run fixture enters the
ordinary `Investigator.run` loop from a byte-identical closed postbaseline
checkpoint within each family. Eight scripted cells cover two hidden recipe
variants and two choices in each network/browser and application/performance
family. One registered `fixture.task_baseline` probe records an exact **synthetic**
target, expected/observed result and 500 ms UTC window. Each cell then has 52
preexisting synthetic source records, explicitly limited as having no on-case
probe execution; the only matching `probe_executions` row belongs to the task
baseline. One four-source menu appears at state version 30 with a nondegraded
scripted `catalog_attention` call. The exact-code private manifest SHA-256 is
`F9A5D630BA679EEAAC6E0A849D59090E67AD479E6C3C5392127CD173800ECE97`;
A verified its 8/8 integrity and three focused tests passed. C independently
checked the stored task/source custody before unsealing evaluator results,
though earlier provisional oracle code had been seen and strict unseen-label
blinding was unavailable. Four `ev49` choices reduce two toy recipe labels to
one; four abnormal `ev50` controls leave both. All runs end `no_progress`,
with zero supported causal answers and `comparison_admissible=false`.

The normalized validated prechoice request differs across hidden worlds in
`ev49`'s `source_record_sha256`. Current-adapter **static projections** of the
Laya and local-deep candidate descriptions, IDs, evidence packet wires,
symptom and briefs match within each family; no actual model transport ran.
The compact first-choice evidence packet exposes only the synthetic task action,
omitting its target handle, result and window, although these remain in the
stored typed baseline record. The 48 background records, six no-new-fact pages,
and roughly three-second CPU cell time are artificial paging mechanics, not
time-to-useful-evidence or model-policy speed. Source titles/order can cue
relevance, and no real Windows affected-task outcome exists. The prior `0afc087`
candidate misleadingly used the built-in `core.system` ID for a synthetic task;
`b7bb226` replaced it, and `97a241b` labeled preexisting source provenance.
The second matched model episode remains held pending a fully bound model-visible
task, actual provider-call parity and an independently observed outcome.

At integrated `dc4c8c4`, the full-run synthetic fixture uses the runtime's
version-2 task-observation binding. It records an exact reference to the one
executed `fixture.task_baseline` observation at the closed checkpoint, before
copying the database into eight cells. Runtime readback checks case, evidence,
source, collector/version/execution, record SHA-256, the seven exact task facts,
500 ms UTC window, and explicit synthetic/no-Windows limitation. Laya receives
the bounded task context as a required indivisible worker-state field across
evidence, probe, and compare stages; local-deep ranking receives the same typed
context in its prompt. An invalid persisted reference fails closed, records a
warning, and is quarantined. This remains a fixture-only contract; it does not
bind or verify a real affected task.

A's exact-code CPU replay at `dc4c8c4` verified 8/8 cells and retained
`comparison_admissible=false`; private manifest SHA-256
`71AD2C3D055F58B8DA629777B55242A95B90945E578FFD47388FEE7A3ED58F93`,
anonymous request packet SHA-256
`C9AFFF8D8ACE594FF489F5DD70D2E771C002D749561146BE1D02B68B13443407`,
protocol digest `10e2cebe6b1fe08ead2a955af3c78131e4fdd59ac9ec400513436942bd11c5f7`.
B's adapter test captures exact typed context in both actual ranking adapter
inputs for all eight cells and checks Laya's fitted state using a fake process,
tokenizer, and model tensors. It proves structural preservation, not installed
Laya tokenization, weights, ranking quality, or real task behavior. C independently
reran the adapter test and accepted only that restricted claim. A's integrated
focused gate passed 94; whole-suite/build results are recorded in
[build history](BUILD_HISTORY.md). The raw cross-world request mismatch by
`ev49` source-content hash remains, as do the synthetic source titles/order
cue and absent real outcome. There is still no admitted matched model-policy
or time-to-useful-evidence comparison.
The required worker-state field changes the exact Laya worker source pin at
`adc2b57`; older exact-batch captures must be requalified against this worker
before any later pilot admission. No weight update or training ran.
At `70f1eb5`, the linked eight-cell audit ran the actual Laya and local-deep
adapter serialization with fake transports, including Laya's fitted worker
state. Four same-choice hidden-world pairs had identical model-facing payloads;
the validated request still differed in the `ev49` source-content commitment.
All eight captures completed, and C independently reran the focused test and
checked blind inputs before evaluator labels. The source labeled useful after
retrieval was always first and uniquely task-titled. Both a first-item rule
and a lexical title rule would choose it in every pair. Reversing item order
was checked only at the adapter boundary; no reversed retrieval or model
trajectory ran, and the title cue remained. Thus this audit supports input
fidelity and identifies a confound, while `comparison_admissible=false`.
Selecting the abnormal host sample is an uninformative toy retrieval; it has
not been shown to induce a false causal claim. Private audit manifest SHA-256
`D32DDB1798DCE76A9EF4375A719F3473EDE87C303B58F6D0EEF622D6C0095609`,
blind input SHA-256
`9EF49306BD756393BF37A52CDB73F2C53778F27BF7BDFF4EED00C115DB44CE10`.
At `cd9218e`, a fixture-only source coverage relation can be derived from an
exact source row and the bound synthetic task target/500 ms window. It uses a
strict source type, collector/parser versions, locator, source identity, case,
UTC times, exact fixture row time quality and explicit synthetic limitation.
The model sees only full-coverage/nonmatch status and a no-cause limit; ordinary
sources have unknown coverage. A self-consistent fixture locator is not
independent producer authentication. At `9224197`, B's eight-cell ordinary
`Investigator.run` test alternated the covered source between the first two
positions with equal candidate titles, stored facts, quality, cost and time.
It checked both selected and alternative retrievals and that an unopened
source fact value stayed out of the prechoice request. C accepted this as
owner assembly and scripted retrieval only: every cell ended `no_progress`,
the equal facts distinguish no rivals, and no model ranked that balanced menu.
Five combined focused benchmark/source tests passed on A's integrated checkout;
65 adjacent source/frontier/historical tests passed before B integration.
At `83f5bb2`, B's sixteen-cell CPU replay crossed two hidden toy fact variants
per network/browser and application/performance domain, two covered-source
positions and two scripted choices. C froze its judgment from the anonymous
prechoice packet before viewing labels, then independently checked selected
SQLite row hashes, retrieved facts and the toy rival rescore. Eight full-window
source choices reduced two fixture rivals to one; eight different-target or
short-window controls reduced none. Every actual `Investigator.run` cell ended
`no_progress` without a causal assessment. The two source titles, cost,
quality and time are equal; the explicit coverage relation itself identifies
the full-window source. Reindexed executed choices give a coverage rule 8/8
useful on eight unique menus, first-item and title-tie-first 4/8, and a
title-only rule eight abstentions. These baselines were not separate runs.
Eight paired raw requests differ by source-content hash, while eight pairs of
fake Laya/local-deep adapter inputs match. Installed-model choices, real
causes, diagnostic speed, and a matched policy comparison remain untested;
`comparison_admissible=false`. The original frozen artifact is tied to
`83f5bb2` and private manifest SHA-256
`94E6FBB6768B08D4418D5CEB08A131EB0CD299D4D1305D63747CD74F6EDAF808`.
At `30f6314`, B corrected a future-reporting defect: any unjudged causal claim
now makes the total false-claim count unknown, with known false claims and
unknown cells reported separately. The frozen sixteen zero-claim rows and
their hashes were not rerun or changed. The later code's source-pin verifier
must not be described as verifying the older artifact.

At integrated `c309bf9`, a separate 16-cell CPU scripted provider replay
freezes the first postselection version-5 reasoning request and accepted
response. Exact receipt-backed selected source facts and the synthetic task
reach that request; eight full-window first choices revise support and
contradiction citations, and eight controls do not. C froze the blind score
before independently checking all 16 task/source SQLite rows, hashes,
receipts, first applied hypothesis revisions and terminal records. No row or
receipt mismatch was found. Later retrieval of the matched source in control
cells prevents attributing their terminal hypotheses to the first choice.
All 16 complete with `no_progress`, no cause assessment and zero causal
claims. The preregistered prediction/next-test gate fails: 0/16 first
responses have an expected fact, distinguishing probe or explicit next
evidence request. No timed counterevidence or installed model was exercised.
The scripted contrast reads fixture facts and coverage; it does not measure
model judgment, real diagnostic accuracy or policy speed. B's first private
replay executed 16 cells but its verifier failed on tuple/list JSON equality;
the corrected fresh artifact is code-pinned to B `597b4f9`, manifest SHA-256
`177B8EDDEB61915B6AFED146A73E583267032BA41D458E28C5303B23849CDB8A`.
On integrated `8cbe0ee`, 11 focused source/PDF/advisory tests passed and the
combined non-MCP Python gate passed 3,367 with 31 opt-in skips, one MCP
deselection and seven expected warnings in 638.42 seconds. One actual local
Laya/Qwen counterevidence overlap passed with seven menus, 16 distinct
offered IDs, two admitted read-only probes and one applied deep result.
Active ranking reached 5.887 distinct offered IDs/s, below the 20/s target;
no all-event 400-ms p95 or time-to-useful-evidence claim was measured.
The case still produced no supported cause. The exact log hashes and build
gates are in [Build history](BUILD_HISTORY.md).

Two direct final-code pinned Laya v4 calls used the frozen synthetic menu with
the full-window source at ordinal zero, then one. Both returned complete,
nondegraded four-item rankings with that source first. The request carried
the exact synthetic task context and source relation, but these calls did not
execute a ranked retrieval or inspect postretrieval cause facts. The known
coverage rule already succeeds on all eight toy menus; two direct model calls
do not establish model value, a real cause, or a speed comparison. The private
call logs have SHA-256 `9BAA1A8BD6F6B3AB0533CFCC684ACC1C8AC0315E56F755CF4A7EB573082B7122`
and `12D128276C413352AE177118580305907F96C99CD8FF77052110FAC67529B6FE`.
At `2b258a5`, the snapshot path also rechecks that exact source binding before
a ranked measurement selection or execution link. A focused source-change
regression and 35 related tests passed. One capture-off policy comparison was
still **not** run: the single actual pinned Laya v4 functional call used one
frozen four-source schema-2 request and returned a complete nondegraded ranking.
Its five exact worker captures (four evidence, one probe) all contained the
same complete task context and model input. It did not exercise actual
Qwen ranking, installed-model compare stage, affected-task observation on
Windows, or an independently adjudicated cause. Private log SHA-256
`10461582E42DEB38E8C30C57513CF19D9D9EA4CEA8D8EB8B947E91E9B8BE5252`.
Two preparatory attempts produced no model result: a private script outside
the repository lacked the test import path, then a historical v3 admission
helper was denied against the already migrated v4 host lease database. The
supported `warm-independent` v4 profile admitted the successful call; all
owned workers and leases were verified closed afterward.

A separate capture-off **actual-model scheduling demo** at `97a241b` passed
one opt-in test. Laya made seven menus with 16 distinct offered IDs and four
post-counterevidence selections while local Qwen was active; one deep response
applied. Two synthetic read-only probes were admitted. The case ended with
five unmet requests and no causal answer. Setup took 14.25 seconds; case time
was 12.14 seconds. Active ranking offered 5.885 distinct IDs/s, below the
20/s target, and no all-eligible-event p95 was measured. This is a synthetic
concurrency/input-custody check, not a matched search-policy or diagnostic
utility result. Private log SHA-256
`4ED55845784CE44C0DE3DF65902FF97C62E79CF27227FAEC1717467A45659A89`.

A separate component-only ranker smoke at `840596f` offered the same four
source-bound IDs and one synthetic evidence packet to actual Laya and local
Qwen. One cold Laya attempt fell back on its two-second worker deadline;
after explicit Laya prewarm, both rankers returned complete nondegraded
rankings on visible SHA-256
`13e22d6230b70282fd15a87600f46e590112e133638c7d9aba34ec65bad41883`.
Laya ordered indices `[4,3,1,2]`, local-deep `[2,1,3,4]`; rank calls took
140 and 9,203 ms with different warm states. No choice was executed and no
independent task outcome was bound, so this is an interface and coverage
smoke, **not a speed or cause-quality comparison**. Private result SHA-256
`62C27D9DE1F817A27A78E1E33D1448E55F6FD597FFF1ECB791F127BE945F5E98`.

At integrated `282771f`, B's exact-revision CPU toy trajectory comparison
completed 14/14 deterministic cases in each of two fresh replays. Selected
probe sets, useful counts, final compatible-cause labels, and per-probe
cause-reduction credit agreed in all 14; aggregate effects were 26 useful,
26 wasted, four unknown. Raw execution order differed in 11/14 and actual
first-useful time differed in 8/14, so this is not a stable latency estimate.
Forty-two actual-model cells were unavailable and zero full four-arm pairs
exist. The integrated focused benchmark file passed ten tests. The comparator
uses evaluator-only toy labels after the run; its compatible-cause label is
not an investigator-supported answer or independent Windows outcome.

A separate read-only local-model run at code `d449429` with an isolated 32k
warm development profile completed nine registered probes, four nondegraded
applied Qwen responses, three unresolved final hypotheses, and no assessment.
It exhausted its 60-second case budget. B's read-only saved-case evaluator,
integrated through `fba0a25`, found 13/13 support/contradiction citation
occurrences were visible and considered; it assigns **unknown** independent
correctness to all four applied responses. The reported browser action lacked
an exact target hint and expected outcome, and no independent affected-page
result was bound. Eight unique requested detail keys ended as three completed,
four pending, and one lost at the old four-item queue limit. The red regression
and bounded queue repair at `e32e540` address that loss; no changed-code live
case has yet shown a better assessment. A nonce-bound VM page would be a new
controlled target, not retrospective validation of this unspecified page.
The original 16k live run's ten protected-context prompt-fit failures and the
32k run differ in requests, probes and timing; this is functional evidence,
not a matched speed or diagnostic-quality comparison.

At A revision `a646320`, an eight-case deterministic linked episode replay
(`python -m benchmarks.sequential_investigator_episodes --output-dir <private-dir>`
with `--verify`) completed 8/8. Four browser cases now executed both registered
direct and external controls, compared with 0/4 before the control follow-up.
Across the eight cases the change used eight more probes (32 to 40) and 20 more
deterministic provider calls (36 to 56), while final compatible toy-world counts
and causal answers did not improve. Two cases retained two compatible recipe
variants each, but both variants in each case have the same labeled root cause;
the unrun battery-wear probe would separate variants, not competing causes.
The post-integration replay manifest SHA-256 is
`7B0E20919FB6E8F3B36D6BC25A4C72F26CDCF829B5A8A6B12201EEB77D7DD688`.
The typed-need resolver had no hypothesis requests in those deterministic
episodes; its exercised runtime evidence is a focused registered-follow-up
integration test, not a diagnostic gain. The cited brief and resolver passed 131
focused tests with the existing loop at `a646320`; the stable non-MCP gate
passed 3,268 with 31 opt-in skips and seven expected failure-path warnings in
556.08 seconds. Whole Pyright reported zero errors, Ruff lint/format passed,
and offline sdist/wheel build passed. These CPU toy episodes do not measure
host impact, real-model latency, Windows diagnosis, or Scout benefit.

At integrated revision `44414d2`, B's independent cause-equivalence scorer
confirmed that all eight frozen toy cases have one compatible *labeled cause*
despite two cases retaining same-cause recipe variants. A separate source-blind
fixed-rival advisory provider ran eight isolated cases from the same frozen
initial-state contract. It emitted two unresolved cause-family rivals per case
and requested only registered distinguishing probes; all declared
distinguishing probe IDs ran. The replay completed 8/8 with 40 read-only toy
executions, 8/40 unrun incidental battery probes, 16 unresolved final
hypotheses, zero revisions or contests, and zero assessments. Four of four
designated counterevidence-stage probes ran, but no prediction existed to
reconcile. The evaluator saw withheld labels only after execution and again
found one compatible toy cause per case; that is a fixture property, not an
Investigator answer. Replay manifest SHA-256:
`826E79C32CE9B7AFC22351F9513308AC032D2250FD14F233CAFD6E5C97B4C00B`;
cause score SHA-256:
`7C2C6F37F1307912FFAF8D0EEAD2BCAE4ED6342F19411463AB19CCF831162E74`.
The original readback links 24/40 executions to decision snapshots and finds
zero rows in its two adaptive admission tables. At later integrated `536ebb4`,
a read-only classifier checked the durable execution, step, snapshot, and
admission records on a fresh private eight-case replay: eight initial baseline,
eight trusted deep-requested batch, 24 fast snapshot-linked, zero adaptive,
and zero unknown selection paths. The trusted deep classification uses adjacent
`routing_superseded` and `collecting` steps with typed requested probe IDs;
it establishes a recorded selection path, not admission authority or an
independent cause. This explains why counting only decision snapshot links
missed 16 executions without implying an admission bypass. Fresh replay
manifest SHA-256:
`B26367EA60E1C0B3885F73614BA20E55006663EFF98B892E14628BB5FBCAAD4D`;
selection-path readback SHA-256:
`F4E8F3DB6F081E06F6037378C7DC73BE824BB368A67BD6EF7001509DAB01D766`.
Independently bound affected-task outcomes and evidential adjudication are
still missing; another battery probe would not resolve that gap. These were
CPU-only deterministic provider replays, not matched model-speed experiments
or Windows diagnoses.

At focused-tested `07b731c`, the existing PDF PageDown journey binder began
rejecting internally inconsistent UTC wall/monotonic sample order, action
placement, stable-marker sequence, interval bounds, and replayed visual timing
across trials. Forty-two integrated PDF witness tests passed; scoped Pyright,
Ruff lint, and format checks passed. No live PageDown action ran. The witness
is still host-only: v1 case exports do not authenticate the visual source or
bind their timing to the case, so this is neither an affected-task product
outcome nor a causal comparison.

At focused-tested `3f5982f`, a red integration case showed a later valid
reasoning response dropping a previously cited historical rival. The new
custody-checked transition retained both as unresolved after wiring into
synchronous and concurrent deep paths. It preserves exact trusted
contradictions and the original coordinator timestamp for repeated or omitted
predictions; unavailable or unshown citations and capacity omissions remain
explicit. B's independent review then found that an unshown historical
citation could be dropped when its excerpt left the compact packet despite a
durable case link. B's red regression turned green after A checked the stored
typed record/source and authorized historical owner; the citation is retained
as unshown. The prior historical contradiction and timed prediction checks
stayed green, and 103 focused deep/investigator tests passed with one opt-in
actual-model test skipped. The later code has not had a
new actual-model trial; the `44414d2` live trace below is earlier-code
functional evidence. A full combined gate for `3f5982f` is pending.

At code `2fad32a` (building on `7d61227`), the version-6 prospective test gate requires an exact
registered probe version, a top-level fact name, and a finite typed value
domain visible in the fitted deep prompt. The response validator rejects
unknown names, out-of-domain values, model-supplied probe versions,
predictions for completed probes, and predictions from an omitted optional menu. The coordinator stamps the
registered version, and later trusted observations from another collector
version cannot mark the prediction contested. A later same-ID advisory revision
cannot erase an existing custodied contradiction by changing its statement.
The one scripted B/C-reviewed
fixture trajectory produced a later `direct_origin_status=offline` fact and
contested an `online` prediction, but both rivals stayed contested and no
assessment followed. Its toy labels do not measure model diagnostic utility.
The first pinned-Qwen version-6 attempt at `051b17c` failed after an output-length
stop and startup collision on its bounded retry, yielding no usable advice.
At `3505d0b`, a retry reused the same reported owned listener and returned
validated unresolved advice in 22.985 seconds, but prompt fitting omitted the
registered menu and the model supplied zero expected facts. At `fe9e16d`,
optional catalog and graph material is fitted before the small registered menu
is omitted. A new pinned-Qwen call retained the menu, 12 focused observations,
and 20 catalog entries in both model calls; the first answer failed advisory
validation and the bounded second answer returned validated unresolved advice
in 20.016 seconds, with one read-only follow-up proposal and zero expected
facts. The exact first validation error was not captured. These are bounded
functional attempts, not matched speed experiments or diagnostic success.
No actual-model prediction-to-later-observation comparison has passed.
At `2626433`, an evaluation-only helper can label a newly returned local
advisory as Pydantic-invalid, outside the fitted visible prediction menu, or
past those first two checks. Its receipt contains only call order and hashes
of the request, fitted prompt and schema. One synthetic regression passed;
the earlier real-model artifact has no raw first answer or boundary receipt,
so its exact rejection subtype remains unknown. Passing these first checks
does not imply later response or coordinator acceptance. One subsequent
synthetic actual-Qwen run at `5a48a6a` captured four return boundaries:
`pydantic_schema`, `passed_initial_validation`, `pydantic_schema`, then
`pydantic_schema`. The first validated response proposed a registered
follow-up before the scripted source review. The same probe executed once
through an earlier frozen fast decision, with no model-origin admission link;
the source-bearing second deep request degraded and did not consume the later
probe observation. C's independent SQLite/receipt review found zero
model-selected executed checks, zero predictions, no accepted post-result
advisory, no assessment, and no supported cause. The 35.075-second run is one
failed synthetic capability trial with a 180-second case budget, not a matched
speed or policy comparison. Its first-boundary receipt cannot identify the
exact Pydantic field errors, and prior artifacts remain unclassifiable.
Later bounded trials identified the same missing `expected_value` field in a
version-6 returned prediction. Existing strict validation rejected it and a
single bounded retry recovered; no accepted prediction was fabricated. At
`eaccb39`, a late successful observation triggered one fresh deep review before
idle closure. The accepted third Qwen response saw the follow-up and kept two
unresolved rivals, but did not cite the new evidence in their support or
contradiction sets. The probe had already run through the fast path, so the
corrected `a2b8382` evaluator records a passed post-result review gate and a
failed model-selected execution gate. A first pinned Laya/Qwen trial at
`7bae699` did not prewarm Laya: its first ranking calls expired and later calls
reported runtime failure, with zero candidate snapshots. At `5920076`, the
runner prewarmed Laya for 29.840 seconds before case timing; all 19 source
rankings were nondegraded model results, then Qwen returned validated third
advice. The app run took 39.173 seconds. Its menu contained retrievals only,
so it still had zero measurement snapshots and zero model-origin check links;
the final rivals had no new observation citations. These are distinct failed
mechanics trials, not matched speed experiments, a useful check choice, or a
diagnosis. Private manifest SHA-256 values for the post-result Qwen trial and
prewarmed Laya/Qwen trial are `83F8981869AD34E18CE6B830820E198700D121CF23236D441F7B0060A0334FDE`
and `84C54390E6C6FAE4569990E03D852BBDC4EC839CE93A5492FEA20CA336FDBFE6`.
A separate opt-in synthetic performance case at `5920076` tested the existing
measurement path with actual pinned Laya and Qwen. It passed one functional
test in 38.47 seconds of test wall time. The case ran for 21.313 seconds,
recorded two model decision snapshots and two exact candidate admission and
execution links, and completed registered GPU and pressure measurements.
The changed pressure observation was present in the later Qwen request, yet
five final unresolved rivals cited no new counterobservation and no causal
assessment was made. Seven observed Laya menus offered 16 distinct identities
over 2.860 seconds of active ranking (5.594/second); the two candidate menus
inferred 11 distinct candidates over 1.148 seconds (9.586/second). Both are
below 20/second and neither is a matched policy-speed experiment. The private
test log SHA-256 is `B5BF3FCC103D158C526AD005855C79EDC2F6CF6477BF6EB3D0C193BEA42D9959`;
the isolated case database SHA-256 is
`D11EBB7D158F6C3ED6FA2B1CD17BB002FEBD272D02330F38253E9480AF0F0537`.

Source-side collection limits remain distinct from model-view omissions. The
latter can be labeled and retrieved when retained; never-captured facts cannot
be recovered from a brief.

One read-only browser report on the integrated `a646320` code used pinned
managed Laya and local Ollama Qwen with a 60,000 ms case budget. It completed
in 83.053 s including startup, collected eight probes and 15 evidence records,
and ended `insufficient_observability`: two unresolved hypotheses, three unmet
evidence/detail requests, and no assessment. Two Qwen calls were non-degraded;
one Laya candidate snapshot ranked one item with complete 14-packet coverage
and no degraded reason. Scout's one prefetched resource probe was accounted as
used. The report marked its evidence view truncated and a detail scan limit;
no affected browser action was independently measured. Private log SHA-256:
`F0F50303015739141DAEDE08322767F2F7A56840F74A73C6F0EBD03B3A496949`.
This is a functional actual-model run, not a matched speed experiment or proof
of meaningful multi-option Laya ranking. Unrelated foreground GPU load was
present and was not interrupted.

The `a646320` opt-in synthetic counterevidence overlap test was run twice
without changing code or its 45-second case budget. The first attempt **failed**:
Laya saw the later pressure fact and ranked four relevant retrievals, but the
managed Qwen role entered `call_LocalInferenceError` recovery; its deep mailbox
expired and no deep result was applied. The second attempt **passed**: seven
Laya menus offered 16 distinct items, four complete post-counterevidence
rankings occurred while Qwen was active, and one non-degraded deep result was
applied. The passing case took 17.313 s after 20.562 s cold setup; the failed
case consumed the 45-second case budget after 23.313 s cold setup. Both
collected two read-only measurements and stopped without a supported cause;
the pass still had six unmet evidence/detail requests. Neither is a matched
speed experiment. The passing run's 16 distinct offered IDs over 4.157 active
ranking seconds are 3.849/s, not independently judged useful choices and below
the 20 useful/s target. The paired outcome is **one pass, one failure**, so
concurrent deep reliability and diagnostic utility are not qualified. Private
log SHA-256 values, failed then passed:
`F884DC8D380B14BDDE24C273E00360DFCDFC9C86C9B7318D4D63DFBA36EED6E9` /
`8F4B8BB152502B20EC5A6EA8131C773CD18CF8DE6ACF675FC7FD534C91FCC4EF`.

At later `b83c186`, a focused test caught downstream prompt fitting evicting
protected support from a previous hypothesis when all visible contexts were
cited and the packet could not fit. The provider now returns an explicit
context-budget failure in that case; 105 focused provider/investigator tests
pass. Terminal reports also label the independent affected-task result as
unverified when only a user report exists. At integrated `44414d2`, one
opt-in actual Laya/Qwen synthetic counterevidence trial passed: Laya made a
complete post-counterevidence ranking while Qwen was active, and one valid
deep result was applied. It offered 16 distinct IDs over seven Laya menus,
admitted two read-only probes, and stopped with six unmet requests and no
cause. The case took 13.625 s after 27.500 s cold setup; the 16 distinct
offered IDs over 2.670 active ranking seconds are 5.993/s, not independently
judged useful. The report's instantaneous end status shows both roles idle;
the overlap assertion uses worker timestamps during the case. Private log and
database SHA-256:
`DB1C1F4834933C8A6A747053E220C69AF7D1AFB50EDAB7BEFD77DB738F92C2CF` /
`6CE10E0594054E1B3E41277D486651808754C5EA974B928456A61B211AC727ED`.
Managed model/process/listener ownership was clear afterward. This is one
functional smoke at later code, not a reliability qualification or matched
speed experiment. The previous unchanged pair remains one pass and one
failure. The broader non-MCP gate at `44414d2` recorded 3,275 passes, 31
opt-in skips, and one durable scheduler test failure; ten isolated repeats and
the 66-test scheduler module passed. At later integrated `536ebb4`, the clean
combined non-MCP gate passed 3,280 with 31 opt-in skips and seven warning-path
notices in 406.46 s; whole Pyright had zero errors, Ruff lint/format passed
for 587 files, and offline source/wheel build passed. Private test log SHA-256:
`9BC8C2F3B593D3604E4E55932DEAB81BD8CD133E9DF2FE3A4F83C6EAF149182F`.
These checks do not qualify the opt-in model arms or later unintegrated work.

At tested code revision `3f04d15`, the new one-step Scout, follow-up shortlist, and
deep-output recovery are built; their whole-episode quality is unqualified. The
14-case public deterministic pilot at integrated B commit `870ba49` ran through
`python -m benchmarks.full_trajectory_pilot --output-dir <private-dir>` and
`--verify`: 14/14 cases completed, 24 probes ran, 10 independently reset
single-probe effects were useful, 43/53 eligible tool opportunities remained
unrun, and all 14 outcomes were insufficient observability. The current-default,
deep-only, Scout off, and Scout on model arms are each 14/14 unrun; paired
complete episodes are zero. No model speed or diagnostic gain follows.

The independent sequential toy matrix at integrated B commit `fee0d4d` uses
`python -m benchmarks.sequential_visible_matrix --output-dir <private-dir>`
and `--verify`. Its 14 same-start cases each freeze six ordered visible states;
evaluator-only labels and unknown root truths stay separate. Contract SHA-256
`14a0d889ad0faeeb6c032c50161c893751dfaaf06d43fd63b345cbc04ddfd6aa`.
On C's frozen pre-selector 84-state retrieval replay, B found reviewed-only
relation-set changes on 22/31 toy discriminating follow-up stages and 11/39
nondiscriminating stages, with 23/38 distinct-root final pair collisions. A
candidate source-scope gate reduced false churn to 6/39 but reduced those
discriminating changes to 8/31 and increased final collisions to 38/38; it is
held unmerged. These are retrieval responsiveness and coverage limits, not
causal-accuracy scores. The revised selector has no verified product benefit.

One actual Laya/Qwen read-only PDF objective at A commit `1befd7d` completed
with 7 probes, two valid deep responses, three unresolved hypotheses, four
unsatisfied evidence/detail requests, no affected page-action measurement, and
no assessment. Case time was 24.546 seconds; process time 54.153 seconds
includes startup. Private log SHA-256
`6919A9C3FA6AE41B076DB1AA9013BAE5A2D299A90B3C6B177C03994888B9150B`.
It is a functional host observation, not a matched speed experiment or a
supported diagnosis. The named VM/nonce-bound outcome blocker remains unchanged.

## Generalist checkpoint (2026-09-26)

After correcting two reproducible source-generation races (before receipt freeze and after Laya rank), one serial capture-off run per ordinary read-only CLI objective used the same warm-local-development profile and 45,000 ms/two-round bound. The exact command form is `.\.venv\Scripts\python.exe -m systemsense.cli investigate '<objective>' --profile examples\warm-local-development.profile.json --budget-ms 45000 --max-rounds 2`, with `SYSTEMSENSE_DATA_DIR` set to a fresh private temporary directory. Laya 0.3.5 weight SHA-256 `4fa56de72383a9d3efa9cfa78955733c81b9fc8067a587ca4beb82c78107a24e` ranked one menu in each case; managed `qwen3.5:4b` digest `361823c09f0cc2125d6844672dc2c1063b4f95b80c54db04c2c09fcf7884f077` applied one deep result in each. No `streaming_mixed_frontier_invalid` warning remained. These three different objectives are functional checks, **not matched speed experiments**, and their single-choice menus do not prove broad comparative search.

| Read-only objective | Case | Laya menus / admitted measurements | Parent persistence to admission | End state |
| --- | --- | --- | --- | --- |
| Browser/Wi-Fi/proxy | `case_f28cb1fa06c94a34adadd1db909e5dd3` | 1 / 1 | 1,070.628 ms | insufficient observability |
| Game FPS/GPU/display | `case_8daebb73ef5540ca97e447f5f39727e2` | 1 / 1 | 661.918 ms | budget exhausted; later deep call cancelled |
| System/storage slowness | `case_ec13c8258f6f41649d36315a1ad6d93d` | 1 / 1 | 463.180 ms | budget exhausted; later deep call cancelled |

The post-change synthetic counterevidence overlap check passed once with actual warm models: 7 Laya menus, 16 distinct offered identities, 34 microbatches, 2 admitted measurements, and four subsequent changed-evidence retrieval choices while Qwen remained active. Cold setup/Laya prewarm was 16,015 ms; warm case elapsed 11,141 ms. Across worker calls, synchronized forward totaled 1,411.373 ms, admission 885.292 ms, input/tokenization 225.908 ms, and queue wait 0.101 ms; active ranking totaled 2,672 ms or 5.988 distinct offered IDs/s. Qwen's first owned call was cold and took 10,687 ms. The later source trigger was queued 2,904 ms after persistence because its current bounded session was still consuming the evidence; it then closed `no_new_fact`. These are not a meaningful all-event p95 or an independent diagnostic-utility score. The 20/s target is missed, and the 400 ms target remains unqualified; no speed optimization was attempted in this correctness pass.

A read-only frozen-menu synthetic comparator and CPU no-update fixture rehearsal now have repeatable commands in [Training plan](TRAINING_PLAN.md). They preserve unknown alternatives and reject training admission. The named Windows VM remains locked (`LoggedInUsers=0`), and its approved `https://example.com/` endpoint still lacks the nonce-bound 204 response needed by the independent affected-task checker. No host fault, VM fault, or weight update occurred.

## Training-ready V1 attempt (2026-09-26)

Three serial, capture-off actual-model counterevidence repeats used the same development profile, RTX 4090, menu fixture, model pins, and budgets. Each passed, with 7 Laya menus, 16 distinct offered IDs, 34 worker microbatches, 3 source triggers, 10 completed turns, zero unfinished turns, two admitted read-only measurements, one applied non-degraded Qwen result, and no model fallback/timeout. Laya consumed the changed pressure value `3` with 10/10 packet fragments and compared four relevant stored-evidence choices while Qwen was active; the selected retrieval was delivered. This is scheduling/input proof, not an independent usefulness label.

| Case prefix | Cold setup / warm case | Active ranking / distinct IDs/s | Queue / admission / input / synchronized forward sums | Original parent-to-first/second admission | Admission-to-launch first/second | Changed event queued after persistence |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `case_da9f2017` | 28,766 / 14,735 ms | 2,749 ms / 5.82 | 0.096 / 1,025.636 / 202.718 / 1,343.814 ms | 1,068.436 / 1,931.775 ms | 189.039 / 194.142 ms | 2,860.588 ms |
| `case_9f16190d` | 15,984 / 11,375 ms | 2,844 ms / 5.63 | 0.093 / 1,108.099 / 216.405 / 1,353.928 ms | 1,133.684 / 1,977.115 ms | 160.072 / 230.833 ms | 2,939.144 ms |
| `case_9565f291` | 15,750 / 11,813 ms | 2,921 ms / 5.48 | 0.097 / 1,130.262 / 234.735 / 1,396.643 ms | 1,204.462 / 2,019.763 ms | 173.883 / 184.288 ms | 2,969.175 ms |

The first setup is an outlying cold start; warmed turns and whole cases remain distinct. All six admitted parent-to-admission samples exceed 400 ms; an all-eligible-event p95 remains `null` in the durable reporter, so the p95 target is not qualified, while the observed admitted samples and 5.48–5.82 distinct offered IDs/s miss the engineering targets. Each changed event's separate trigger was intentionally delayed by the active bounded session, which had already used the new evidence, then closed `no_new_fact`; it was not worker queueing. The measured worker queue was negligible and synchronized forward plus repeated valid admission dominated active ranking. No new batching or cache setting was promoted because earlier matched batch-eight trials had inconsistent whole-case benefit and a concurrent host crash of uncertain cause. This is a bounded performance pass, not a speed qualification.

An isolated ordinary Windows CLI invocation with `--profile examples/warm-local-development.profile.json --budget-ms 45000 --max-rounds 2` recorded two actual Laya mixed decisions (one then four candidates) and one applied actual Qwen reasoning result; a later Qwen task was cancelled by the round budget. Five read-only probes succeeded and 12 remained not collected. The case completed with bounded budget exhaustion, one unsatisfied detail request, no diagnosis, and no repair. Its 5 distinct mixed IDs over 1,207.123 ms active ranking give 4.14 IDs/s; no measurement was admitted. It is a host observation, not an affected-task success test. The top-level CLI provider field reports the procedural keyword route; immutable mixed snapshots identify the actual Laya provider.

The first opt-in three-case capture attempt produced 28/28/18 worker drafts but **failed** installed-builder parity in all cases because an old synthetic parity fixture supplied a question too long to fit as a complete instruction. Those attempts remain failed. After replacing that fixture with a complete bounded question, three fresh serial attempts passed: `pressure_fault` 17 drafts/117 exact batches, `healthy_control` 18/124, and `external_outage` 28/173. All 414 installed-builder batches had zero tensor differences. Case durations were 25.60/23.50/30.20 s; two-second host samples observed minimum free VRAM of 17.45/17.45/17.25 GiB and minimum available RAM of 44.23/44.61/44.22 GiB, not allocation peaks. The independent selected-action oracle marked one measurement useful in each case and left the other 60 selected outcomes unknown. Privacy review and training admission were false in all three cases. One captured exact call also passed a CPU no-update load/forward smoke (three questions and three answers). No real Windows fault, teacher labels, weight update, or ranking-quality qualification occurred. A later test-only reference policy selected from these same frozen visible menus before consulting the hidden fixture: it had 2/2/10 useful choices compared with Laya's 1/1/1 across 17/18/28 repeated states, but there are only three independent recipe families and **zero proven worse-Laya learning pairs**, since the differing Laya actions were unrun/unknown. This is not a Windows-accuracy or training-readiness result.

After the authoritative catalog eligibility correction, three more serial capture-off runs on the same synthetic counterevidence fixture/profile/models passed without fallback or timeout. They retained seven observed Laya menus, 16 distinct offered item IDs, three eligible source triggers, ten completed turns, two linked read-only measurements, changed value `pressure_percent=3` visible to Laya during active Qwen reasoning, and one applied Qwen result per case. This is a functional repeat, not a claimed speed optimization. The selected pressure/GPU sequence and retrieved branch were observed, not hardcoded as expected winners.

| Case prefix | Cold Laya setup / warm case | Active ranking / distinct IDs/s | Queue / admission / tokenization / synchronized forward sums | Parent persistence-to-admission samples |
| --- | ---: | ---: | ---: | ---: |
| `case_2686d37` | 14,046 / 11,672 ms | 2,765 ms / 5.787 | 0.095 / 1,106.977 / 202.285 / 1,289.442 ms | 1,046.823 / 1,865.799 ms |
| `case_6d420b4` | 13,907 / 11,328 ms | 2,639 ms / 6.063 | 0.095 / 967.398 / 208.149 / 1,280.226 ms | 1,111.299 / 1,887.281 ms |
| `case_840a31b` | 14,047 / 11,047 ms | 2,657 ms / 6.022 | 0.097 / 1,046.222 / 204.520 / 1,259.822 ms | 975.922 / 1,777.728 ms |

These 48 distinct offered identities are 16 per repeated case, not 48 independent diagnostic judgments. Forward remains the largest summed active worker stage, with valid admission checks close behind; queue wait is negligible. Prior batch-eight comparisons did not show a repeatable whole-case gain, and unchanged-input caching already avoids a new worker call when the exact semantic state and comparison set are unchanged. Changing evidence correctly invalidated all batches here, so there was no justified reuse or evidence-dropping optimization to promote. All six admitted samples missed the 400 ms source-to-admission target; the durable all-eligible-event p95 is still unavailable, rather than inferred from admitted-only samples. The separate changed-event trigger closes `no_new_fact` because the active session had already consumed its evidence, not because the worker silently skipped it.

A subsequent guarded-handoff correction closed a cancellation race for a model callback returning after the owner offer queue. Deterministic held-callback tests prove rejected measurement and deep selections do not remain `CLAIMED`, and a late focus selection cannot remain `RUNNING` or claim a delivery receipt. One capture-off actual-model confirmation before the final terminal-state correction (`case_9cac9794`) passed with seven Laya menus, 16 distinct IDs, changed pressure visible during active Qwen, two measurement admissions, and one applied Qwen result. Cold Laya setup was 13,969 ms; warm case 11,531 ms; active ranking 2,689 ms (5.950 distinct IDs/s); worker totals across 34 calls were 1,259.447 ms synchronized forward, 1,066.693 ms valid admission, 208.558 ms input construction, and 0.091 ms queue wait. Its two admitted parent-persistence-to-admission samples were 969.771 and 1,757.066 ms. Three source triggers produced ten completed turns with zero queued-unreserved or unfinished turns; all-attempt p95 remains unknown. This is a confirmation, not a fourth performance-factor experiment.

Three more capture-off overlap attempts after the final terminal-state correction had two **failures** (`case_ac1476ad`, `case_509153a0`) and one full pass (`case_81e63608`). All had actual warm Laya seeing low-pressure counterevidence and selecting among four relevant retrievals while actual Qwen was active; the two failed cases still admitted two measurements each. Qwen's ~12.968 s and ~11.906 s completed calls in those cases returned degraded advice with `ValidationError:value_error`, so the owner rejected rather than applied it. The passing case applied non-degraded Qwen advice after 13.297 s and passed the actual-model overlap assertion. The first failed case observed seven menus, 16 distinct IDs, and 34 microbatches at 6.282 distinct IDs/active-ranking second; no speed claim follows from a failed case. The exact invalid advice field is not retained in the bounded trace, so the intermittent schema failure cannot yet be attributed more narrowly. No rejected result was converted into a diagnosis.

An ordinary read-only Windows game-performance CLI case after eligibility and terminal-state correction (`case_06bf99aeefb14340b78b5a7bdafc54da`) used actual Laya once on a legitimate one-measurement menu while Qwen's first 10.000-second reasoning call was active, admitted/launched a GPU telemetry sample, applied that Qwen result, and finished with both admitted frontier items `SATISFIED`. Its single source-persistence-to-admission observation was 442.502 ms, admission-to-start 166.350 ms, and the actual sample took 4,755.854 ms. A second deep call was cancelled by the two-round budget; no diagnosis or repair was established. The separate Windows-health objective had no eligible mixed measurement after the invalid options were removed, so it made no Laya selection and stopped with an explicit unresolved request. Neither host run contained a controlled fault or competing post-counterevidence menu; the synthetic overlap runs establish that behavior separately. An opt-in CLI capture before the eligibility fix retained three exact Laya drafts with nine builder-parity batches and one locally replayed three-question CPU forward, but its two selected measurements were rejected by the owner and remain failure evidence, not useful dispatches.

The tested local invocation is `SYSTEMSENSE_DATA_DIR` set to a fresh directory, then `.\.venv\Scripts\python.exe -m systemsense.cli investigate 'Game runs slowly despite a capable GPU' --profile examples\warm-local-development.profile.json --budget-ms 45000 --max-rounds 2`. It is read-only; a new directory avoids mixing case databases. The three-family simulator and no-update replay commands are in [Training plan](TRAINING_PLAN.md). The exact named-VM proxy episode is authorized, but the guest has not been unlocked or qualified for the independent affected-task baseline. Do not introduce a fault on this development PC.

## Alpha checkpoint: one-factor warm admission experiment (2026-09-25)

Three serial, matched capture-off runs used the unchanged `test_live_counterevidence_overlap.py` fixture, RTX 4090, Laya 0.3.5 CUDA fp16 weight `4fa56de72383a9d3efa9cfa78955733c81b9fc8067a587ca4beb82c78107a24e`, and concurrently active managed Ollama `qwen3.5:4b` digest `361823c09f0cc2125d6844672dc2c1063b4f95b80c54db04c2c09fcf7884f077`. Baseline was the prior HEAD; the only promoted performance factor was up to 150 ms reuse of an already-valid, extra-headroom-safe host telemetry sample for repeated worker calls. Lease renewal, worker identity, GPU identity, limits, and watchdog/startup fresh sampling remain in force. Each case had 7 observed Laya menus, 16 distinct offered identities, 34 worker microbatches, 3 source triggers, 10 completed turns, no queued-unreserved/unfinished turns, and a non-degraded applied Qwen result. The changed low-pressure value of 3 reached actual Laya with complete 10/10 fragment coverage; it compared four relevant retrieval alternatives while Qwen was active. Its selected delivery is not an independently verified useful diagnosis.

| Trial | Cold setup | Warm case / whole-case distinct/sec | Active ranking / distinct offered/sec | Admission sum | Forward sum | First source-to-admission | Post-counter persistence-to-delivery |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| No reuse, `case_c58a3fa3` | 15,750 ms | 12,672 ms / 1.263 | 3,860 ms / 4.145 | 2,012 ms | 1,416 ms | 1,488 ms | 610 ms |
| Reuse, `case_0ec4341f` | 15,594 ms | 10,656 ms / 1.502 | 3,016 ms / 5.305 | 1,162 ms | 1,460 ms | 1,270 ms | 574 ms |
| Reuse repeat, `case_56cae94d` | 15,391 ms | 10,859 ms / 1.473 | 2,687 ms / 5.955 | 988 ms | 1,371 ms | 1,162 ms | 494 ms |

Warm worker queue wait was about 0.1 ms or less per whole case; input construction/tokenization totaled 225–232 ms. The admission saving is consistent with the changed telemetry path, but three runs cannot isolate all host variance. Synchronized model forward is now the largest measured active-ranking stage, at 1.37–1.46 seconds across 34 calls. First mixed small-menu ranks took 485/406/375 ms (median 406, n=3); this is responsiveness, not sustained throughput. Original source-to-admission for the second selected measurement was 2,460/2,100/1,973 ms, and admission-to-launch added 158–229 ms across the six measurements. The changed source event's separate trigger was queued 3,460/3,149/2,788 ms after persistence because the current session still had work, then closed `no_new_fact`; the value was already used in the active session's Laya input. This is an intentional bounded-session delay, distinct from worker queueing. All three cold starts, all three cases, and all observed opportunities are included; no Laya/Qwen fallback or timeout occurred in these three actual-model runs. Procedural later turns did use keyword-baseline. Post-counter persistence-to-delivery had median 574 ms (n=3); a population p95 from three samples is not credible. The all-eligible-event p95 remains `null` in the durable reporter, so the 400 ms target is unqualified and the three observed delivery samples themselves miss it. Distinct offered-item rate is not diagnostic utility, and 20/sec is missed. The next single performance experiment, if authorized after this checkpoint, is to compare fewer **complete** evidence microbatches on the same warmed inputs without hiding evidence or weakening source/permission checks.

Run the functional actual-model reproduction with `$env:SYSTEMSENSE_RUN_LIVE_COUNTEREVIDENCE='1'; $env:SYSTEMSENSE_PROFILE_TIMING='1'; .\.venv\Scripts\python.exe -m pytest tests/integration/test_live_counterevidence_overlap.py -q -s`. The ordinary isolated Windows run used `SYSTEMSENSE_DATA_DIR` pointing to a fresh temporary directory and `.\.venv\Scripts\python.exe -m systemsense.cli investigate 'Check current Windows system health and resource pressure without changing anything' --budget-ms 15000 --max-rounds 2`; it took 5.67 s, used keyword-baseline (3 calls) and deterministic reasoning (2 calls), and recorded three `ok` probes, 14 explicitly `not_collected`, no repair, and `insufficient_observability`. No real fault, independent affected-task success, or training-admissible label is claimed. The exact disposable-VM proxy trial is authorized but remains blocked on guest unlock and independent affected-task baseline.

For the training-admission checkpoint, the final-code opt-in actual-model synthetic PDF-process test passed once in 47.46 s: 18 Laya rankings, one successful Qwen3.5 4B deep call with overlap, a frozen same-source menu with two distinct target-pressure handles, and installed-builder parity across 129 batches. Laya chose `consult_deep`; both target-pressure actions were unrun at that decision, and their separate offline simulator receipts have unknown utility. The final report SHA-256 is `2b4d266ad87a0a8ddad1fd9354868888ca4a3b3320e98729835a8661635f4f57` (local-only artifact). Earlier paired-menu captures passed in 44.51 and 48.56 s; one 50.71 s run failed an overstrict test expectation because Laya did not select deep work, although its menu and parity were valid. The test now checks custody without prescribing the model's winner; concurrent deep behavior is verified separately. This is exact-input custody, not evidence of correct ranking or Windows accuracy. The command is `$env:SYSTEMSENSE_RUN_PDF_PROCESS_PAIR='1'; .\.venv\Scripts\python.exe -m pytest tests/integration/test_opt_in_live_four_kind.py -q -s -k test_actual_models_capture_two_pdf_process_measurements`. Capture artifacts stay local outside Git.

The named VM was restored to `systemsense-clean-baseline-20260923` and booted only after the user's exact-scope approval for the `127.0.0.1:9` current-user WinINet proxy fault, `https://example.com/` endpoint, healthy/direct/external controls, and reset. No fault was injected: the guest sign-in required a user password change and read-only GuestInfo still reported zero logged-in users. The running-VM preflight now parses actual display/Guest Additions metadata and reports `guest_login_unverified`, `clean_reset_unverified`, and `independent_oracle_unverified`; it does not authorize starting an episode. The user must unlock the guest before any affected-route baseline or fault trial. No development-PC settings were changed.

## Post-counterevidence runtime checkpoint (2026-09-25)

The prior failing trace contained a real scheduling defect: a source event already persisted before `_new_mixed_work_after_turn` ran could be omitted by its same-iteration event-count gate after the current mixed session drained. The event remained pending despite spare case/session budget. The owner now checks pending triggers and events directly. A controlled-provider regression leaves at least two legitimate post-contradiction choices (a source-bound GPU measurement and deferred relevant evidence) and verifies that the changed source obtains a completed turn. An earlier actual-model assertion also looked for a streaming focus receipt on the mixed-turn route; the correct durable proof is its custody-checked `focused_delivery` turn outcome and satisfied item.

The capture-off opt-in case now passes with actual warm Laya and managed `qwen3.5:4b`: the low-pressure value of 3 and a newer evidence generation reached Laya, which compared four relevant stored observations while Qwen's worker interval was active. In the traced `case_968119fa...`, Laya first selected a stored Windows Update process-pressure observation and its mixed turn delivered that exact item. This is an observed model choice, **not** an independent diagnostic-utility label. The counterevidence persisted at 21:26:43.165332Z; the new rank started about 70 ms later and focused delivery completed 543.967 ms after persistence. Its separate source event was queued 3,272.064 ms after persistence because the current bounded session still had work; after those four deliveries it received two explicit `no_new_fact` turns and closed. No turn was hidden by the deep worker. The case report records 3 source events/queued triggers, 10 reserved and completed turns, and zero unfinished or queued-unreserved turns. Event/turn accounting includes gap and deadline outcomes when present, but old snapshots do not establish that every source event had a useful model menu.

Two test attempts exposed the failure before the corrected proof: the original checkpoint case failed the post-counter assertion because it inspected only measurement snapshots, and the first corrected assertion failed because it sought a receipt from the wrong route. Seven subsequent actual-model cases passed the scheduling/input/overlap assertion, including a final run with an explicit no-omission worker-coverage check. Six capture-off runs with complete menu accounting offered 16 distinct item identities across 7 Laya menus per case, with 4.34–4.533 distinct offered items per active-ranking second and 34–35 worker microbatches. No fallback or timeout occurred in these recorded Laya menus. This is below 20/sec and is not diagnostic usefulness. Four aligned case-only timing samples totaled 1,965.621–2,067.884 ms in mandatory per-worker-call admission and 1,241.184–1,277.987 ms in synchronized model forward; tokenization/input construction was 204.147–208.357 ms and worker queue wait under 0.1 ms. Repeated bounded comparisons plus resource admission dominate active ranking. A next bounded experiment is to measure whether still-valid resource telemetry can be reused across a short owned turn without weakening the lease, checks, or admission limits. The 543.967 ms delivery misses 400 ms; this small admitted sample does not qualify an all-eligible-event p95. The deep model's result applied; it did not certify the selected retrieval. No host fault, Windows diagnosis, repair, training capture expansion, or weight update occurred.

## Bounded continuation and latency correction (2026-09-25)

The correction at this checkpoint removes the coordinator wait on deep reasoning when a prior mixed turn still has eligible work. The original capture-off case `case_3a20964...` remains the before trace: `core.resources` evidence persisted at 17:45:16.319598Z; the first GPU measurement was admitted 947.606 ms later; GPU evidence persisted at 17:45:17.434715Z; the second pressure turn did not reserve until 17:45:25.187850Z, 31 ms after Qwen finished. The original parent-to-pressure admission was **9,315.348 ms**, and admission-to-launch added 207.768 ms. Of the total, 8,868.252 ms elapsed before second-turn reservation; 405.986 ms was freeze-to-snapshot and 25.465 ms snapshot-to-admission. The 7,768.780 ms GPU-evidence-to-second-freeze gap was avoidable deep waiting, not a measured Laya or resource-check delay. The retained database can be traced with `python -m benchmarks.real_mixed_trace <database> case_3a20964cb4d24f5abbfd58541cbc04d2`.

After the correction, the same pinned capture-off model profile admitted a second pressure measurement 1,653.685 ms after its **original** parent persisted (`case_1a822a0d...`); the second turn reserved at 1,132.878 ms, froze 16.280 ms later, ranked in 481.337 ms, validated/persisted and admitted in 28.177 ms, then launched 189.801 ms after admission. This is an improvement of 7,661.663 ms against the earlier trace, **not** a matched-case causal estimate or a qualifying percentile. The synthetic pressure handler and case budget differed between cases. Necessary waits included the first selected GPU measurement and baseline/event delivery; repeated admission checks were only 19–28 ms. Warm Laya inference plus its complete evidence microbatches remains the largest measured per-turn cost after removing deep deferral. The normal capture-off two-choice case had 8 then 10 expanded questions across 3 then 4 microbatches, 336.256/481.337 ms freeze-to-snapshot, 3 distinct candidates over 817.593 ms active ranking (3.669/sec), and Qwen ran concurrently for 9,328 ms. Its low-pressure counterevidence arrived after both Laya decisions.

Four local actual-model attempts were retained, including a pre-case managed-Qwen-prewarm rejection (no case), a 1.969 s case that exhausted its local probe budget before the delayed observation (deep cancelled), the no-omission case above (deep applied), and `case_ec71f2b5...` with four relevant stored observations intentionally omitted from a simulated focused packet (deep applied). In the latter, Laya ranked 6 then 5 distinct offered alternatives before counterevidence, 11 distinct candidates over 1,410.345 ms active ranking (7.8/sec), requiring 14 then 16 expanded questions, 5 then 6 microbatches, and one finalist comparison per rank. The original parent-to-admission samples were 1,439.432 and 2,450.529 ms; Qwen ran 8,281 ms while both rankings and four later exact retrievals proceeded. The low-pressure observation persisted at 20:26:02.445025Z, then the next procedural focus turn reserved in 67.402 ms. Laya chose GPU and pressure before that observation; no comparative menu remained afterward, so **actual post-counter Laya redirection was not proved in that earlier checkpoint**. A fake-oracle fixture verifies that such alternatives can be routed, but does not establish learned model quality. The opt-in actual-model test failed that earlier acceptance assertion; the corrected run and its limits are recorded above.

Two further matched capture-off repeats used the unchanged simulated-omission fixture, batch-four profile, and RTX 4090, with no concurrent foreground benchmark. Across all three matched cases, startup was 15,453–15,969 ms; each case had 2 actual Laya ranks over the same 6-then-5 original-candidate menus, 11 distinct inferred candidates, 14/16 expanded questions, and 5/6 microbatches. Active distinct throughput was 7.631–7.8/sec. All six original-parent-to-admission samples ranged 1,439.432–2,514.061 ms (admitted-only p50 1,950.206, p95 2,513.774; **not** all-attempt p95). Qwen worker durations were 8,281/12,156/12,781 ms; two results applied and one degraded `ValidationError:value_error` result was rejected. All three runs made zero post-counter Laya decisions; exact retrieval proceeded instead. No run was discarded to compute the range.

The old small-menu sample was 2/1 original candidates with 368.162/405.986 ms freeze-to-snapshot; the corrected no-omission trial had 2/1 with 336.256/481.337 ms. With two samples each, the apparent p95 is not a meaningful population estimate. The 20 distinct useful judgments/sec and under-400 ms **all-eligible-event** p95 targets are missed or unqualified: even active distinct throughput was only 3.669–7.8/sec, and the durable trace lacks the all-eligible-event denominator. `SYSTEMSENSE_PROFILE_TIMING=1` records worker queue, input construction, synchronized forward, IPC, and validation samples in the live Laya runtime, but the managed factory does not expose those in-memory samples after case completion; these sub-stages cannot be reconstructed from the saved database. Do not attribute the 336–713 ms aggregate to CUDA cleanup or resource checks without that measurement. A bounded next experiment is to expose those existing timing samples through a read-only managed diagnostic surface, then compare semantically complete evidence microbatch counts on matched warm inputs before changing the batch size or CUDA cleanup behavior. No such optimization was promoted here.

The runnable local profile command is `.\.venv\Scripts\python.exe -m systemsense.cli investigate "Game runs slowly despite a capable GPU" --profile examples\warm-local-development.profile.json --budget-ms 45000`. The reproducible capture-off synthetic check is `$env:SYSTEMSENSE_RUN_LIVE_COUNTEREVIDENCE='1'; $env:SYSTEMSENSE_PROFILE_TIMING='1'; .\.venv\Scripts\python.exe -m pytest tests/integration/test_live_counterevidence_overlap.py -q -s`; its corrected post-counter scheduling assertion now passes, subject to the quality and speed limits above. The 130- and 181-record ordinary mixed-loop tests reach tail evidence with bounded 20-entry metadata pages. A 641-record sparse case can exhaust finite mixed turns; it now ends `NO_PROGRESS` with an explicit unscanned-catalog gap instead of false insufficient-observability closure. Unavailable/degraded catalog attention and still-requested retrieval backlog receive the same honest unresolved outcome. No Windows fault was introduced on this development PC; the disposable-VM pilot still requires exact VM access and fault approval.

## Correction-checkpoint measurements (2026-09-25)

The development profile is `examples/warm-local-development.profile.json`: Laya 0.3.5 CUDA fp16, weight SHA-256 `4fa56de72383a9d3efa9cfa78955733c81b9fc8067a587ca4beb82c78107a24e`, and managed Ollama `qwen3.5:4b`, digest `361823c09f0cc2125d6844672dc2c1063b4f95b80c54db04c2c09fcf7884f077`. Capture was off. Installed-tokenizer checks on actual mixed inputs found candidate questions at 194/205 tokens and real evidence at no more than 216, under the 239-token instruction capacity. Two direct warm Laya calls took 417 and 681 ms after a 19.195 s cold prewarm; their eight worker microbatches had 53–70 ms admission and 48–72 ms synchronized forward time per call, with 4–25 ms tokenization/input construction. This tiny direct sample is not an integrated percentile.

An actual-model, isolated synthetic mixed case `case_3a20964cb4d24f5abbfd58541cbc04d2` ran with a 15.455 s cold Laya prewarm and 22.857 s case time. Laya produced two complete mixed decisions (2 then 1 offered candidates, 5 then 8 evidence packets, 7 then 9 worker questions, 3 microbatches each, no repeated candidate presentations). Three distinct candidates over 774.148 ms of frozen-to-snapshot time is about 3.9/sec in this small case, below the 20/sec target. Three Qwen tasks were non-degraded. A Laya decision and GPU measurement both occurred while Qwen's first 8.344 s task was running. Two source-bound measurement admissions/executions succeeded: source-persistence-to-admission was 947.606 and 9,315.348 ms; admission-to-claim 30.665/53.505 ms; claim-to-start 97.287/154.263 ms. The selected order was GPU then pressure, not the independent pressure-then-GPU rationale. Later pressure evidence contradicted the original pressure reading, but arrived after the last Laya decision. Thus this proves actual overlap and bounded dispatch, **not** intelligent post-contradiction redirection or diagnostic usefulness. Two admitted samples do not establish a meaningful p95; the 400 ms target was missed in both. The five persisted evidence events cannot be equated with five eligible follow-up opportunities because that denominator is not yet durably recorded.

A separate capture-off full local case `case_5a8a34fdd50d4e6aaea29ae341061672` produced three genuine mixed Laya rankings with complete packet coverage and five non-degraded Qwen tasks but no candidate admission. Earlier full-case attempts fell back after an overlong legacy Laya packet; the corrected mixed path no longer invokes that legacy model route, and authenticated input-fit rejection no longer retires a healthy worker. These failed attempts remain part of the checkpoint evidence, not successful latency samples. Neither 20 distinct useful judgments/sec nor under-400 ms all-attempt p95 is established. The later durable trace above supersedes the earlier attribution of dominant cost to serial model microbatches: avoidable coordinator deep-waiting dominated the 9,315 ms sample.

All actual-model case attempts in this correction pass used capture off. The first five are in the local `systemsense-real-model-ff3b0976afa74defb7139190284bc076/systemsense.db`; the last is in its `synthetic-mixed-real-model.db` sibling. Prefixes below uniquely identify the durable case IDs in those databases.

| Case prefix | Mixed Laya/fallback | Deep applied/rejected | Measurement admissions | Qualification |
| --- | ---: | ---: | ---: | --- |
| `case_2497e85` | 0/3 | 3/2 | 0 | Legacy fit/fallback; exact timeout count unknown |
| `case_b27ffdf` | 0/3 | 3/2 | 0 | Legacy fit/fallback; exact timeout count unknown |
| `case_cb85112` | 0/2 | 3/2 | 0 | Legacy fit/fallback; exact timeout count unknown |
| `case_9a1d1cb` | 0/3 | 3/1 cancelled | 0 | Instrumented: one input-fit rejection, then two worker deadlines and quarantine |
| `case_5a8a34f` | 3/0 | 5/0 | 0 | Mixed fixed, legacy fast calls still degraded before final gate |
| `case_3a20964` | 2/0 | 3/0 | 2 | Final synthetic overlap/dispatch proof; no real fault diagnosis |

The first three cases each had seven degraded legacy Laya attempts, the instrumented case five, and the partly corrected case four. Final synthetic provider events show zero legacy Laya attempts. Brief whole-GPU used-memory samples were about 1,141–2,474 MiB across those early trials; no per-model or peak RAM/VRAM/CPU measurement was made. Direct replay checks separate from the case table succeeded: one old 16-packet/4-candidate request after about 17.37 s including startup; one compact 5-packet/1-candidate request after 15.839 s prewarm plus 309 ms warm ranking; and two opt-in profiled warm rankings at 417/681 ms after 19.195 s prewarm. No replay timed out. The synthetic case used `SYSTEMSENSE_PROFILE_TIMING=1` for stage timing while training capture stayed off; the five CLI cases used normal timing mode and capture off.

The controlled local evidence still falls below the full gate. On RTX 4090 with pinned Laya (weight SHA-256 `4fa56de72383a9d3efa9cfa78955733c81b9fc8067a587ca4beb82c78107a24e`) and local `qwen3.5:4b` (Ollama digest `361823c09f0cc2125d6844672dc2c1063b4f95b80c54db04c2c09fcf7884f077`), post-fix synthetic case `case_59d19756998b431aafc1c8a1765dda31` passed the opt-in four-kind sequence. One Laya-selected `pressure.sample` launched before an unrelated eight-second probe finished; later evidence advanced the generation, actual Laya reranked while Qwen was running, and two non-degraded Qwen responses were applied. The case took 31.7 seconds, made 16 actual Laya rankings, and ended insufficient-observability. Fifteen retained worker drafts replayed through 88 installed-builder batches with zero tensor differences. Its one exact-parent persistence-to-admission sample was 2,360.703 ms, not an all-attempt p95 and above the 400 ms target. No root cause or repair outcome was verified. The read-only `benchmarks/real_mixed_trace.py` reporter can recompute durable stages while the local database remains available. Earlier smoke details are in [archive](archive/2026-09-24-v4-local-smoke.md).

Three additional isolated synthetic fault/healthy/external cases each ran actual Laya and Qwen with exact worker parity and a case-bound hidden recipe. They produced 14, 16, and 14 selected-action receipts respectively; each case had one linked measurement that produced a new fixture fact, while unrun choices remain unlabelled. All three ended budget-exhausted without a diagnosis. These are unreviewed, non-training-admissible custody pilots, not diagnostic accuracy or a useful-action throughput benchmark. Exact-payload privacy review and independent real-fault outcomes remain absent. The pilot executions preceded the final pre-truncation retrieval filter, so their captured inputs are exact records of those executions, not a claim that the post-filter menus are identical.

An opt-in local comparison kept the production profile at batch four and ran three isolated additional cells: batch-four/no-capture (`case_32cb980bbde84cf7ad8a0a2a3736f1c5`), batch-eight/capture (`case_c42a9ae9304e4a9aaf71b4547f7723d6`), and batch-eight/no-capture (`case_f210918ea3f5402684eabcc72e4f980f`). All used pinned Laya and Qwen, applied two deep responses, and passed their mixed-menu smoke checks. Their first Laya turns took 1,000, 969, and 890 ms; median turns were 1,102, 1,000, and 1,000 ms. No-capture runs had zero worker cache hits because each offered context differed. Batch eight reduced microbatch counts but not end-to-end time or the linked admission sample consistently (3,661.570, 2,238.458, and 4,297.891 ms respectively). The two batch-eight runs used a test-only 5 GiB Laya reservation and showed no bounded host error events; this small, non-isolated comparison neither clears the earlier crash concern nor justifies promoting batch eight. The checked-in development profile remains batch four.

A controlled batch-eight comparison did produce eight Laya ranks, two exact drafts with 5/5 installed-builder parity, and an early measurement in 11.7 seconds, but it exhausted the probe budget before applying a deep result and repeated the same pressure observable through two routes. The repeat and premature closure now have regressions; that run is not a pass. A separate synthetic semantic throughput sweep measured 54–74 raw candidate judgments/sec across 27 cells, not distinct useful judgments/sec. The <400 ms all-attempt p95 and 20 useful judgments/sec targets remain unproven.

The later batch-eight run coincided with a Windows `llama-server.exe` crash (`0xc0000409` in `ucrtbase.dll`) and nearby NVIDIA `nvlddmkm` event 153 errors. The crash is confirmed; its cause is not. Batch eight was not promoted, and the development profile remains at batch four pending resource and transport diagnosis.

A subsequent batch-four, telemetry-instrumented synthetic run (`case_401ca79f851949899481dcbc57213d36`) produced four real Laya ranks and four exact worker-input drafts; one read-only pressure measurement launched before the unrelated slow probe ended. Both local Qwen answers were rejected for an optional expected fact referencing an unregistered probe, so no deep answer was applied or concurrent redirect proven. The one admitted-only persistence-to-admission sample was 1,235.079 ms. No new application crash event appeared in the bounded window, but one `nvlddmkm` event 153 did; 2-second free-VRAM samples cannot establish a driver or memory cause. The generated-answer schema now constrains expected-fact probe IDs to the registered catalog; the later controlled run above applied Qwen responses without that validation error.

## Subsequent product gates

Use controlled, resettable Windows fault episodes with a hidden independent affected-task oracle, healthy and external controls, and matched probe/evidence/time/resource budgets. Compare deterministic baseline, fast-plus-deep, and ablations without giving one arm extra information. Score supported root cause, unresolved honesty, time to useful evidence and diagnosis, host impact, coverage/failure rate, and false fixes. Preserve failed/unrun cases in the denominator. Fixture scenarios and scripted labels validate the harness, not real diagnostic performance.

For a repair family, require exact target and precondition binding, explicit interactive consent, policy checks, audit/reconciliation, rollback limits, and independently measured affected-task success after the change. A passing fake transport or direct-path control does not establish that the affected path was repaired. No autonomous repair claim is permitted before a real controlled fault trial.

## Development checks

Before a delivery claim, run focused tests, the non-MCP suite, typecheck, lint, format check, and build; record commands, results, skips, and pre-existing failures. Verify the integrated diff and runtime behavior, not merely component tests. Preserve explicit unknowns where the environment prevents a gate.

For the 2026-09-26 V1 attempt, the earlier `python -m pytest tests -q --ignore=tests/mcp` passed **3,138**, skipped **29** opt-in live/model checks, and emitted seven expected failure-path warnings in 386.08 s. The focused changed-path run passed 49/49. The final-code opt-in actual-model overlap passed once and failed twice on rejected Qwen advice as recorded above; it is **not** an all-passing qualification. `python -m pyright` reported 0 errors/0 warnings, `python -m ruff check .` passed, `python -m ruff format --check .` passed 551 files, and `python -m build` produced both sdist and wheel. The three-case opt-in capture check passed 3/3 after the bounded fixture correction; the first three pre-correction capture attempts are failures, not omitted successes. A later post-PDF-regression run passed 3,142, skipped 30, deselected one opt-in test, and emitted seven warnings; final rehearsal-code checks are recorded below.

The test-only head rehearsal checks exact worker-batch reconstruction, useful-over-synthetic-negative loss, head gradient integrity, no parameter updates, synthetic pairwise evaluation, split-group separation, and metadata checkpoint replay. Default-environment focused tests passed 9 with one explicit Torch skip; the pinned Laya runtime passed all 10 focused tests. This is mechanics evidence only: caller-supplied fixture proofs do not authenticate useful or uninformative real outcomes, and no independently reviewed same-menu pair exists. The current stricter API passed one pinned-GPU no-update train/resume/development rehearsal on two distinct PDF simulator episodes, with exact four-question compare batches and different episode groups. One fake train pair took 2,890.36 ms inside the rehearsal and peaked at 2,311,268,352 B CUDA allocated / 2,562,719,744 B reserved; the resume plus fake development pair took 5,072.35 ms including replay and peaked at 2,121,490,432 B allocated / 2,562,719,744 B reserved. Whole-process time including qualification and model load was 30.55 s. The in-memory parameter and weight-file hashes were unchanged. Both episodes share a fault family, so the reported synthetic pairwise win is **not** held-out performance; these figures are not a qualified fit-memory or fit-time estimate. Three initial one-off GPU attempts failed before forward because a CPU qualifier hid CUDA in the same process; the previous API then completed one no-update pass. The revised API's first pinned-GPU attempt stopped before forward because its one-off wrapper omitted the required weight-digest qualification field; a single corrected retry passed as above. No attempt updated weights. The successful command body exists in the tool transcript, not a retained one-command script; do not call it a production training command.

The user authorized A to handle normal guest access and choose/setup a compatible endpoint for the named disposable VM pilot. `SystemSense-Investigator-Qualification-20260922` still reports zero logged-in users; the latest normal-access check found it saved with its adapter cable disconnected after one failed blank-password sign-in; the clean snapshot remains available but a clean reset is unverified. No fault was injected. The earlier `https://example.com/` returned HTTP 200 in a host check, whereas the existing same-origin nonce-bound affected-task binder requires HTTP 204 with matching origin receipts. It also requires a captured CONNECT and HTTP 502 during the injected phase; the previously approved closed guest proxy port `127.0.0.1:9` cannot produce that receipt. A separate closed-port connectivity observation would be narrower and cannot be scored as that full binder. Normal guest access, a controlled origin, clean-reset verification, and a coherent independent outcome protocol remain open gates; this development PC is not the fault target.

After the test-only rehearsal change, `python -m pytest tests -q --ignore=tests/mcp` passed **3,144**, skipped **31** opt-in/runtime-specific tests, and emitted seven expected failure-path warnings in 389.35 s. The pinned Laya runtime separately ran all 10 loader focused tests; the default environment passed nine and explicitly skipped the one Torch-dependent test. Repository-wide Pyright returned 0 errors/0 warnings, Ruff lint and format passed (551 files), `git diff --check` passed, and `uv build --wheel --offline` produced the wheel. These checks do not change the absent real-label and VM-oracle gates.


## Subscription investigator trial

At implementation `ac236bb`, the explicit development command below reuses the
existing synthetic game-performance fixture and actual pinned Laya, with GPT-6
Sol advisory reasoning through the logged-in Codex subscription. The standalone
npm Codex 0.145.0 rejected this model; the installed bundled 0.155.0-alpha.16
acknowledged it and completed a subscription connectivity call. Pass a compatible
installed executable explicitly; the driver never installs or upgrades one.

```powershell
.\.venv\Scripts\python.exe -m benchmarks.subscription_loop --codex-executable '<absolute installed codex.exe>' --artifact-directory '<new private artifact directory>' --budget-seconds 180
```

The case deadline is at most 180 seconds; managed Laya startup precedes that
budget. The existing v4 profile supplies the Laya resource owner, while the
reasoning route is Codex and does not call its local Qwen reasoner. This is not a
matched Qwen/Sol comparison: context capacity, output constraints and call timing
may differ. Exact prompts, response schemas, model returns, acknowledged runtime,
case database, frozen choices, admission/execution links and later reviews stay
in the private artifact directory. Full Laya worker payload capture is off; this
is not a training-parity trial. Run the opt-in integration test only with
`SYSTEMSENSE_RUN_LIVE_SUBSCRIPTION=1`, `SYSTEMSENSE_CODEX_EXECUTABLE` and
`SYSTEMSENSE_SUBSCRIPTION_ARTIFACT_DIRECTORY`; ordinary tests never start either
model.

The mechanical gate requires an actual nondegraded Laya measurement choice, exact
successful registered execution, and an accepted later Codex review of observed,
considered evidence. Citations or a lexical missing-target/time statement provide
traceability only. Independently inspect whether the later pressure reading
weakens sustained pressure without erasing earlier/intermittent load; whether
thermal telemetry supports a GPU rival without inventing an affected-game link;
and whether delivered rivals, counterevidence, citations and time limits survive.
An unresolved conclusion can pass this reasoning review. No forced diagnosis,
Windows accuracy, policy superiority, speed result or training label follows.

The `ac236bb` trial (`sol-loop-02`) passed the mechanical gate with two exact
Laya-selected registered executions and two accepted Sol responses. The later
response supported a GPU-thermal rival using 92 C / 300 MHz / thermal telemetry,
and contested sustained CPU pressure using the later 3% reading while retaining
the earlier 97% reading. Both model-selected observations executed during the
first deep call and appeared in the second request. Sol explicitly declined to
link either reading to slow game frames; the case closed with
`insufficient_observability` and no causal assessment. Independent review accepted
this narrow reasoning result; `score.json` deliberately leaves semantic correctness
`not_evaluated` because the automated scorer cannot establish it.

The first and second accepted Sol calls took 12.297 and 15.359 seconds. These are
observations from one synthetic run, not a latency comparison. The invocation
had no bound affected task, target handle or window. The response acknowledged
missing frame-time overlap, but did not explicitly analyze game/adapter identity.
New hypothesis IDs also left old rival wording, including an obsolete request
for underlying observations, in the final case; one same-ID revision was rejected.
This is not complete rival reconciliation or qualified target/time reasoning.
An earlier transport attempt (`sol-loop-01`) failed both deep calls and remains
a failed run. The corrected run is not a matched Qwen/Sol experiment.

## Frozen overnight Investigator evaluation

The committed suite runs the real Investigator against substituted, registered
read-only collectors. Its 12 synthetic cases cover network/browser,
application/storage, and GPU/resource symptoms: two development and two holdout
cases per family. This is a **case-heldout** split, not a family-disjoint test or
a Windows fault pilot. Each case has a 90-second budget and the same frozen
visible input, initial evidence, action catalog, and probe budget across arms.
The hidden outcome oracle is evaluator-only; it must never enter a model prompt,
candidate ID/title, or policy. Preserve the raw fixture bytes and their hashes:

- Suite `benchmarks/fixtures/overnight_suite.json` SHA-256:
  `87ba8cd18d01b263023e099de325fa31f21331b89a63511d1cfc73a90f1a4467`.
- Synthetic recipes `benchmarks/fixtures/overnight_cases.json` SHA-256:
  `1696889f534a4b69e20a447b6171cf37da1a496940ea0c065a06b202149afd66`.
- Separate oracle `benchmarks/fixtures/overnight_oracle.json` SHA-256:
  `53355470522d027d88a3854de044568ecd5d96208f44d08a383c905edaa38fde`.

The runner rejects a changed suite digest or case contract; scoring separately
requires the preregistered oracle digest. Compare normalized starting contracts
across arms rather than claiming byte-identical runtime requests, whose generated
case IDs and clocks differ. Keep every failed attempt, raw model return, retry,
and prior score. The four phases are `development_baseline`,
`development_candidate`, `heldout_baseline`, and `heldout_candidate`. Diagnose
and revise on development cases. Freeze the candidate revision, then execute
both old-baseline and candidate holdout arms before inspecting holdout scores;
using holdout results to change the candidate consumes that holdout. The
[final measured result](#overnight-measured-result-2026-09-28) records completed
heldout evaluation and the remaining diagnostic qualification gaps.

From the exact baseline or candidate checkout, with an active Python environment
and a private absolute output directory outside the repository, reproduce the
freeze and one development arm as follows. The installed native Codex executable
must be supplied for Sol arms; the driver does not install one or use a paid API
fallback. Replace the revision and path placeholders with frozen values. Run the
baseline command at `$Baseline` and the candidate command at `$Candidate`:

A shared editable virtual environment can import `systemsense` or `benchmarks`
from a different checkout. In each exact checkout, set `PYTHONPATH` to its
`src` directory and verify both imported module paths before freezing or
running an arm; a checkout-local environment is another way to isolate imports.
Repeat this guard after switching checkouts. An imported path outside the
active checkout invalidates that run's revision attribution.

```powershell
$Checkout = (Resolve-Path .).Path
$env:PYTHONPATH = (Join-Path $Checkout 'src')
python -c 'import pathlib, systemsense, benchmarks.overnight_suite as suite; root = pathlib.Path.cwd().resolve(); print(systemsense.__file__, suite.__file__); assert pathlib.Path(systemsense.__file__).resolve().is_relative_to(root / "src"); assert pathlib.Path(suite.__file__).resolve().is_relative_to(root / "benchmarks")'
$Suite = (Resolve-Path .\benchmarks\fixtures\overnight_suite.json).Path
$Oracle = (Resolve-Path .\benchmarks\fixtures\overnight_oracle.json).Path
$SuiteSha = '87ba8cd18d01b263023e099de325fa31f21331b89a63511d1cfc73a90f1a4467'
$OracleSha = '53355470522d027d88a3854de044568ecd5d96208f44d08a383c905edaa38fde'
$Baseline = '<frozen baseline Git SHA>'
$Candidate = '<frozen candidate Git SHA>'
$CodexExe = '<absolute installed codex.exe>'
$Out = '<absolute private directory outside the repository>'
python -m benchmarks.overnight_suite freeze --suite $Suite --oracle $Oracle
python -m benchmarks.overnight_suite run --suite $Suite --suite-sha256 $SuiteSha --oracle-sha256 $OracleSha --phase development_baseline --arm laya_sol --baseline-revision $Baseline --codex-executable $CodexExe --output-root $Out
python -m benchmarks.overnight_suite run --suite $Suite --suite-sha256 $SuiteSha --oracle-sha256 $OracleSha --phase development_candidate --arm laya_sol --baseline-revision $Baseline --candidate-revision $Candidate --codex-executable $CodexExe --output-root $Out
python -m benchmarks.overnight_suite score --suite $Suite --suite-sha256 $SuiteSha --attempt '<attempt directory printed by run>' --oracle $Oracle --oracle-sha256 $OracleSha --score-revision '<reviewed scorer Git SHA>'
```

For the matched holdout pair, substitute `heldout_baseline` and
`heldout_candidate` for the two run phases and pass the candidate revision to
**both** runs with `--candidate-revision $Candidate`. Score only after both arms
finish; rescoring with `--score-revision` writes a new score file without
overwriting an earlier one. The `deterministic` arm uses the existing meaningful
baseline with no model. Run it with `--arm deterministic` and omit
`--codex-executable`. `deterministic_search_sol` combines deterministic search
with Sol reasoning; label it as that hybrid ablation, never “deep-only” or a
Sol-owned choice policy. The `laya_sol` arm reuses one explicitly owned warm
Laya runtime across sequential cases. Cold startup is separate from case time;
completed mailbox durations include queue wall time rather than pure model
latency. Retry counts have their recorded capture scope. Process CPU/RSS
samples are not host/GPU peaks or external model-server attribution.

From `c8a871c`, Laya trials also save `laya-worker-calls.json` and
`runtime.laya_worker_calls`. These are passive per-case worker-protocol counts:
rank attempts, attempted writes, flushed writes, completed ranks, and failed
ranks. They exclude prewarming, retain fatal-case receipts when writable, and
do not count neural forward passes. Nonzero in-flight counts at either case
boundary make case attribution incomplete. The meter does not enable input
capture or change caching. Earlier attempts lack these complete protocol
counters; persisted successful ranking microbatches are only a lower bound.

Score fast choices only through a nondegraded persisted frontier response,
exact selected candidate, admission, invocation, and execution. Score
asynchronous deep choices separately through a schema-38 applied response and
immutable proposal-to-execution receipt with exact manifest, parameters,
target, and window. A same-ID later run is not causal proof; older schema-37
databases without these receipts leave deep-origin choice **unknown**, not zero.
Report useful choice, successful supported observation, and a later accepted
response as distinct gates. Denied, failed, unsupported, truncated, and unrun
checks may justify honest uncertainty but cannot earn a completed useful
observation loop. The scorer leaves semantic correctness, raw rejected claims,
final accepted claims, affected-task time/target binding, and competing-cause
handling for independent human review. Exact Sol prompts are captured, while
full Laya worker input capture is incomplete in this operator path; do not call
its automated hidden-oracle leakage check a complete all-model-input audit.
These fixtures and mechanical links cannot establish real Windows diagnostic
accuracy, speed superiority, or a training-admissible label.

“Useful” in the mechanical counts means the frozen oracle designates the exact
registered check useful; it does not measure incremental information gain. In
the two development network cases, `network.configuration` repeats DNS, route
and proxy settings already supplied by bootstrap `network.connectivity`. Its
selection, execution and later review are real, but those counts alone do not
show better browser diagnosis. Report new storage coverage and corrected rival
reasoning separately from these repeated-configuration checks. Preserve the
frozen oracle and original scores when documenting this limitation.

The read-only `benchmarks.overnight_report` command inventories every attempt,
including incomplete or unreadable artifacts, and selects an explicitly named
score revision. It reports known and unknown denominators separately and checks
normalized starting-contract parity across arms. It neither reads the hidden
oracle nor rescores a run. Generate its immutable output outside the repository:

```powershell
python -m benchmarks.overnight_report --suite $Suite --suite-sha256 $SuiteSha --attempts-root $Out --scorer-revision '<reviewed scorer Git SHA>' --oracle-sha256 $OracleSha --output '<new private absolute report path>'
```

An optional `--reviews '<private review sidecar>'` binds reviewer notes to each
exact attempt ID and score-file SHA-256. Record the reviewer and review scope;
primary-agent review is not independent human or blinded grading. Score files
do not embed a capture digest, so adjacent score and capture hashes provide an
artifact inventory, not an independent proof that a score was computed from
that capture. Keep the preserved raw responses and accepted checkpoints
available for reproduction and semantic review.

## Overnight measured result (2026-09-28)

Product candidate `12990adc0513991669ac30268e8a2d70d3f228fc` was compared with
`fc7f81430f5a380b6c510fbfaecd2418ac42ffad`. All suite scores use the common,
audit-bound scorer `ef2ed6fff55335cdb874b31a0416a391291b5ed1`. Rescoring the
105 earlier attempts changed no result field except scorer revision. The final
18 development attempts bring the retained development inventory to 141.
Intermediate failures are included in the private inventory and build history;
this table compares the preregistered baseline with the final candidate, not
the best result chosen separately for each case.

### Development before/after

Each row is one synthetic run per revision. Times are case wall seconds with
cold Laya startup excluded. Calls include validation retries. Neither a current
summary nor a frozen-useful check is a whole-case diagnostic pass.

| Case | Baseline behavior → candidate behavior | Sol calls | Retry prompts | Case seconds |
|---|---|---:|---:|---:|
| `7c2b80de4573`, configured proxy | No accepted post-measurement review → conditional proxy/configuration review; browser use and endpoint outcome still unobserved | 1 → 2 | 0 → 0 | 14.42 → 29.20 |
| `21a684f9c275`, normal local settings | No accepted post-measurement review → configuration kept separate from untested target reachability | 1 → 2 | 0 → 0 | 11.91 → 30.00 |
| `cf38a20e5b41`, PageDesk event | Summary notes event but rival says evidence absent → same rival acknowledges matching event with launch-time gap | 5 → 3 | 2 → 0 | 69.12 → 51.75 |
| `e046c3592e77`, low disk / other app event | Storage not collected → 94 MB free observed; OtherTool event separated from PageDesk; no proven launch dependency or distinct storage rival | 5 → 2 | 2 → 0 | 57.90 → 27.41 |
| `6db492a1c735`, thermal / falling CPU | Later CPU used but GPU rival remains stale → thermal flag incorporated conditionally; earlier 97% and later 3% remain time-qualified | 6 → 4 | 2 → 0 | 83.37 → 55.73 |
| `d9750c64ae92`, GPU power cap | Cap summary but stale pressure rival → software power cap separated from Windows scheme and low CPU/memory; game binding still absent | 4 → 3 | 1 → 0 | 68.26 → 43.54 |

The candidate used **16 Sol calls versus 22**, **zero validation retries versus
seven**, and no captured call failure in either of these Laya–Sol six-case runs.
Mean case wall time was 39.60 versus 50.83 seconds. The two network cases got
slower while gaining a post-result review. Cold Laya startup was 15.688 versus
16.094 seconds, measured separately. These single development runs are not a
statistical speed, cost or reliability guarantee. Actual app-server records
acknowledge GPT-6 Sol/OpenAI with ChatGPT authentication, no environment access
and zero MCP tools, using native Codex 0.155.0-alpha.16. The installed Laya package is 0.3.5 on Python 3.12.14 and Torch 2.10.0+cu128; the profile configures CUDA device 0 and float16. The pinned model is `convaiinnovations/laya-typed-decisions` revision `f9ab0b228f0fc0f14d873dbc99038f135c2da1b2`, whose startup weight check requires SHA-256 `4fa56de72383a9d3efa9cfa78955733c81b9fc8067a587ca4beb82c78107a24e`. This trial overrides the profile's deep role with Sol; the Qwen entry is not a Qwen execution claim.

Candidate mechanical frozen-useful loops occurred in six of six cases: four
fast-origin and three deep-origin cases, with thermal overlapping. The baseline
has one verified fast-origin useful loop; its older schema leaves deep-origin
attribution unknown, so **6/6 versus 1/6 is not an aggregate uplift claim**.
The two candidate network configuration checks repeat bootstrap facts; the new
storage observation and corrected rival content are stronger evidence of
improved coverage/reasoning than those repeated-check counts.

All six candidate summary generations were current, all six causal assessments
were null, and review found no unsupported definitive cause among the 16 raw
returns and six finals. Review still found older security wording, incomplete alternative coverage and weak citation
classifications. The PageDesk third call follows newly expanded requested event
detail, not an idle duplicate.
The lead reviewed these raw claims and final states; a second agent audited
16 applied deep tasks and all 11 deep-origin receipts. This is agent review,
not blinded independent human grading or full causal correctness.

### Comparator scope

| Development arm | Sol attempts / raw returns | Validation retries / failures | Interpretation |
|---|---:|---:|---|
| Baseline Laya–Sol | 22 / 22 | 7 / 0 | Legacy deep-origin attribution unknown; missed storage and retained stale rivals |
| Candidate Laya–Sol | 16 / 16 | 0 / 0 | All six later reviews current; new storage coverage and corrected rival context |
| Baseline deterministic-search + Sol | 28 / 27 | 9 / 1 | Degraded app/thermal work and retained coverage gaps |
| Candidate deterministic-search + Sol | 19 / 19 | 0 / 0 | Useful conditional local distinctions; storage still not collected and some rival rows stale |
| Baseline and candidate deterministic | 0 / 0 | 0 / 0 | Meaningful DNS/route/proxy rules; generic unknown on the four app/GPU cases |

The hybrid thermal summary correctly mentions telemetry, but its saved GPU rival
still falsely says none was observed. This is a semantic freshness failure. Other
hybrid rivals retain stale wording or omit unavailable evidence. Null assessment
does not erase these failures.

The hybrid has a different scheduling path and lacks asynchronous origin
receipts; it is not deep-only or a controlled single-factor Laya ablation.
Zero verified model-origin links in a deterministic/hybrid arm must not be
presented as zero executed checks. A second agent reviewed all 19 final-hybrid
raw returns and 12 comparator finals; the lead separately reviewed the finals.
No unsupported definitive cause was found within that scope. Hybrid uncertainty
sometimes carries weak support classifications; it is not a clean whole-case pass.

The final Laya–Sol development run recorded 89 completed Laya worker protocol
requests, no failed request and zero in-flight requests at case boundaries.
This is not a neural-forward-pass count. Earlier baseline protocol totals are
unknown. Per-case before/after CPU/RSS samples are preserved in each score,
covering the runner and live children only. They exclude peaks, unrelated
processes and external servers; no host/GPU utilization or cost savings claim
is supported.

### Heldout before/after

Source `12990ad` was frozen before final heldout execution. The earlier 30-attempt
cohort at `5866a83` had finished but its answers remained unreviewed when the
original-loop reference-loss fix was selected. The predeclared followup reused
**all 12 unchanged baseline attempts**, with original start/capture hashes, and
ran all three final candidate arms. All 18 intermediate candidate attempts remain
in the 48-attempt heldout report. No source changes were made from heldout results.
A worker's pre-release broad text search inadvertently returned generic heldout
SHA/ID lines and paths; no model answer or semantic label was inspected or used.
This protocol slip is disclosed rather than claiming perfect blinding. All final
arms finished before grading began at 13:28 UTC.

The split holds out cases, not families or machines. Each row is one baseline and
one final Laya–Sol run; the useful-chain column applies the frozen exact-choice,
execution and later-review rule, separately from semantic case quality.

| Heldout case | Observed comparison | Sol calls | Retries / failures | Case seconds | Final useful chain |
|---|---|---:|---:|---:|---|
| `b6d035ae29f8`, Absent default route | Both retain bounded route lead; final adds accepted post-result context; destination untested | 1 → 2 | 0/0 → 0/0 | 13.48 → 28.79 | pass, fast |
| `509ed3c4b780`, Denied network | Both preserve unknown fields; final summary uses later partial view but rival missing-ID updates are lost | 1 → 2 | 0/0 → 0/0 | 38.41 → 38.92 | pass, fast |
| `a934ed27f3c1`, Old OtherTool event | Both reject wrong target; final app rival retains the distinction, with unsupported extra local-AI check | 5 → 3 | 2/0 → 0/0 | 66.22 → 47.37 | pass, deep |
| `183f6bad8640`, PageDesk running now | Both distinguish running now from a prior launch; final keeps time-unbound empty-event context | 5 → 2 | 2/0 → 0/0 | 72.56 → 25.50 | pass, deep |
| `0e8ab51f4d63`, Unbound thermal GPU | Both keep thermal signal conditional; final avoids baseline call failure but misses useful inventory follow-up | 4 → 3 | 1/1 → 0/0 | 90.03 → 44.19 | fail, missing check |
| `b3e7814a209c`, Unavailable GPU | Both keep missing telemetry unknown; final updates resource rival but misses useful inventory follow-up | 4 → 3 | 0/0 → 0/0 | 58.43 → 37.29 | fail, missing check |

Final heldout Laya–Sol used **15 calls/15 returns, zero validation retries and
zero captured call failures**, compared with baseline **20 calls/19 returns,
five retries and one failure**. The baseline thermal case last accepted a
review at generation 5, then its later request expired at the case deadline while
current evidence had reached generation 9. Its legacy summary freshness field is
unknown; the saved mailbox establishes the incomplete later review. Mean case time was **37.01 versus 56.52 seconds**;
cold Laya startup was 15.921 versus 16.297 seconds and is excluded from those
case means. Both network cases got slower while obtaining later review. The
intermediate candidate used 14 calls, zero retries/failures and 35.73 seconds mean;
the final was selected before seeing those results, not for the smallest count.
The final heldout run recorded 89 completed Laya protocol requests, zero failed
requests and zero in flight at case boundaries.

Final useful chains passed **4/6**, two fast network and two deep application
chains. Both GPU cases failed to choose the frozen useful `local_ai.snapshot`
followup and did not inspect its additional inventory. Their bootstrap GPU
interpretation does not earn model-choice credit. The two network configuration
checks also repeat existing local facts. Baseline fast useful credit was0/6;
legacy deep-origin attribution is unknown, so an aggregate4/6-versus0/6 improvement
claim is invalid. All six final summaries reviewed current generations, which
does not prove complete evidence use or current rival wording.

Heldout deterministic results are stable across all three revisions: useful
bounded missing-route and denied-coverage rules, generic unknown with no rivals
for the four application/GPU cases. The final hybrid used 19 calls/19 returns,
one validation retry, zero failures and 48.58 seconds mean; the intermediate
hybrid also used 19/19 with one retry and 49.53 seconds mean. Its useful local
interpretations do not count as model-directed action chains. It is not deep-only.

The root reviewed all48 final states and29 intermediate/final Laya raw returns;
a second agent reviewed baseline Laya and both hybrid raw returns. Semantic
review keeps local condition discrimination, honest uncertainty and rival
freshness separate. The only heldout oracle case with a positive local rival is
the missing route; baseline, final and deterministic all identify it. The other
five require uncertainty. PageDesk running now does not refute an earlier exit;
OtherTool is not PageDesk; denied/unsupported telemetry never proves health.
Remaining failures include missing-ID/prose propagation, weak support/status
classifications, a thermal explanation under an older power-limit ID, and the
two missed GPU followups. No affected-task diagnosis was established.

Across the **12 final Laya–Sol synthetic cases**, calls were 31 versus 42 baseline
attempts, validation retries 0 versus 12, and captured call failures 0 versus 1.
Ten of twelve met the frozen useful-chain rule. These are measured engineering
results for this exact suite and runtime, not diagnostic accuracy, population
reliability, cost savings, or general speed guarantees. Every development and
heldout attempt remains in the 189-attempt inventory.


### Recorded resource samples

Each cohort has 12 before/after samples across six Laya–Sol cases. RSS is resident
memory of the runner and children alive at that instant. CPU values are summed
cumulative process counters, not per-case CPU cost or utilization. Exited children,
external servers, host/GPU peaks and VRAM are not covered. These measurements do
not support a resource-saving claim.

| Cohort | Sampled RSS range, MiB | Sampled CPU counter range, seconds | Processes at sample |
|---|---:|---:|---:|
| Development baseline | 2092.58–2144.94 | 21.50–48.75 | 4 |
| Development final | 2108.64–2164.47 | 20.95–51.25 | 4 |
| Heldout baseline | 2109.98–2164.57 | 21.44–50.27 | 4–6 |
| Heldout final | 2093.76–2148.95 | 20.92–45.00 | 4 |

### Original-loop regression and qualification boundary

At `5866a83`, the original synthetic performance loop recorded two actual Laya
measurement choices, two linked successful executions, and two accepted Sol
responses. The later response explained the pressure timing gap and unbound
thermal GPU target. Its preserved legacy `mechanical_pass=false` is a checker
false negative: the checker recognizes older citation fields and exact-ID
summary text but not the newer typed noncausal review. A separately versioned
check is reported below; the old score is not overwritten or quietly relabeled.
The final GPU rival retained its typed reference; the CPU rival kept older text
without the newer reference. Accepted result review is demonstrated, complete
rival propagation is not. That failure motivated a product fix before any heldout answer was inspected;
the preserved run was not overwritten.

Benchmark scorer v2 retains the old mechanical field and adds `review_loop_pass` plus typed review links. A typed link requires the exact Laya choice, admitted/audited execution, observed fitted and considered evidence, verified frozen request/read-set hashes, later applied nondegraded Sol response, matching typed explanation/reference and final checkpoint retention. Read-only replay of the preserved run has legacy false and v2 true through one GPU link; the dropped CPU reference earns no typed credit. The extension passed 37 focused tests with one live opt-in skipped. Its implementation is `f0f214a`; it changes benchmark accounting, not product behavior. Semantic correctness remains separately reviewed.

Product `12990ad` then adds exact-prior reference-only projection: validated
noncausal context can survive a mixed proposal while all prior wording, causal
citations, status and requested probes remain unchanged. The actual new original
loop, run because the product changed, has two Sol returns without retry/failure.
It retains both GPU target-unbound and CPU time-unbound references and exercises
the CPU projection with an explicit partial-rejection warning. Legacy mechanical
false and v2 review-loop true are both preserved. The lead reviewed both raw
returns and final rivals; the final cause remains unresolved. The candidate passed
3,738 non-MCP tests (32 skipped, one MCP deselected), whole type/lint/format gates,
161 focused tests, 18 desktop E2E checks and the separately built private unpacked
app smoke. The own-process live identity test passed; no fault diagnosis is implied.

All 12 fixtures lack independently measured affected browser, launch or frame
outcomes. The implemented task-observation resolver is fixture-only. Null causal
assessments therefore do not mean 12 correct diagnoses; generic uncertainty also
misses available local distinctions. The narrow listener/device/bind-conflict
assessments do not independently establish an affected-task root cause. Real
Windows diagnostic accuracy, repair success, production cloud readiness and
training admission remain unqualified. The next high-value gate is an exact
observed task/target/time outcome, subject to the existing VM/endpoint permissions.

### Reproduction and preserved evidence

Use the frozen commands above at the exact checkout revisions. For holdout, run
both baseline and candidate deterministic and Laya–Sol arms plus candidate
`deterministic_search_sol`, then inspect results only after all five finish.
Read model raw returns and final states alongside mechanical score files; do not
substitute an accepted response for semantic review. The agent review rubric
SHA-256 is `c19160d02db6ef8f338340d1613e909891fb13f35393045e227db29dfaa57dc4`.

Private artifacts are under `%LOCALAPPDATA%/SystemSense/overnight-20260928`:
`freeze-v2.json`, `candidate-v13.json`, `heldout-freeze-12990ad.json`, `heldout-freeze-5866a83.json`, immutable
`attempts/<suite SHA>/<case>/<phase>/<arm>/<attempt ID>`, raw responses,
read-only case databases, revisioned scores, and source-hash-bound review sidecars.
They are intentionally excluded from Git and packages. The final report and its
digests are listed here after evaluation; the committed recipe/scorer can reproduce
new independent attempts, not the nondeterministic model text byte for byte.

The final inventory contains 189 attempts, 189 digest-verified captures, 189
score-bound review annotations and 147 matching same-arm baseline/candidate pairs. All 12
normalized case contracts match; 12 heldout hybrid attempts are unpaired because
no baseline hybrid heldout was run. Legacy deep-origin attribution is unknown for
39 attempts. Separate custody audits cover all 189 attempts and pin 457 raw Sol
returns plus 13 failed-call artifacts. An older empty runtime acknowledgement is
unknown, not a mismatch or fabricated identity. Corrected v2 audit artifacts
supersede audit-reader encoding/comparison errors; original artifacts remain.

| Private artifact | SHA-256 |
|---|---|
| `overnight-scorecard-all-189.json` | `577913aa8a7407d303cd7b3287ed4f7affcc1d81a769f3e51ad093fdd43f4b4c` |
| `overnight-semantic-sidecar-all-189.json` | `6d70f494cde67d938b3b731c050f5d26f4c5569c9869a4a0979b9fee673ac3b0` |
| `development-custody-through-v13.json` | `e798f2dfb8d82bbeb2c63277e132f908e40748a6aadd2727c4310e49b9a962db` |
| `runtime-identity-through-v13-v2.json` | `5ff03da8480d755225afee5bae619f7bf031443641427253898bd081c2ebc045` |
| `heldout-custody-all48-v2.json` | `133bbe98c49f927281f129fb8eb404e9f8e40f90401ae5f19caf70f1fc784529` |
| `heldout-runtime-identity-all48-v2.json` | `23eaad8c8a65e0aaf578daff7c1cdd92f0feccef7b1564cdd6772cb0fc8a70f6` |
| `verification-12990ad.json` | `8356c2c3e1158ec9f3756fdc1bbc89fcdd2ee442ce9eeac5551b1ba62e184d56` |
| `old-loop-12990ad-semantic-review.md` | `f9a999ae50bbfdff3504ab42090726009914bbc00a3c7f8f5acb7e11bce2a82f` |
| `heldout-root-semantic-review.md` | `7c62da70ab87f6bcfefbe3975cbaaf18ed4425145ec1d00721b3e40b2dca675f` |
| `heldout-comparator-semantic-review.md` | `ab64fb0f08948f11fceeb6be3955bc8b045ae295f5c2164cf324d5f98b5cb5b7` |
