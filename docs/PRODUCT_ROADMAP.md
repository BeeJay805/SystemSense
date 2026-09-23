# Product direction: diagnose, fix, prove

SystemSense should let someone describe a computer problem in ordinary language,
find the useful evidence quickly, and restore the affected task when a safe software
fix exists. A result that feels finished is concrete: “Your game was capped at 12
FPS; the measured frame rate is now 86 FPS in the same scene.” When the cause is a
failed component, router, service, or other external system, the result should say
what was measured, what remains uncertain, and who or what needs attention.

This is a product target, not a description of the present release. The current
application is a tested, read-only Windows investigator. It has no enabled repair
executor and no measured general diagnostic-accuracy result. The [current
architecture](architecture/local-two-brain.md), [build evidence](APPLICATION_BUILD.md),
and [benchmark protocol](BENCHMARK_PROTOCOL.md) separate shipped behavior from the
work below.

## What exists today

| Layer | Current behavior | Product gap |
| --- | --- | --- |
| Deterministic coordinator | Runs 17 bounded Windows probes, parallelizes independent work, stores timestamped evidence and coverage, audits attempts, and recovers cases. | More decisive domain probes and controlled active tests. |
| Fast brain | Pinned Laya ranks evidence and eligible probes repeatedly; keyword planning is a fallback. | Windows action-quality training and a fast laptop runtime. |
| Deep brain | Pinned local Qwen3.8 27B compares hypotheses and requests focused evidence through a replaceable interface. | Held-out causal-quality evaluation and an optional cloud provider. |
| Knowledge | Sourced conditional reference graph plus observed temporal machine relationships. | Wider version-aware procedures and verified case outcomes. Graph links alone cannot prove a fault. |
| Result | Can support a few narrow observed answers, including listener ownership; broader cases may end with explicit uncertainty. | Causal diagnosis criteria, approved repair, independent remeasurement and recurrence checks. |
| Interface | Local browser supports cases, citations, cancel/resume, coverage and redacted export; MCP is optional. | A short consumer journey from symptom to validated outcome. |

The exact data boundary remains: models can choose from registered capabilities and
explain evidence, while SystemSense measures the machine and controls every action.
The reference graph, actual machine graph, and scheduler's task graph are distinct.

## Knowledge graph strategy

Grow the reference graph as a versioned, sourced map of *conditional* mechanisms:
component, setting, symptom, discriminating observation, and allowed next test.
Join it to observed installed versions and recent changes at investigation time;
keep support articles and prior cases retrievable but separate from live facts.
A bulk import of generic IT text or unverified edges would create confident false
paths. Admit new edges only with provenance, applicable versions, a counterexample
or exclusion, and a probe that could distinguish the mechanism. Evaluate graph
ablation on held-out incidents before calling graph expansion useful.

## Product promise and operating boundary

The first marketable promise should be **fast diagnosis and verified correction for
specific, qualified Windows software faults**, not "fix any computer problem."
An on-demand baseline may scan broadly, but deeper collection is selected by the
incident, source freshness, expected information gain, and user-visible cost.
Coverage gaps and contradictory measurements remain visible. A missing or broken
hardware component, an ISP outage, or an unsupported application can yield a
useful, cited escalation instead of a fictional software fix. Qualification is
per fault family, affected task, Windows version, and action scope.

Autonomy has three separate levels: read-only investigation without repair
permission; a proposed exact fix that a person approves; and a later, separately
qualified standing-consent policy for narrowly reversible actions. The current
release is at the first level. "Automatic" must never mean that a model can
invent a command, change a setting, or call its own explanation verification.

## Deployment evolution

Keep the deterministic collector, local case store, action gate, and a qualified
fast brain on the user's PC. Today's optional desktop profile pairs Laya with a
local Qwen3.8 27B reasoner; this is not a laptop deployment recommendation. A
later consumer profile can send only a redacted, user-approved focused evidence
map to a replaceable cloud deep reasoner. The provider can propose hypotheses
and registered next probes, never execute repairs or silently collect more data.
When cloud access fails, the case remains inspectable and local deterministic
checks continue; a broken Wi-Fi connection must not make diagnosis impossible.
Keep a fully local deep provider available for adequately equipped machines,
without making a large local model mandatory for ordinary laptops. Cloud price,
privacy, availability and data-retention terms require their own qualification.

## Milestones, in order

### 1. Establish a reproducible outcome benchmark

Build [the benchmark protocol](BENCHMARK_PROTOCOL.md) before selecting another
model or claiming that the dual-brain design is faster. Start with a software
proxy fault, a slow PDF workload, an external DNS failure, and a healthy control.
Use VM checkpoints for software cases and separate physical rigs for Wi-Fi and
gaming. Blind reviewers to the injected cause when they judge SystemSense's cited
diagnosis. A fault that does not reproduce independently is an invalid episode,
not a successful investigation.

The owned-port rehearsal exposed an answer-layer gap: the collector persisted
an exact listener owner, but a broad bind-failure objective ended unresolved.
The current application now retains a separately typed, cited **observed
finding** for a complete, current endpoint-owner row while keeping the wider
cause unresolved. It does not turn that finding into a diagnosis or repair
proposal. Target scan and packet omissions withhold the finding, and the UI
shows it alongside the reasoning summary, terminal outcome, and stop reason.
The next gate is to use additional independent evidence to distinguish the
actual bind-failure cause and qualify a separately approved action and oracle.
The next evidence-core change is a versioned causal-claim contract, not a more
confident prompt. Persist the target application's own failed bind attempt as
case evidence (endpoint, address family, socket options, target identity and
configuration, source time, WinError 10048, provenance), then correlate it with
complete contemporaneous listener ownership. The current independent target
observer records this only in the harness report. It must not be smuggled into
the case as the planted fault label. A verified recovery is a still stronger
claim: exact approved action, ordered independent retry, unchanged target
configuration, successful bind **and** application response, plus collateral
checks. The present `root_cause_proven` contract cannot represent that claim.

**Exit:** repeatable injections and independent symptom oracles; frozen probe
catalog, time budget, provider versions and permissions for each comparison;
failures and unknown cases retained. Existing fixtures and five synthetic
coordinator episodes remain engineering checks, not diagnostic-performance data.

### 2. Prove one complete fault family: connectivity

Build a staged connectivity map: radio and Wi-Fi association, IP assignment,
gateway, DNS, TLS, then the affected application. Collect Windows WLAN reason
codes, signal/association state, DHCP and adapter transitions, route/DNS/proxy
state, and nearby event history with source times. Add narrowly scoped active
tests against an owned endpoint only when their network traffic and timeout are
allowed. Correlate failures across a second device or lab service before calling
an external cause. Targeted evidence must distinguish “not connected to Wi-Fi”
from “connected, but this app cannot reach its server.”

Keep an offline local diagnostic path: a broken connection cannot depend on a
cloud reasoner. Start with reviewed deterministic rules and the current advisory
models; use a cloud provider only for cases that can reach it and pass a separate
privacy/export decision. [Microsoft's connectivity troubleshooting stages](https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/wireless-network-connectivity-issues-troubleshooting)
are a useful source for the probe catalog, not machine-specific evidence.

**Exit:** held-out connectivity cases show a supported cause or justified
uncertainty, including external and healthy controls. The fast brain must improve
probe choice or time to a supported answer over the same deterministic baseline.

### 3. Add a narrow, verified software repair boundary

Implement only versioned, typed procedures for the fault family just qualified.
The first catalog could cover an exact proxy setting or a lab-owned service;
adapter toggles and network resets need separate interruption and rollback
handling. An action request must bind the device, user, target identity, observed
state, expected change, expiry and permitted adapter. The local executor
rechecks those preconditions, consumes a single-use authorization, journals the
attempt across crashes, and records an independent before/after symptom test.

The current narrow WinINet runner durably claims its token and target, rechecks
consent and live state before a write, and persists affected/direct/post-change
evidence IDs. A separate admission store now persists immutable exact proposals
and at most one atomic review claim per proposal across restarts, rejecting
stale case state, an inactive proposal, and expired acknowledgements. Its
active-plan head binds the exact proposal ID and digest, so a newly proposed
action supersedes an older one even when the procedure revision string and case
state are unchanged. The procedure revision check at registration still relies
on the trusted application layer. A claim ID is **not** proof of human
authentication or an execution lease: the store is not mounted in the browser,
does not authorize a repair by itself, and cannot safely replay an interrupted
action. The existing runner still checks only case state plus the procedure
revision at its write boundary; a same-revision proposal replacement would be
invisible there. It must check the exact active proposal ID/digest under a
unified execution claim before any live writer is connected. The runner is not
connected to an application consent issuer. Target
identity, all managed-policy sources, the endpoint and affected application
scope still need independent qualification; crash reconciliation must never
blindly replay a possibly applied write. Consent defaults to unreviewed, but
that alone is not an executable safety boundary. Begin with explicit per-action
approval; consider short-lived standing consent for well-tested reversible
actions only after false-repair and rollback rates are measured. A model never
sends shell commands.

Before connecting the native writer, put approval and execution claims in one
durable transaction and require a trusted interactive reviewer. A loopback
browser cookie and CSRF token defend the web surface but do not authenticate a
person. Microsoft's [desktop consent guidance](https://learn.microsoft.com/en-us/uwp/api/windows.security.credentials.ui.userconsentverifier)
uses a window-bound verifier; its [Win32 interop method](https://learn.microsoft.com/en-us/windows/win32/api/userconsentverifierinterop/nf-userconsentverifierinterop-iuserconsentverifierinterop-requestverificationforwindowasync)
requires Windows build 22000 or later and may be unavailable or disabled. That
is a candidate broker for qualified Windows 11 deployments, not a universal
Windows 10 approval solution. Unavailable review must leave repairs disabled.

**Exit:** zero unauthorized actions and zero false repairs in the pilot, with a
real independent symptom improvement after each reported fix. Small pilots do
not establish a field safety rate. A failed verification is reported as a failed
repair, not success.

### 4. Make the fast brain practical on ordinary PCs

The current Laya checkpoint is 421M parameters and was trained on four synthetic
workflows. On the development host, a warm CPU pass over 100 fragments and 25
probes took **65.820 seconds** and its process tree peaked at **2.72 GiB**; the
qualified RTX 4090 FP16 pass took **1.269 seconds** for the 100-item model pass.
In a later CPU-only rehearsal with 54 bounded previews and all 17 registered
probes, cold attention took **124.266 seconds**, warm passes with distinct
symptoms took **105.890/106.688 seconds**, and sampled owned-process peak RSS
was about **3.03 GiB**. These are different workload shapes, not a before/after
speed comparison.
These measure runtime, not Windows routing quality or laptop speed. The present
adapter supports CPU and NVIDIA CUDA, not an Intel/AMD integrated-GPU path. The
[upstream model card](https://huggingface.co/convaiinnovations/laya-typed-decisions)
explicitly warns about out-of-domain behavior.

Keep the existing replaceable fast-provider contract, but do not assume the
421M-parameter Laya checkpoint is the right laptop model. The recommended first
laptop candidate is a **typed-feature ranking policy**: deterministic eligibility
and graph traversal first, then a small ranker using evidence status/freshness,
symptom match, graph distance and edge provenance, expected distinguishing
value, probe cost, prior yield, and revisits. The current keyword/deterministic
route is the baseline, not training ground truth. A
[LightGBM learning-to-rank model](https://lightgbm.readthedocs.io/en/stable/pythonapi/lightgbm.LGBMRanker.html)
is one implementation to test once independent expert next-probe labels exist;
its latency, memory and diagnostic value here are unmeasured. It must still
return only registered probe IDs through the normal admission gate.

If typed features lose useful semantic matches, test the compact
[BGE-small-en-v1.5 encoder](https://huggingface.co/BAAI/bge-small-en-v1.5) as
one cached similarity feature. Reserve a
[MiniLM-L6 cross-encoder](https://huggingface.co/cross-encoder/ms-marco-MiniLM-L6-v2)
for top-K reranking only if it improves held-out action quality enough to pay
for pairwise CPU inference. Compare these against incumbent Laya and an
optimized/exported Laya under identical evidence, catalog and budgets. These
general retrieval models have no established Windows investigative skill.
Try ONNX CPU first, then the supported
[Windows ML](https://learn.microsoft.com/en-us/windows/ai/new-windows-ml/overview)
path where it improves actual hardware performance. Windows ML can target CPU,
GPU and supported NPUs; support for a particular converted checkpoint must be
tested. Its vendor providers may download on demand, so installation and offline
behavior must be explicit.

Measure an 8 GB CPU laptop, a 16 GB integrated-GPU laptop, a 4-8 GB NVIDIA
laptop, and the development desktop. Record cold start, warm p50/p95 decision
latency, RAM/VRAM, battery or power, full evidence coverage, and interference
with the user's workload. A proposed **3-second p95 attention-cycle target** is
an engineering goal, not a present result. Reject a candidate that loses
held-out useful-probe recall to the deterministic baseline or increases unsupported
diagnoses, regardless of model size. In a gaming case, GPU inference must not
create the slowdown under investigation.

Fine-tune or train the fast ranker only after expert-reviewed next-probe labels exist.
The checked-in label contract freezes candidate probes, evidence references,
post-probe outcomes and reviewer/redaction attestations; it contains no field
labels yet and cannot authenticate a reviewer's identity by itself.
Split training, validation and final tests by case, machine, app/version and fault
family so pages from one investigation cannot leak across splits. A future cloud
deep brain does not prevent local fast-brain training. Choose the deep provider
through the same held-out outcome and cost tests; do not name a universal
“perfect” pair from upstream leaderboards or synthetic protocol checks.
The current Qwen3.8 27B is a locally qualified interface/runtime on this desktop,
not a demonstrated best diagnostician. A future cloud deep model should be
chosen on the same blinded cases after redaction and privacy gates exist; its
vendor and size are deliberately not fixed at this stage.

### 5. Expand by complete domain journeys

For a slow PDF, measure the exact viewer/version, document and page-turn latency;
correlate process contention, storage, renderer, extensions and graphics settings
before changing anything. For a 12-FPS 4090 game, capture frame-time distribution
in a pinned scene, display and in-game caps, actual render GPU, driver/version,
power/thermal behavior and overlays. The [PresentMon project](https://github.com/GameTechDev/PresentMon)
provides a frame-time measurement route to qualify on the physical rig.
Expansion follows diagnosis and repair evidence for one family at a time, rather
than adding broad collectors that never distinguish causes.

## Product release gates

- **Truth:** a cited cause survives reviewer challenge; healthy, hardware and
  external failures produce appropriate uncertainty or escalation.
- **Outcome:** the affected task is measured before and after an authorized fix;
  collateral behavior and recurrence are checked.
- **Safety:** no unrestricted model authority, no mutation outside an exact
  approved target, and every action has a durable result.
- **Speed:** report p50/p95 to decisive evidence, supported answer and verified
  recovery, with cold starts and observer overhead included.
- **Access:** a CPU-only laptop and a disconnected computer retain a useful
  local path, even if cloud reasoning or GPU acceleration is unavailable.

“Replaces a call to IT for common software issues” becomes a defensible claim
only for fault families that pass these gates on held-out machines. Hardware and
external failures may be explained and routed without pretending software repair
is possible.
