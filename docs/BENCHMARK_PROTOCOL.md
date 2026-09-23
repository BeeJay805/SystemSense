# Diagnostic and repair benchmark protocol

`benchmarks/owned_port_journey.py` is a separate controlled real-host integration
rehearsal. It starts only its own loopback listener, collects full registered
listener snapshots before and after the failed bind, and runs the same fixed
target configuration in a separate process. The target reports its actual
Winsock 10048 bind failure and socket options, which the harness validates
and persists through a registered runtime probe with its source observation
time. The investigator now supports the narrow
`owned_tcp_bind_conflict` explanation from that failure plus the same exact
listener owner observed on both sides of it, rather than inferring causality
from one owner row alone. The action gate requires that exact three-evidence
assessment and rechecks the owned blocker's PID, creation time and endpoint.
The harness then terminates only its own disposable process and checks that
the target can bind and serve HTTP.
`root_cause_proven=false` still reflects the limited scope of one observed bind
attempt; SystemSense has not proposed or executed a consumer repair. This is not
a held-out diagnostic-accuracy or consumer verified-fix score. It used default
keyword attention and deterministic reasoning, not the optional Laya/deep-brain pair.
The version-2 rehearsal runs the same fixed target configuration in
separate bounded processes before and after the harness-owned action. It
retains raw UTC-timestamped bind/HTTP results and a matching configuration
digest; an observer error or missing raw result cannot count as recovery. The
write-once CLI report is reserved and synced as `in_progress` before host work,
then finalized; an interrupted report is not a success. The harness still
supervises both processes, so this is not an independent VM oracle. Target-scan
or packet omissions withhold the unique-owner finding. The live tests are
opt-in with `SYSTEMSENSE_OWNED_PORT_REHEARSAL=1` on Windows; ordinary test runs
do not create or terminate even a disposable listener.

The causal admission is deliberately narrow: exact IPv4/TCP endpoint, Winsock
10048, exclusive address use, distinct stable owner identity, complete
persisted listener tables with no omitted rows, and observations strictly
bracketing the bind failure within two seconds on either side. An unrelated
inaccessible owner may make the whole table `partial`; that is admitted only
when it is the sole limitation and the exact endpoint's owner is complete.
A compact model context cannot substitute for full persisted rows. Neither source timing nor the
in-process benchmark probe is an independent VM oracle, and database provenance
is not a cryptographic attestation.

`systemsense.evaluation.attention_replay` provides a separate held-out
next-probe ranking protocol. Version-2 expert labels bind the exact visible
evidence, registered candidate catalog and provider-visible capabilities by
canonical digest; version-1 labels remain readable but unscorable. Top-K counts
all proposed slots, including unsupported suggestions, and reports recall over
explicitly labeled useful probes, negative top-K suggestions, and how many
registered candidates have a recorded outcome. Untried candidates remain
unknown, so this is not counterfactual probe utility. Any matched outcome time
is the recorded expert outcome, not a provider's counterfactual time to evidence.
Hashes check consistency, not reviewer authenticity or split independence. No real expert
labels or held-out performance scores have been admitted yet.

This protocol measures the whole user journey rather than a model's confidence
or a report's arithmetic. Existing JSON fixtures test schemas and the five
synthetic coordinator episodes test instrumentation. Neither injects an
independently verified Windows fault or measures a repaired symptom.

`benchmarks/lab_episodes.py` now implements a versioned controlled-lab harness:
sealed fault labels, separate numeric symptom checks, clean/injected/after-arm/
after-restore readings, arm/profile binding, and conservative action-journal
cross-checks. Its owned-loopback rehearsal closes only its own ephemeral listener
and runs the real coordinator, then restores the listener itself. Every output is
marked `controlled_lab_rehearsal`, `diagnostic_accuracy_claim=false`, and
`repair_verified=false`; symptom recovery following an action is deliberately
narrower than causal repair proof. A repeatable Windows fault lane, independently
verified full-state reset, blinded cause review, and matched A/B/C arm runs are
still required before the scorecard below can be used for product claims.

`benchmarks/vm_lab_contract.py` adds protocol admission for two allowlisted VM
recipes: a wrong current-user WinINet proxy and a healthy control. It checks the
claimed image/checkpoint/catalog/code identities, fresh rig attestation, distinct
rig/oracle/arm controller IDs, full-state reset digests and unique generations,
seeded injection signature, exact arm profile, UTC event order, and symptom
readings recalculated against the manifest threshold. `ARM_ERROR` trials remain
admitted failures in the denominator. Even a passing admission is labeled
`vm_protocol_only`, with `diagnostic_accuracy_claim=false` and
`repair_verified=false`: the JSON proof is not an audited rig, a VM run, an
independent endpoint, or evidence that the declared state was actually measured.
`benchmarks/virtualbox_preflight.py` performs only fixed read-only inspection of
an existing VirtualBox VM, snapshot, attached media, network isolation and Guest
Additions metadata. Its result is explicitly `virtualbox_preflight_only`, not a
fault injection, guest-control proof or measured episode. The development host's
Golden source is blocked for direct cloning by an inherited auxiliary optical
image; a new isolated linked clone was booted after detaching that image on the
clone only, but reached a password-expired prompt. No guest fault or independent
oracle has run. A controller with authenticated guest access, reset validation,
separate oracle and artifact custody is the next qualification step.

`benchmarks/vm_qualification_readiness.py` checks the specific clone using only
fixed read-only VirtualBox commands. On 2026-09-23 it found the clone powered off,
NIC disconnected, no snapshot, and no available Guest Additions metadata; guest
login and clean reset are unverified. It reports `can_begin_episode=false`
because host metadata cannot prove those guest gates.
`benchmarks/vm_lab_custody.py` provides bounded, write-once raw host captures with
role separation, source/collection times, hashes, readback, and a fixed trial
sequence check. This is `host_capture_only`, not an authenticated oracle, proof
of VM execution, or a scored product outcome. A real controller must supply and
authenticate captured observations before benchmark admission.
A separate `host_review_capture_set_only` check requires a later review capture
from a fourth controller ID; neither the ID nor a hash establishes that the
reviewer was independent, blinded, or correct.

`benchmarks/windows_scorecard.py` accepts a separate type of externally reviewed
real-Windows episode. It refuses the rehearsal and protocol-only objects as
standalone performance evidence, checks matched A/B/C access, profiles, warm
state and distinct resets, retains failures/timeouts in the denominator, and
reports cause accuracy, false fixes, verified recovery, terminal wall-time,
reviewer-adjudicated first-useful-evidence time, and supported-answer time
with uncertainty. Its output says `reviewed_input_only`: declared reviewer and
rig identities are consistency fields, not authentication. Until an audited rig
and reviewer actually produce those records, the scorecard has **no measured
product result**. A VM protocol admission must additionally be supplied for VM
records. Its version-2 binding is computed from the manifest, result, recipe,
and proof content, then checked against the reviewed episode ID, scenario, fault,
sealed labels, numeric oracle rule, budget, rig/oracle/arm controllers, and each
arm's warm state, profile, before-reset proof, and trial record. Reusing a VM
proof or result across episodes in one scorecard is rejected. A bare admitted
boolean or a passing one-arm rehearsal can no longer qualify a three-arm reviewed
episode.
These are consistency links only: this scorer cannot authenticate the rig or
reviewer, establish that a VM ran, or prevent a fabricated record from being
supplied. Real qualification still needs an audited independent rig and
authenticated artifact custody.
The binding also carries each VM trial's status, so an admitted `ARM_ERROR`
cannot be relabeled a completed answer. A completed arm that exceeds the common
budget remains in the denominator as a terminal timeout and receives no recovery
credit; an independently reviewed answer reached within the budget still receives
diagnosis credit even if later repair or verification runs long. Reviewed
before/action/after timestamps must be ordered, and
reported wall time must cover the oracle observation window; the scorer still
cannot authenticate those timestamps without the independent rig.
An endorsed supported answer requires a timestamp after useful evidence and
before the post-arm oracle or any repair action, so scoring data cannot be
retroactively treated as investigator evidence. For milestone latency, missing
or post-budget answers
count at the common budget rather than disappearing from the distribution;
the score explicitly reports how many milestones were observed versus censored.
These budget-capped quantiles are descriptive, not an uncensored survival-time
estimate or proof that one arm is faster. An arm that quits early with no answer
therefore cannot look fast on the supported-answer metric.
The scorer also reports the paired, budget-capped supported-answer time difference
for the same episodes (comparator minus baseline), with a pair-resampled interval
only from ten or more episodes. Terminal wall-time is reported separately and
must be read beside accuracy and recovery; a fast failed arm is not a fast fix.

## Episode contract

Each frozen episode manifest needs a case ID and version, host/image and software
versions, target workload, plain-language symptom, sealed fault recipe and random
seed, independent clean/fault/repaired oracles, accepted causes and negative
controls, allowed probes/actions, and time/resource budgets. Store probe/model/
prompt/tokenizer/knowledge-pack hashes, consent and execution journal, evidence
IDs, failures, before/after measurements and reviewer labels in a versioned
redacted artifact. Keep the fault recipe and oracle outside the investigator's
evidence workspace until scoring; ordinary observable effects remain available.

The harness checks three clean and three injected measurements before admitting
an episode. The symptom must occur in all three injected measurements and none of
the clean measurements, or the injection is invalid. That is a harness gate, not
a diagnostic result. Restore the same clean snapshot between runs, randomize arm
order, and include cold/warm starts and cache state in the manifest.

| Initial lane | Controlled fault and independent oracle | Expected behavior |
| --- | --- | --- |
| Software VM | Bad Windows proxy against an owned HTTPS test endpoint; endpoint succeeds from clean checkpoint. | Distinguish proxy from DNS/TLS/remote outage; request an exact authorized correction and retest the endpoint. |
| Software VM | Bounded lab CPU load plus pinned PDF, viewer and page-turn task; compare repeat latency to clean. | Find the contention with timestamps; initially diagnosis-only unless an exact safe process action exists. |
| External VM/lab network | Lab DNS service unavailable for two clients. | Identify shared external failure and avoid a false local repair. |
| Healthy VM | The same work without an injected fault. | State that there is no supported local cause and perform no repair. |
| Physical Wi-Fi rig | Repeatable AP or adapter association/authentication fault, with radio and second-client oracle. | Distinguish radio, IP, DNS and external service stages. A virtual NIC is not a Wi-Fi qualification. |
| Physical RTX 4090 rig | Pinned game/version/scene/settings with a repeatable in-game 10-15 FPS cap; capture displayed frame times. | Identify the cap, use an exact game-specific procedure, and verify restored frame rate in the same scene. A virtual GPU is not a 4090 qualification. |

Examples for calibration: a PDF case can require page-turn latency at least 2x
clean and recovery to at most 1.2x clean across three runs. A game can require
clean scene performance at least 60 FPS, injected 10-15 FPS, and post-fix at
least 80% of its clean FPS. These are proposed manifest rules; confirm their
stability on the actual test hardware before freezing them. Use a qualified
hypervisor checkpoint or snapshot/reset mechanism for disposable software VMs
and [PresentMon's documented console capture](https://github.com/GameTechDev/PresentMon/blob/main/README-ConsoleApplication.md)
on the physical gaming rig.

The WinINet lane needs a registered owned external HTTPS endpoint tested through
the affected current-user WinINet configuration and a separate direct-bypass
control against that same endpoint. Separate isolated PRECONFIG/DIRECT transport
implementations exist, but the endpoint, qualified native behavior, proof of
actual proxy traversal, and real app route do not. The runner accepts only a
narrow measured WinINet network failure before an attempted write; worker errors,
timeouts, TLS errors and unexpected HTTP are unavailable or non-diagnostic, not
repair preconditions. A failed WinINet request alone cannot distinguish a bad
proxy from DNS, TLS, endpoint, or upstream failure; loopback is not a proxy-fault
oracle. Keep
endpoint ownership and resolution, injected setting readback, and control
results with the rig, not in a model's authority surface.
For the first admitted route, the lab origin must have a fixed DNS name that
resolves only to permitted global addresses, valid TLS, and a stable GET that
returns HTTP 204 with no body or redirect. Preserve origin logs and ownership
proof outside model control. The isolated rig must show that PRECONFIG actually
attempted the injected manual HTTPS proxy, not merely that Windows stored a
proxy value; DIRECT must reach the same origin during the failure. Qualify an
interactive guest user, clean checkpoint, exact setting readback, controlled
egress, after-action affected-route retry, collateral route checks, and full
restore/readback before scoring. Managed/ambiguous policy, a healthy control,
and origin/DNS/TLS outages where DIRECT also fails must all yield no repair.

## Arms and scoring

Compare (A) deterministic/keyword routing, (B) deep reasoner without learned
fast ranking, and (C) both brains. Give every arm the same catalog, reference
knowledge, evidence history, budgets, approval policy and maximum authority.
The benchmark harness measures the symptom; it does not tell a model the planted
cause. Separate scorecards for diagnosis-only and diagnosis-plus-repair prevent
an arm without an executor from appearing to have completed a fix.

Blinded reviewers score the cited root cause, competing explanations,
contradictions, and justified uncertainty. Automated oracles score symptom
reproduction, before/after recovery, recurrence, collateral damage, exact target
binding, consent and journal completion. Report all invalid injections separately
and all admitted failures in the denominator. Never omit timeouts or unsupported
claims. Report p50 and p95 wall time to first useful evidence, supported answer
and verified recovery, plus probe usefulness, model calls/tokens, CPU/RAM/GPU
impact and measured interference with the target workload.

Three restored repeats per recipe validate the harness. They cannot establish an
accuracy or field-safety percentage. Require diverse held-out faults, machines,
versions, healthy cases and multi-cause cases, with uncertainty intervals, before
marketing diagnostic or repair rates. A zero-error pilot remains a pilot: zero
bad actions in 100 independent negative cases still leaves an approximate 3%
upper 95% bound by the rule of three.

## Admission gates

1. Injection and oracle validity pass before investigator output is scored.
2. The candidate does not regress cited diagnostic quality or unknown-case
   handling against the same baseline.
3. An action is exact-scope, authorized and journaled; **any** unauthorized
   mutation or repair on a healthy/external control blocks promotion.
4. Every claimed fix passes the independent symptom oracle and collateral checks;
   a failed check is a failed repair.
5. Any speed or cost claim uses paired admitted episodes and includes inference,
   probe and verification time. Claim a two-brain gain only when it improves
   reviewed outcomes or paired latency at equal authority.

The first benchmark should expose current missing evidence honestly. SystemSense
does not yet measure active connectivity, PDF page latency or game frame times;
“insufficient evidence” can be the correct result until those probes exist.
Its passive connectivity preview and deterministic unresolved stage hypotheses
help choose the next bounded test, but do not count as a diagnosed Wi-Fi fault.
The first measured VM run must retain the admitted manifest, rig proofs, raw
redacted observations, model/tool traces, reviewer cause label, action journal,
and independent before/after readings. Report VM-protocol validity separately
from diagnosis and repair outcomes; do not combine them into a success rate.
