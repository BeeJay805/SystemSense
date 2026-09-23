# Diagnostic and repair benchmark protocol

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

`benchmarks/windows_scorecard.py` accepts a separate type of externally reviewed
real-Windows episode. It refuses the rehearsal and protocol-only objects as
standalone performance evidence, checks matched A/B/C access, profiles, warm
state and distinct resets, retains failures/timeouts in the denominator, and
reports cause accuracy, false fixes, verified recovery and terminal wall-time
with uncertainty. Its output says `reviewed_input_only`: declared reviewer and
rig identities are consistency fields, not authentication. Until an audited rig
and reviewer actually produce those records, the scorecard has **no measured
product result**. A VM protocol admission must additionally be supplied for VM
records, but this scorer alone cannot prove it belongs to a real run.

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
stability on the actual test hardware before freezing them. Use
[Hyper-V checkpoints](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/checkpoints)
for disposable software VMs and [PresentMon's documented console capture](https://github.com/GameTechDev/PresentMon/blob/main/README-ConsoleApplication.md)
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
