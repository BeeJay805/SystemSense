# Diagnostic and repair benchmark protocol

This protocol measures the whole user journey rather than a model's confidence
or a report's arithmetic. Existing JSON fixtures test schemas and the five
synthetic coordinator episodes test instrumentation. Neither injects an
independently verified Windows fault or measures a repaired symptom.

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
