# Architecture audit disposition

The supplied architecture audit reviewed revision `40e70a6`; this is a
current-source disposition, not an assertion that the audit itself was wrong.
`Resolved` means a focused regression and source path now enforce that finding's
specific invariant. `Partial` is not a release pass. Disabled repairs and cloud
networking stay outside the training-policy milestone, but their gates remain
explicit. See [the active delivery record](ACTIVE_GOAL.md) for measured checks.

| Finding | Status | Current evidence and remaining gate |
| --- | --- | --- |
| F01 precise target/window | Partial | [Candidate registry](../src/systemsense/storage/case_candidates.py) binds target, parameters and window for registered measurements; the [live frontier route](../src/systemsense/application/investigator.py) is still a PDF-process slice, not all domains. |
| F02 repeat after failure/change | Partial | [Eligibility](../src/systemsense/application/investigator.py) separates satisfied executions and one bounded transient retry; general changed-condition/window refresh still needs controlled episodes. |
| F03 cross-batch prerequisites | Resolved | [Eligibility](../src/systemsense/application/investigator.py) requires a current-manifest successful persisted execution with a source-timed observed fact in the incident window; [cross-batch tests](../tests/integration/test_investigator.py) cover fresh, stale, failed, and invalid chronology. |
| F04 serial outer phases | Partial | [Runtime](../src/systemsense/application/runtime.py) persists results then offers bounded child follow-ups before an unrelated slow task completes; outer investigation still has collection boundaries. |
| F05 known-fact fast route | Open | [Assessment](../src/systemsense/application/assessment.py) protects narrow claims, but ordinary direct answers can still pay for reasoning; no qualified verified-procedure route. |
| F06 arbitrary Laya fragments | Partial | [Semantic packets](../src/systemsense/decision/semantic_packets.py) retain fact/time/quality and are used by the frontier ranker; legacy decision path and held-out utility comparison remain. |
| F07 packet-limited discovery | Partial | [Paged evidence discovery](../src/systemsense/evidence/retrieval.py) and [live mixed frontier](../src/systemsense/application/investigator.py) deliver exact stored case evidence and source-bound relationship branches beyond a focused packet; useful-search breadth is not measured. |
| F08 supported causal conclusion | Open | [Assessment](../src/systemsense/application/assessment.py) intentionally does not turn model support into root-cause proof; qualified causal criteria and outcome oracles are missing. |
| F09 diagnostic progress | Open | [Typed progress rules](../src/systemsense/evaluation/progress.py) now recognize distinct branches and a v3 WLAN association observation. [Schema-26 intent custody](../src/systemsense/storage/diagnostic_intents.py) freezes one scoped question, one-shot dispatch, audited execution and three-valued terminal, but Investigator does not yet admit that question or project its verified branch result into fast/deep context and stop policy. Raw novelty remains insufficient. |
| F10 durable diagnostic requests | Partial | [Search frontier](../src/systemsense/storage/search_frontier.py) persists item states and result outbox; the [deep mailbox](../src/systemsense/application/deep_worker.py) binds one immutable deep question to terminal reconciliation and atomic checkpoint completion. General measurement-request lifecycle remains narrower than the product goal. |
| F11 goal refinement/recurrence | Open | [Investigation state](../src/systemsense/application/investigation_state.py) retains incident scope, but typed in-place clarification and recurrence remain incomplete. |
| F12 device/driver truncation | Resolved | [Worker snapshot](../src/systemsense/worker.py) fetches an extra row, marks first-64 truncation, and discloses uninspected targets; collector tests cover the 65th row. |
| F13 incident event cap/aliases | Partial | [Windows incident collector](../src/systemsense/platform/windows/deep_collectors.py) includes storahci/stornvme aliases and explicitly marks a capped recent tail partial; it still filters after that cap, so native profile filtering/paging remains. |
| F14 multi-association storage | Resolved | [Storage topology join](../src/systemsense/platform/windows/deep_collectors.py) preserves one-to-many volume/partition associations and marks unsupported multi-disk layouts. |
| F15 reliability identity | Partial | [Storage collector](../src/systemsense/platform/windows/deep_collectors.py) keeps ambiguous reliability unbound rather than silently attaching by number; provider-native mapping qualification remains. |
| F16 paged device claim | Resolved | [Device assessment](../src/systemsense/application/assessment.py) consumes exact raw, paged and source-wrapped rows; focused regression rejects an unbound wrapper and never proves broader causality. |
| F17 graph acquisition | Partial | [Machine graph](../src/systemsense/evidence/projection.py), [frontier discovery](../src/systemsense/application/frontier_discovery.py), and the [source-checked branch](../src/systemsense/application/frontier_branch.py) support exact bounded relationship retrieval in the live loop; general targeted measurements and causal validation remain. |
| F18 reference applicability | Open | [Knowledge models](../src/systemsense/knowledge/models.py) carry conditional text and sources, not fully executable version predicates or passage custody. |
| F19 claim-level hypothesis citations | Open | [Reasoning contract](../src/systemsense/reasoning/contracts.py) still chiefly references aggregate evidence IDs; distinct missing-measurement claims need atom-level binding. |
| F20 cloud-both/local-both | Partial | [Local profiles](../src/systemsense/inference/profile.py) and [cloud session fake](../src/systemsense/cloud/session.py) preserve local authority; production cloud deployment is disabled. |
| F21 cloud egress/identity | Partial | [Cloud session fake](../src/systemsense/cloud/session.py) requires exact local approval and bounded authenticated deltas; tenant service, OS-user authority, production transport and retention remain release gates. |
| F22 observer resource budget | Partial | [Managed GPU admission](../src/systemsense/inference/managed_laya.py) pins one local Laya worker/lease; whole-host collector/passive/deep accounting and workload-interference qualification remain. |
| F23 model deadlines | Partial | [Laya runtime](../src/systemsense/inference/laya_runtime.py) bounds request waits, but cold/queued end-to-end latency exceeds the target on the pinned host workload. |
| F24 descendant containment | Partial | [Collector executor](../src/systemsense/orchestration/executor.py) now assigns its suspended worker to a private Windows Job Object and fails closed on setup/assignment/cleanup errors; [Windows regressions](../tests/integration/test_worker_timeout.py) cover owned children, unrelated sentinels, and normal/timeout paths. The guarantee covers ordinary `CreateProcess` descendants, not `Win32_Process.Create` or other brokered launches. |
| F25 temporary diagnostic experiment | Open | [Action contracts](../src/systemsense/actions/contracts.py) do not yet expose a consented, journaled temporary change as distinct from a repair. |
| F26 repair execution safety | Gated | Exact consent records exist in [action contracts](../src/systemsense/actions/contracts.py); native repair execution is deliberately disabled pending preconditions, journal, rollback and independent verification. |
| F27 diagnostic superiority | Open | [Benchmark protocol](BENCHMARK_PROTOCOL.md) specifies equal-access comparators, but synthetic fixtures and one owned-host rehearsal are not held-out diagnostic evidence. |
| F28 commit-bound verification | Partial | Local commands, revision and artifact hashes are recorded in [the active record](ACTIVE_GOAL.md); CI/portable release bundle and a controlled benchmark set remain. |
| F29 measurement depth | Open | [Windows collectors](../src/systemsense/platform/windows/deep_collectors.py) are broad, but staged Wi-Fi, PDF and gaming workload tests lack qualified domain-specific alternatives. |
| F30 verified learned selection | Open | [Training plan](LAYA_TRAINING_PLAN.md) and [pilot inventory](PILOT_CORPUS.md) preserve unknown utility and split boundaries; no Windows-trained fast policy or admitted real utility labels exist. |

The first-policy pre-training handoff remains **BLOCKED** until exact
corpus-wide worker-input parity, independently supported utility labels,
controlled Windows episodes, and live event-to-admission behavior pass. No
weight update or autonomous repair is authorized by this checklist.
