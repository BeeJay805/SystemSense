# ADR (proposed): Case-scoped identities for investigative candidates

Status: **Proposed, not implemented** (F01 vNext). This document specifies the
next contract; it does not qualify Laya, create training labels, or authorize a
new Windows action.

## Context and decision

The current `DecisionRequest.available_probes` requires unique `probe_id`s.
`LayaDecisionProvider` sends `{probe_id, description}` to its ranker and maps
ranked IDs back to one `ProbeCapability` per probe. Its catalog binding produces
a `MeasurementNeed` only when a capability has exactly one target handle and
one observable. Thus two processes, or two incident windows, using the same
probe cannot appear as distinct choices in one decision. The typed
`MeasurementNeed`/`ProbeInvocation` path and selected-process binding are real
but do not remove this ranking limitation. An existing `ProbeInvocation` hash
distinguishes execution parameters; it is not a model-visible candidate ID.

**Decision:** Introduce a versioned, case-scoped *candidate* as one locally
admitted measurement choice, distinct from a probe capability. A candidate
references a registered read-only probe/version and one exact observable,
case-bound target handle, typed parameters, optional UTC measurement window,
and relevant dependency versions. The local registry, never either model,
mints an opaque `candidate_id` (for example `cand_v1_<uuid>`), records the
canonical `ProbeInvocation` digest, and is the only authority that resolves the
ID back to an invocation. Re-enumerating the same fresh canonical invocation
and dependency versions in a case epoch returns the same candidate ID;
different target, observable, window, parameters, or relevant dependency
version produces a different ID. Keep execution/attempt identity separate so
a retry or resample is not confused with a new capability.

The registry must bind each entry to `case_id`, case epoch/state version,
catalog manifest ID/version/digest, source target-evidence identity and
freshness, invocation digest, and expiry. It must revalidate target identity,
window admissibility, privilege, read-only safety, cost, current case state,
and budget immediately before dispatch. A candidate ID is a lookup key, not
an operating-system selector or permission token. Missing or stale resolution
returns a typed observability/eligibility gap; it never substitutes a broad
scan. Only relevant dependency changes invalidate a candidate; an unrelated
evidence-generation increment must not force needless reprobes.

The fast brain receives bounded, privacy-projected descriptions paired with
candidate IDs and ranks an exact permutation of the offered IDs per worker
batch. It may neither mint IDs nor return executable parameters. The deep
brain may request a bounded typed `MeasurementNeed`; deterministic code may
turn that need into a candidate after registry admission. Unknown, repeated,
stale, cross-case, omitted, or reordered-without-trace IDs fail closed to an
explicit fallback/gap. Batch scores remain ordinal within their exact
presentation, not globally comparable. The scheduler operates on admitted
invocations and durable task/result dependencies, not on probe-ID strings or
the evidence relationship graph.

## Contract and storage migration

1. Add a new `DecisionRequest`/`DecisionResponse` schema version with ordered
   `available_candidates` and candidate-ID proposals. Keep capability metadata
   separate from instances. Replace probe-ID-only completion/retry/satisfaction
   as the authority for this path with invocation-, freshness-, and
   result-specific state. The old schema remains readable as legacy data, not
   silently recast as vNext candidates.
2. Persist a versioned local candidate registry and frozen per-decision
   candidate manifest (ordered IDs plus canonical invocation and manifest
   digests) with case/epoch and target-evidence binding. A snapshot records
   the exact offered order, registry version, request digest, freeze/capture
   times, and any later admission/execution link by candidate ID. Preserve
   existing snapshot and `decision_execution_links` semantics for historical
   probe-ID decisions. Extend the separate same-epoch follow-up admission lane
   only with an explicit versioned candidate binding, never an inferred one.
3. Version the Laya serializer, worker result fields, presentation trace, and
   cache namespace together. The trace must prove which candidate IDs and
   descriptions were actually presented in each batch, their order, cache
   origins, truncation, and the pinned model/tokenizer/config identity. Cache
   keys include the exact candidate manifest and presentation hash. Historical
   probe-ID snapshots and labels remain historical; no automatic relabeling or
   training export is allowed without privacy review, exact input parity,
   and independent outcome/reviewer qualification.

The local registry adds storage and invalidation work, but avoids letting
advisory text become machine authority and lets one probe distinguish multiple
targets/windows. Probe-ID-only ranking remains a deterministic baseline while
the new contract is qualified; model-authored arbitrary invocations are
rejected because validation cannot make an unregistered operation safe.

## Red-green acceptance matrix

Each row starts as a failing contract or integration test, then passes only
through the new candidate path; fixture success is not diagnostic accuracy.

| Scenario | Required observable result |
| --- | --- |
| Same probe, two admitted targets | Two distinct offered IDs, both rankable; each resolves to its exact target, with no ID collision. |
| Same probe and target, two UTC windows | Distinct IDs and invocations; a fresh identical request shares one candidate/result only while its freshness and dependency bindings remain valid. |
| Stale/reused PID, expired window, changed target evidence | Admission or dispatch rejects the stale candidate; no silent retargeting or global fallback. |
| Unknown capability/observable or forged cross-case ID | Explicit gap/rejection, zero probe executions and zero new Windows authority. |
| Invalid model permutation, duplicate ID, missing ID, or old schema field | Fail-closed provider result with recorded fallback reason; no guessed candidate. |
| Budget, safety class, privilege, or typed-parameter violation | Registry/dispatcher rejects before execution; repair permission cannot be inherited. |
| Frozen snapshot, worker microbatches, and cache hit/miss | Readback reproduces offered order, candidate/invocation digests and actual worker-boundary IDs; wrong cache origin or tampered digest is rejected. |
| Retry after failure versus unchanged fresh request | Failure is an attempt, not a satisfied need; bounded retry is possible, while an unchanged valid observation coalesces. |
| Restart and old snapshot | New candidate mapping survives readback; old probe-ID snapshot remains readable but cannot masquerade as vNext or a training label. |

Non-goals: adding arbitrary command/path/URL/SQL/registry access; changing
Windows during investigation; claiming a causal dependency from scheduler
edges; fine-tuning Laya from weak teacher drafts; cloud inference; and
measured diagnostic-performance claims from these contract tests.

Related design: [local two-brain architecture](local-two-brain.md),
[next steps](../NEXT_STEPS.md), and the external F01 architecture audit.
