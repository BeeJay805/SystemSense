# Candidate-directed read-only investigation

Status: first production vertical slice, 2026-09-24. This is not a general
target/window planner or measured diagnostic-performance result.

## Why a candidate is not a probe ID

Two instances of `application.target_pressure` can refer to different process
identities from the same inventory snapshot. Ranking the probe ID alone cannot
express which process to inspect. A candidate is a versioned, opaque ID for an
exact locally registered tuple: probe manifest, observable, typed parameters,
inventory target, source evidence, dependencies, budget cost, resource class,
and expiry. The model sees a redacted description and digests, not a PID, SQL,
path, command, or permission. A candidate ID is a lookup key, never authority.

The initial catalog is intentionally narrow. After a persisted
`application.snapshot` observation in a slow-PDF case, the application can
issue at most the bounded inventory processes as distinct candidates for the
read-only `application.target_pressure` probe. It revalidates the exact
evidence/PID/creation identity before admission, in the queued worker, and
again in the collector. A later snapshot, stale source, changed manifest,
expired candidate, or changed case epoch invalidates the choice. No arbitrary
target/window or model-supplied parameter is accepted.

## Custody and dispatch

1. The case-scoped registry stores immutable candidate rows (schema 018) with
   source and invocation digests. Source observation, capture, execution, issue,
   and expiry times remain separate.
2. The fast-brain candidate request freezes the exact ordered choices and
   context before inference. The decision snapshot (schema 019) stores the
   validated response and registry-row custody. It does not prove the source
   was genuine, the decision was useful, or that the worker used the target.
3. The application resolves the chosen candidate against fresh evidence and
   current registration. A one-shot dispatch admission (schema 020) reserves
   its cost and attempt slot before scheduling. Candidate cost lives in this
   ledger, not in `InvestigationState.spent_cost_ms`; remaining-budget queries
   include both. An admission is never a repair permit.
4. The queued worker opens its own case-store connection and claims that exact
   admission, case epoch, task ID, and invocation digest once before any host
   probe. It rechecks the inventory binding and registered probe policy. The
   collector independently checks live PID creation identity while sampling.
5. For an attributable worker result, execution, evidence or coverage, audit,
   and the admission/snapshot link are committed together. The link checks
   that the claim precedes probe start, the frozen decision precedes start,
   and the invocation matches. A probe may finish after the decision deadline
   if it started before it.

An admission left unclaimed or claimed without an attributable result remains
uncertain and consumes its reserved budget/slot. It cannot be replayed on
resume. A scheduler-generated timeout/cancellation whose start time predates
the worker claim is not recorded as a probe execution: doing so would invent
collector chronology and double-count the attempt. The ledger and checkpoint
report the uncertainty instead. Successful collection and partial/unavailable
collector observations do not by themselves establish a cause.

## Model and training boundary

`CandidateDecisionProvider` is replaceable. Laya's adapter can rank candidate
IDs through its bounded typed-decision worker; deterministic code still owns
candidate issuance, dispatch, budget, scheduling, provenance, and all Windows
access. A decision gap preserves the prior manual PDF target-selection path.
The coordinator caps an advisory call at its frozen deadline and polls for case
cancellation. At most two provider worker threads can remain outstanding;
late responses are discarded and a stranded worker holds its slot until exit.
This protects investigation responsiveness but cannot kill a provider stuck in
native code. Any future provider needs a separately qualified killable process
boundary before being treated as a reliable production adapter.
The local Qwen deep reasoner continues to compare hypotheses and can redirect
broader investigation; it does not authorize dispatch.

The version-3 candidate review contract preserves target/window identity,
pre-result question, observed utility, and unrun-as-unknown. It is explicitly
non-trainable. Local Qwen teacher drafts may suggest rankings for independently
reviewed, consented cases, but are weak labels only. Exact deployed Laya input
parity, authentic reviewer and outcome custody, held-out split controls, and
laptop latency/interference gates remain prerequisites to fitting or promoting
a Windows-specific Laya student. See [training plan](../LAYA_TRAINING_PLAN.md).

## What this does not prove yet

The fixture tests prove ID separation, fail-closed admission, one-shot claim,
budgeting, chronology, and transaction links. An opt-in production isolated
probe smoke observed the running pytest process and rejected a false creation
identity; it is not a diagnosed slow-PDF case. No measured root-cause accuracy,
faster time-to-answer, page-turn recovery, ordinary-laptop Laya qualification,
or autonomous repair follows from this slice. The next product gate is an
independently instrumented, resettable affected-task episode with sealed fault
and recovery oracles.
