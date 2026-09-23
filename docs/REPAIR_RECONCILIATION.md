# Repair terminal reconciliation boundary (storage primitive only)

This is the next boundary for the **unmounted, fake-tested** current-user WinINet
proxy repair. Migration 009 and a repository method provide an immutable terminal
record and atomic exact-lock release. A separate read-only assessor can reload
the execution, proposal, approval, active head, token, and journal and compare
fresh setting and affected/DIRECT observations. It defaults to unavailable
without independently installed stop, evidence, and registered-check verifiers,
and always returns `qualified=false`; it neither calls the terminal repository
method nor unlocks a target. No production caller, trusted reconciliation
service, browser approval route, or qualified cross-process writer arbiter
exists. The terminal method accepts caller-supplied verifiers; tests use stubs,
so it must remain inaccessible to runtime and model callers. None of this
authorizes a host write or makes the repair production-ready.
Migration 008 durably reserves a canonical SID target and commits `PREPARED ->
APPLYING` before the native write. `ProxyRepairJournal` independently records the
procedure (`claimed`, `applying`, then a result or `uncertain`). There is no atomic
transaction spanning those databases and WinINet. Both records must be retained;
neither a journal `verified` row nor a `ProxyRecoveryDisposition.INTENDED_OBSERVED`
alone proves the user's symptom recovered.

## Contract and state machine

Reconciliation is a separate, read-only assessment followed by a narrowly
authorized **terminal record and lock release**, never a replay or rollback. A
schema version 009 appends one immutable terminal record keyed by
`execution_id` with exact claim/proposal/authorization/target bindings, journal
digest/state, executor-stop proof, observation IDs and content digests, outcome,
reviewer proof, and timestamps. The original execution and review
claims remain immutable and single-use. The terminal record is distinct from
the journal's result and from any later proposal.

| Execution claim at restart | Interpretation | Allowed next step |
| --- | --- | --- |
| `PREPARED` | One-shot native-write gate was not committed. The journal may be `claimed` or even `applying` because it is a separate store. | After proving the only authorized executor stopped, verify exact bindings and journal consistency. Classify `no_authorized_write_started` only if the qualified writer can *only* write after `recheck_execution` commits; otherwise remain uncertain. Never resume this claim. |
| `APPLYING` | Native write may have happened, even if the journal says `verified`, `rolled_back`, or is missing. | Mark `INTERRUPTED_UNCERTAIN` when the runner was interrupted, preserve both histories, then perform fresh setting and symptom measurements. No automatic retry or compensating write. |
| `INTERRUPTED_UNCERTAIN` | Outcome remains unknown until a separately reviewed terminal assessment. | Repeat read-only measurements if needed; append at most one terminal record only after all gates below pass. |

For a completed runner whose execution row remains `APPLYING`, the same terminal
path applies: inspect its journal result, but independently validate the current
setting and symptom before assigning an outcome. A `PREPARED` row with missing or
contradictory journal data stays reserved unless the no-write proof is complete.
`APPLYING` with an absent journal is not evidence that no write occurred.

## Required proof before any target unlock

1. **Stopped executor and exclusive custody.** The trusted supervisor records an
   executor instance ID, PID plus process creation identity, launched child
   identities, and the exact target. It confirms the original thread/process has
   completed or terminated and waited, with no surviving child capable of a
   native write. The reconciler then acquires the same target-scoped,
   cross-process exclusive arbiter that every qualified writer must hold from
   recheck through native write and notification. A PID lookup, elapsed lease,
   absent heartbeat, or abandoned mutex alone is insufficient. If custody or
   shared-arbiter coverage is unproved, do not release.
2. **Exact provenance.** Reload the immutable proposal, active head, review and
   execution claims, token/target/SID digests, and journal row from durable
   storage. Detect mismatches, missing data, stale case binding, or evidence-ID
   reuse. Require current interactive SID to equal the target SID. Do not let a
   model or browser request supply a locator, URL, measurement, or stop proof.
3. **Fresh native state.** Read the effective current-user WinINet snapshot after
   executor stop, including proxy enabled, server, flags and managed-policy
   status, with source observation and collection times. Compare with the exact
   before/intended snapshots; label original, intended, diverged, or unavailable.
   An intended setting is only **setting observed**. Policy ambiguity, identity
   drift, invalid flags, or a failed/stale read is unavailable, not success.
4. **Fresh affected and direct-control symptom tests.** Use the same registered,
   owned external HTTPS endpoint and expected SID, separately qualified
   PRECONFIG (affected) and DIRECT (control) transports. Record distinct
   evidence IDs, content digests, routes, source times, bounded durations,
   result codes, and redacted provenance after the stop and setting read. The
   affected request must pass its independent 204 contract and the direct
   control must pass; an unavailable control or unproven actual proxy route
   cannot establish causal recovery. Retain the pre-action affected failure and
   passing control for comparison. A passing lab endpoint is not necessarily
   recovery of a different user application; report the covered symptom scope.
5. **Interactive confirmation.** Show the exact proposal, attempted operation,
   observed setting, affected/direct results, uncertainty and consequences of
   unlocking. Obtain a fresh, authenticated, same-user approval for *terminal
   reconciliation*, bound to this execution and evidence digest. A session
   cookie, CSRF token, old repair consent, model output, or timeout is not this
   approval. An unavailable verifier leaves the target locked.

Classification must keep separate fields for `setting_observed` and
`symptom_outcome`: `recovered`, `not_recovered`, or `unavailable`. A claimed fix
requires a matching intended native setting **and** independent affected-path
recovery with a healthy direct control and valid routing; otherwise it is
`applied_unverified`, `original_observed`, `diverged`, or `uncertain` as supported.
External, hardware, or managed-policy causes may be reported without writing.

## Atomic release and failure policy

The repository uses one immediate SQLite transaction and requires a
caller-held target-exclusion verifier. A future trusted reconciliation service
must hold the same qualified cross-process arbiter as the writer. Inside the
transaction, compare-and-swap the exact unresolved execution, active head, case
version, target lock, journal digest, and terminal approval. Append the terminal record
and release **only that execution's exact target key** atomically; make the
head/case fences ignore only executions with a valid terminal record. Preserve
old claims, journal, evidence and audit history. A new repair needs a newly
constructed proposal, fresh diagnosis and fresh consent; the old claim/token
can never be replayed. If any compare fails, roll back all DB changes and keep
the lock. The future trusted service must record audit events for assessment,
approval, terminalization and denial without sensitive network response bodies.

Verifier callbacks execute while the immediate transaction holds the approval
database write lock. Future verifiers must not write that database through a
second connection from a callback; gather immutable proof first and use
callbacks for bounded read-only checks.

Unobserved setting, failed/direct-only endpoint, mismatched routes, missing
stop proof, inconsistent stores, external modification during assessment,
unknown policy, or storage error all fail closed. The reconciler never restores
settings automatically: a later rollback is a new independently authorized
action after fresh preconditions. This is distinct from the current runner's
immediate, proposal-authorized compensation before reconciliation begins.
Keep an unresolved target quarantined and surface a specific manual handoff;
do not silently turn `uncertain` into `verified` or unlock merely to clear a
stuck case. If an exceptional operator override is ever necessary, design and
audit it as a separate privileged workflow, not this normal path.

## Implementation and qualification gates

- Migration 009, the repository compare-and-swap, and the read-only assessment
  logic are implemented and fake-tested. Build a trusted reconciliation service
  with real stop, journal, native-state, independent affected/direct oracle,
  registered endpoint and route, SID, token custody, and authenticated approval
  verifiers plus a shared cross-process writer arbiter. Wire no browser or model
  route until those are qualified. Both the assessor and `inspect_interrupted`
  remain read-only and never release a lock.
- Fake-test every crash cut point: before journal claim, after claim, journal
  `applying` before execution recheck, after committed recheck before WinINet,
  during/after native write and notify, after each oracle, and before/after
  terminal transaction. Inject journal/database divergence, PID reuse, orphan
  worker, late writer, changed SID/policy/head, evidence reuse, stale clocks,
  target collision across cases, concurrent reconcilers, and DB failure.
  Assert no duplicate write, no premature unlock, and one terminal winner.
- In an authenticated, restorable Windows VM with an owned external endpoint,
  qualify process stop/exclusion, PRECONFIG and DIRECT route evidence, clean
  reset, fault injection, independent symptom oracle, native setting readback,
  cancellation and crash recovery. Measure both successful repair and false
  recovery controls. Until this and a real interactive approval path pass, the
  native host writer and target release remain disabled.
