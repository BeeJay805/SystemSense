# Scoped WLAN Diagnostic Progress Implementation Plan

> For Codex: use the executing-plans workflow within this task. The user has
> already authorized autonomous implementation; do not pause for a session choice.

**Goal:** Let one genuinely unresolved WLAN association question drive a
bounded read-only follow-up, produce a durable verified branch result, and
inform both advisory brains and stopping without claiming an Internet cause.

**Architecture:** A versioned registered question defines two association-state
alternatives for one canonical interface and future observation window. The
existing one-shot diagnostic admission/claim/execution terminal is the host
authority. A separate append-only progress projection binds the terminal, is
revalidated on read, and is surfaced through versioned fast/deep request fields.
The coordinator runs this path only for a trusted transitional WLAN baseline;
ordinary completed-probe suppression stays unchanged.

**Tech stack:** Python 3.12, Pydantic, SQLite migrations, pytest, Pyright, Ruff.

**Outcome (2026-09-24):** Implemented as the bounded F09 WLAN slice. The
integrated suite passed 2,548 tests (20 explicit live/opt-in skips); Pyright,
Ruff lint/format, offline build and Git whitespace checks passed. Astra's
independent architecture/security review found no unresolved P1/P2 defect.
This is not a held-out diagnostic benchmark, a Wi-Fi cause detector, or an
authorization for repair or training. The five-second window is uncalibrated.

---

## Invariants to preserve

- A connected or disconnected baseline answers association at that time and
  does not trigger a routine second sample. Only a complete, current-case,
  single-interface `authenticating` or `associating` baseline is eligible in
  this first slice. Multiple or omitted interfaces and unsupported states are
  explicit non-admissions.
- The alternatives mean only “associated on the next scoped observation” and
  “disconnected on the next scoped observation.” They are not root causes.
  Unknown/transitional follow-up results match neither.
- One question consumes at most one registered read-only v3
  `network.connectivity` dispatch. No arbitrary parameters, shell, path, URL,
  or repair authority enters the model contracts.
- A single owner clock sample determines the target window; source-observed
  time, not case-open/collection/audit time, determines membership.
- The case budget, deadline, attempt cap, one-shot claim and case epoch are
  checked before collection. Claimed work never replays after crash.
- Projection of the exact terminal is idempotent. Lost source custody blocks
  trusted Boolean presentation and stopping, even if an older projection row
  remains on disk.
- Evidence novelty is collection liveness, not diagnostic progress. A resolved
  association predicate is not a supported causal explanation.

## Task 1: Register meaningful scoped alternatives

**Files:** `src/systemsense/evaluation/progress.py`,
`src/systemsense/storage/diagnostic_intents.py`,
`tests/unit/evaluation/test_progress.py`,
`tests/unit/storage/test_diagnostic_intents.py`.

1. Write red tests for an exact two-alternative question: opposite Boolean
   predictions, one canonical GUID, one window, one predicate, one branch, and
   explicit state labels. Reject duplicate/synthetic IDs, cause claims,
   mismatched prediction IDs, and non-future/expired windows.
2. Add `DiagnosticQuestionV1` and `AssociationAlternativeV1` as frozen,
   bounded contracts. The registered question supplies the meaning of its
   prediction IDs; do not infer meaning from free-form model prose.
3. Evolve admission record parsing without invalidating schema-1 admissions.
   New live admissions bind the question bytes, current baseline source,
   manifest, case epoch, objective and window. Old records remain readable but
   are not eligible for the new progress projection.
4. Run focused tests red then green. Preserve the real-runtime claim/link tests.

## Task 2: Project terminal truth without copying it into the checkpoint

**Files:** create `src/systemsense/storage/migrations/027_diagnostic_progress.sql`
and `src/systemsense/storage/diagnostic_progress.py`; modify migration tests;
add `tests/unit/storage/test_diagnostic_progress.py`.

1. Red-test one projection per admission, bound to admission and terminal
   hashes, with positive, negative, unknown, failed, interrupted and conflict
   outcomes. Duplicate projection is idempotent only for identical bytes.
2. Append a bounded, immutable branch-progress row in a caller transaction.
   Use `record_progress` with only a repository-verified terminal; raw evidence
   counts and model text cannot set `diagnostic_progress`.
3. Readback revalidates admission, terminal and cited source custody. A lost
   source yields an explicit gap/error, never a cached old Boolean.
4. Add restart and altered-hash regressions, update v27 rollback fixtures, and
   run focused tests, Pyright and Ruff.

## Task 3: Surface the exact result to both advisory roles

**Files:** `src/systemsense/decision/contracts.py`,
`src/systemsense/reasoning/contracts.py`, Laya request serializer,
local reasoning request serializer, and their unit tests.

1. Red-test a bounded `DiagnosticProgressContextV1` whose fields include the
   question/branch identity, scope, terminal status, exact citations,
   matched/disfavored alternative IDs, assumptions and branch dead-end count.
2. Add optional context to decision and reasoning request schema version 4;
   old request versions load with an empty field but cannot carry this context.
3. Verify the actual Laya worker state and deep-model prompt contain the
   context, including unknown/failed limitations, and never describe it as a
   causal or repair claim. Keep max item/token budgets bounded.
4. Run provider serialization and validation tests plus type/lint checks.

## Task 4: Mount one live read-only question

**Files:** `src/systemsense/application/investigator.py`, possibly one small
registered-question policy module, and integration tests.

1. Red-test a transitional, complete, single-WLAN baseline with a fake
   read-only v3 handler: exactly one second execution, claim, terminal and
   projection. Test connected and disconnected follow-ups separately.
2. Red-test no second collection for definitive baseline, multiple/omitted
   interfaces, stale/corrupt source, too little time or budget, exhausted
   attempts, cancellation and unsupported status.
3. After baseline, validate the source from storage, choose one bounded future
   window, register the state-alternative question and reserve the cost/pending
   attempt. Admit against the resulting case version and exact plan instance.
   Dispatch through `diagnostic_admissions_by_instance`, not a global
   `_eligible` exception.
4. Project the verified terminal after runtime completion. At owner recovery,
   reconcile consumed claims and project unprojected terminals without any
   redispatch. Charge claimed/unlinked work once, not zero or twice.
5. Revalidate progress before creating fast/deep requests and before a branch
   stop. Keep existing evidence fingerprint as liveness only. A Boolean
   association result may close this question but never set
   `SUPPORTED_EXPLANATION` on its own.
6. Run complete integration tests for crash windows, duplicate projection,
   stale epoch, outside-window source time and unrelated fresh evidence.

## Task 5: Qualification and delivery

**Files:** `docs/ACTIVE_GOAL.md`, `docs/ARCHITECTURE_AUDIT_STATUS.md`,
`docs/NEXT_STEPS.md`, this plan.

1. Run `uv run --frozen python -m pytest -q`, `uv run --frozen pyright`,
   `uv run --frozen ruff check .`, `uv run --frozen ruff format --check .`,
   `uv build --offline`, and `git diff --check`.
2. Run one safe live read-only case only if the host remains free of unrelated
   disruption. A healthy connected interface should decline the new repeat
   path; this does not validate a fault case. Do not stop GPU processes or
   invoke repair execution to make a benchmark pass.
3. Keep F09 Partial until the live coordinator, both model presentations and
   branch stop are tested. Keep training readiness BLOCKED and distinguish
   fixture behavior from measured Windows diagnostic performance.
4. Review the integrated diff and security boundaries, stage exact paths,
   commit each stable slice, push the authorized branch, and verify remote tip.

The next field gate remains a controlled, paired Windows fault with an
independent affected-task oracle. This plan does not authorize model training,
cloud inference, or Windows repair.
