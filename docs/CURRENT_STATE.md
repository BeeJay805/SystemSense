# Current state

Code `5e5d933` on `codex/private-alpha-20260928` is the current integrated
candidate. **Private-alpha qualification is still open.** The protected main
checkout remains `b0319e7`. The locally rebuilt unsigned installer now represents `5e5d933`; its SHA-256 is
`44466205aa3d471ed393970f83f6ac48539ce18cb4b40d04ca73b3750de1e43e`.
Installation and final cohort qualification remain open. See [benchmarks and acceptance](BENCHMARKS_AND_ACCEPTANCE.md)
for measured revisions and [build history](BUILD_HISTORY.md) for prior failures.
[NORTH_STAR.md](NORTH_STAR.md), [architecture](ARCHITECTURE.md), and
[training plan](TRAINING_PLAN.md) remain the product contracts.

## Supported candidate scope

- **Exact local health request.** One literal
  `http://127.0.0.1:<49152-65535>/health/<32-lowercase-hex-nonce>` in the problem
  description authorizes only that fixed GET. Dyad records the actual outcome,
  target, nonce, source and request window. Registered choices include a later
  exact-port listener check, a standalone recurrence check, and an identity-bound
  owner CPU sample concurrent with another exact GET. The owner check verifies
  PID and creation time at both listener boundaries. This proves those two
  boundaries, not continuous ownership or a request-handler cause. Later success
  cannot contradict a failure from another request window. No arbitrary URL,
  DNS, proxy or redirect access is granted.
- **Named Windows process questions.** A complete process inventory can answer
  whether one literal `.exe` is running at sample time. A CPU request can bind one
  unique process identity and collect its bounded CPU sample. Ambiguous, missing,
  changed or incompletely observed targets remain specific gaps. These checks do
  not diagnose an earlier exit or the cause of perceived application slowness.
- **One native-selected local JSON file.** The desktop's file picker captures at
  most 256 KiB through a cancellable hidden Windows helper. The affected task is
  explicitly Dyad's strict UTF-8 JSON parser. Parameter-free encoding and parser
  checks use the same immutable capture. Native identity, hashes, times, fixed
  errors and syntax locations are saved; file paths and content are not sent to
  models or saved in case evidence. Network paths, reparse traversal and path
  aliases are rejected. Nesting/integer limits produce a parser-limit gap,
  not a claim of invalid JSON. Application schema acceptance and current disk
  contents remain unverified. Saved cases survive restart, but a new file
  selection is required to regain capture authority.

These three families are implemented and have controlled development evidence.
They are not a claim of general Windows diagnosis or qualified unseen reliability.
The native file picker is a necessary exact-file selection in addition to the
initial description; the user never pastes a path into a model command.

## Investigation and desktop behavior

The default is explicitly **Basic checks**. An optional Laya + Sol mode uses
pinned local Laya and GPT-6 Sol through the signed-in Codex subscription, with
verified runtime identity and no paid API fallback. Models have no shell, tools,
MCP inheritance or machine authority. Readiness blocks unavailable model starts
while saved cases remain readable. Settings, progress, cancellation, History,
evidence export and parent-loss recovery are implemented. Model abstention and
deterministic fallback receipts remain visible and earn no model-choice credit.

Basic now has the same registered recurrence, listener and verified-owner checks
and original case budgets. Its choices have deterministic source-bound receipts;
no model is credited for them. Previous comparisons against listener-only Basic
are historical and do not establish current intelligent value.

For captured JSON, a verified full parser result also settles the encoding check.
The coordinator can await its pending Sol review without repeating measurements
of unchanged bytes. Closing a model case still requires an accepted Sol response
that considered and used the decisive evidence. This linkage does not prove that
Sol's explanation is correct; independent review is a separate evaluation gate.

SQLite keeps observations, provenance, source/capture/case/audit times, coverage,
case state and bounded advisory records. Unknown, denied, stale, truncated and
failed are data. Named Windows Jobs and exact process identity support recovery
of owned read-only workers after parent loss. Legacy claims without exit proof
remain occupied. Legacy saved hypotheses without claim-window custody are not
retroactively validated; their prose remains advisory.

## Approved JSON copy

The desktop offers one separate native-approved executor: remove exactly the
three-byte UTF-8 BOM from the captured version **only when its remainder parses**,
and create a new user-chosen local file. Native confirmation names the capture,
hash, byte change and destination. Approval expires five minutes after capture.
Existing files cannot be replaced; the original is never reopened or modified.
This is not an automatic repair engine or application-recovery claim.

Schema 39 stores a durable single-use claim before writing. A bounded helper
creates through verified native parent handles, then independently reopens,
checks identity/hash/size, and parses the output. Only that result can be called
verified. Lost replies do not replay execution. Interrupted claims become
uncertain at recovery; no paths, bytes or approval tokens survive restart.
Saved copy receipts are separate from read-only diagnostic probe evidence and
appear in case details and export. General Windows repairs remain unavailable.

## Verification and open gates

The first native desktop file/copy run failed because a TypeScript test-stub
error prevented rebuilding the renderer; all three traces are preserved. After
fixing the stub and building the renderer, the three native flows passed:
healthy parser, syntax rejection, and copy approval/cancellation/overwrite refusal.
Focused native copy/capture/migration checks passed 59 tests; file investigation
checks passed 28. These are scoped mechanics, not alpha acceptance.

At `5e5d933`, four actual Laya–Sol development file cases completed with one
selected check and one applied Sol review each: syntax, healthy, invalid UTF-8
and BOM. Warm times were 9.500–11.454 seconds. Earlier failures and the redundant
probe attempt remain in the evaluator archive. New frozen file cases remain
reserved until final evaluation. The full Python run returned 4,067 passes, 34 skips and eight failures. Seven
legacy-migration fixture mismatches and one historical action-catalog mismatch
were corrected without changing frozen hashes or product checks; all 134 affected
checks passed. Python lint/format/typecheck and desktop lint/format/typecheck pass.
The full desktop run returned 25 passes, four skips and a post-exit test-cleanup
failure. After fixing the cleanup race, four focused packaged tests passed,
including actual Laya-Sol healthy/503 cases, History, cancellation, native copy,
startup and process inventory. Paired strong-Basic qualification, repeated unseen
usefulness, private install/uninstall and latency/resource gates remain open.
Only 15 new file cases remain unseen; the old 13 HTTP/eight process cohorts are
consumed and subsequent trials are regression repeats. No training or paid services were used.
