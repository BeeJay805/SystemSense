# Current state

Code `e99e3a4` on `codex/private-alpha-20260928` is the current integrated
candidate. **Private-alpha qualification is still open.** The protected main
checkout remains `b0319e7`. The rebuilt unsigned installer represents product
`9d9b93f` plus formatting-only changes at `37ab246`, SHA-256
`1f7ea95239661b8d4ef8ca91dfed1737b2afb3d1b2098515205e37ee2987c896`.
It installed, passed six desktop flows including actual model diagnosis followed
by native-approved JSON copy, and uninstalled without changing the original
case database. All 30 desktop checks passed. The full Python run passed 4,103
tests with three failures in terminal process-presence scope ordering; the
correction passes all 29 affected checks. A combined repeat remains due. See
[benchmarks and acceptance](BENCHMARKS_AND_ACCEPTANCE.md)
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
  Exact executable questions also expose a source-bound pressure candidate
  without requiring the literal words CPU or processor. That eligibility does
  not force a measurement or prove that the model selected a useful check.
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

These three families are implemented and have controlled Windows evidence.
Twenty new case assignments were frozen and exercised at `fb84567`; failures
remain in the denominator. They do not establish general Windows diagnosis.
The frozen results and later regression fixes are reported separately.
The offline scorecard is integrated at `45db6d7` and keeps all planned, missing
and repeated attempts with artifact-bound reviews. `e99e3a4` adds consistent
logical-core and total-capacity CPU units to named-process evidence. In one
paired two-case Windows regression, Sol distinguished an idle target beside a
busy distractor from a target using about 0.98 cores. Warm times were 27.906 and
27.453 seconds; Basic was 8.031 and 8.437 seconds with the same useful facts.
Cold model setup was 29.031 seconds separately. All four attempts restored and
cleaned. This is a focused regression, not repeated final qualification or
model superiority.

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

The coordinator waits for durable terminal inventory/listener execution receipts,
not an in-flight reservation marked as completed for duplicate prevention. A
verified owner replay can cover use of an older listener observation only when
its exact request and PID/creation-time identity agree and both ownership
boundaries are verified. Narrow present-time process questions can finish after
an applied, nondegraded review uses the complete inventory; causal questions and
incomplete inventories cannot take that shortcut. Request-window claims can
anchor only to observed task windows, never an ordinary process inventory.

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

At fixed source `fb84567`, 15 first-use file cases ran with both Basic and actual
Laya/Sol twice: 60 attempts, all restored and cleaned. Independent review found
correct scoped results in all 30 model runs: ten parser explanations, ten healthy
controls, and ten specific access/limit gaps. Model warm median was 10.922 s,
p90 12.438 s; Basic was 0.610 s and 0.703 s. Both arms answered the same tasks;
this demonstrates no model advantage. Product causes were blinded; reviewers
knew the arm.

Five additional sealed case assignments across HTTP and owned processes ran
both arms twice at that same source. Eight of ten model runs linked a useful
selected check, execution and applied Sol use. Two stopped-process runs failed
to deliver their otherwise accurate raw answer. The older 13 HTTP and eight
process cases are consumed regression cohorts, never unseen holdouts. Four of
eight process model repeats failed similarly. Those failed attempts are retained.

`fba6db0` fixed invalid request-window anchors; `214ac01` fixed premature review
and owner-evidence closure. Its six real reruns all restored and cleaned, but
process questions still took two Sol calls and 52.422/56.844 s; four HTTP cases
took one Sol call and 26.516–39.687 s. `9d9b93f` addresses that remaining narrow
process-review waste, with 55 focused checks passing. Its first two actual-model
presence repeats were correct at 21.609/20.062 s and one Sol call each. Neither
needed a new Laya choice; this earns no adaptive-check credit. Both restored and
cleaned. Repeated final-source qualification remains open; old misses are retained.

The previous full Python run had 4,067 passes, 34 skips and eight fixture/catalog
failures. Their 134 affected checks passed after corrections. A desktop cleanup
race was also fixed. The current installed candidate passed six flows; 64 desktop
unit checks, type checking and lint passed. These do not replace full regressions. Model usefulness over the strong Basic
route, normal-user first-time model setup, and final package qualification are
still open. Optional model setup currently requires operator-installed Python,
pinned Laya and a signed-in Codex CLI; the desktop does not install them.
No training or separately billed APIs were used.
