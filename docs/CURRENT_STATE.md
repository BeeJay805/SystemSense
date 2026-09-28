# Current state

This page describes committed behavior through `cbd3937` and reviewed development evidence
through candidate v7 (`f4dc325`). [North star](NORTH_STAR.md) states the goal;
[architecture](ARCHITECTURE.md) explains authority boundaries;
[benchmarks and acceptance](BENCHMARKS_AND_ACCEPTANCE.md) defines the gates. Earlier trials, failures, and
release checks remain in [build history](BUILD_HISTORY.md).

## Available in the product

- Dyad is a Python 3.12+ local-first, read-only Windows investigator with a loopback case
  application, an optional MCP adapter, and an unsigned Electron development client. The default
  profile is deterministic. Seventeen registered collectors have fixed typed inputs; ordinary
  probes run in bounded isolated workers. Evidence, coverage, source and capture times, case
  state, audit, retention, redaction, and graph references persist in SQLite. Trusted custom
  in-process handlers are not a hard-kill boundary.
- Deterministic code owns probe admission, machine access, scheduling, source freshness,
  permission and resource checks. The mixed frontier offers bounded retrieval, source-backed
  graph/reference work, and currently registered read-only measurements, including qualified
  process pressure, host pressure, storage, GPU, and network configuration candidates. Selection
  does not bypass exact registered invocation and execution checks. Missing process inventory
  removes that candidate with a recorded gap; it does not authorize a substitute target.
- Replaceable fast and deep providers are advisory. An opt-in development route runs pinned
  local Laya for mixed choices and GPT-6 Sol through the logged-in Codex subscription for deep
  reasoning; local Ollama and deterministic routes also exist. The subscription route checks the
  selected provider/model and disables environments and MCP tools. No separately billed API
  fallback is configured. The desktop default remains local/deterministic.
- Applied nondegraded asynchronous deep proposals can carry an immutable exact request,
  proposal, invocation, manifest and execution link. A coincident probe run, legacy database, or
  synchronous proposal has no retroactive deep-origin credit. After a newly observed successful
  result, the coordinator can request one further bounded deep review before closure. A
  summary's source and reviewed evidence generation are persisted; readback reports whether that
  generation is current, stale, or unknown. Matching generations do not prove complete fitted
  coverage or semantic correctness.
- Reasoning preserves competing advisory rivals, prior contradictions and prediction boundaries.
  Registered finite prediction outputs are validated against the exact probe version and later
  observations. Request v7 supports explicit same-ID retirement of old support citations with
  frozen prior digest, new visible evidence and immutable step lineage. Response v5 can account
  for up to two typed noncausal reviews. Response v6 can attach bounded per-rival noncausal
  references and revise a prior statement only with a new reviewed, fitted current-case source;
  those references remain separate from causal support. Verified unavailable observations may
  extend missing evidence without authorizing unsupported prose. Older serialized requests and
  records remain readable. Actual v7 model output exercised the per-rival reference path, including
  correction of a stale GPU rival and separation of another application's event. References may
  also extend context without changing prose. At `cbd3937`, statement prefixing is idempotent and
  new per-rival references exclude source-verified unavailable observations; these later fixes
  have focused regression coverage but await an actual-model trial.
- Repair and WinINet consent primitives exist behind a separate exact-scope boundary, but the
  application does not offer general automatic repair. A reported affected task is unverified
  until independently bound to an observed outcome. No model statement, graph edge, or fixture
  label establishes a Windows cause.

## Development evidence and limits

The frozen overnight suite contains 12 synthetic cases across network/browser,
application/storage, and GPU/resource families, split six development and six heldout cases. The
hidden evaluator oracle is separate from model-visible inputs. The split is by case, not by
family. Attempts and score revisions are retained; mechanical origin/execution/response custody
and independent semantic review are different gates. The heldout arm has not been evaluated at
this checkpoint.

In one reviewed v6 actual-model run per development case (`662a498`), all six had a useful
registered model choice, exact execution, a later accepted deep response, and meaningful use of
the selected observation in accepted reasoning. Four had verified useful fast-origin loops and
three had verified useful deep-origin loops, with one case overlapping. The historical baseline
has one verified fast-origin loop in six, but its older database lacks deep-origin receipts, so
an aggregate baseline-to-v6 uplift is not established. All six final causal assessments remained
null. The review found no unsupported definitive cause in the saved raw responses or finals,
while identifying stale or incomplete rival rows in the v6 final state.

Candidate v7 corrected the measured GPU rival and other-application event context, with ten
persisted noncausal revision links independently checked against frozen requests and checkpoint
hashes. It completed useful choice/execution/reasoning loops in five of six cases. Two final
reviews missed their deadlines, and only four summaries reflected the current evidence
generation. All 18 saved raw responses and six finals were reviewed: no unsupported definitive
cause was found, and all final causal assessments remained null. Its 20 Sol call attempts
included one validation retry and two deadline failures. This is a mixed development result,
not an overall improvement over v6. Prefix-only text changes receive no substantive reasoning
credit, and all unsuccessful attempts remain part of the record.

The v6 run recorded 18 GPT-6 Sol calls and raw returns, no validation retry prompts or captured
call failures, and six case times of about 30–75 seconds. The first cold Laya startup (15.891
seconds) was recorded separately. These Sol counts exclude Laya worker calls, and sampled
process resources are not peak host or GPU utilization. From `c8a871c`, a passive per-case meter
records Laya worker protocol requests, completions and failures; it does not count neural forward
passes and has not yet been exercised in an overnight model trial. Compared with v5's single run, the
retry/failure reduction is observed development evidence, not a latency or reliability
guarantee. The full Laya worker input was not captured, so automated leakage assurance is
partial. [Benchmark evidence](BENCHMARKS_AND_ACCEPTANCE.md) and the private reviewed attempt
records carry the exact scope.

At `d9849b7`, the non-MCP Python audit passed 3,631 tests, with 32 skips, one MCP deselection
and seven warning-path notices. After the per-rival reference change was integrated as
`f4dc325`, 154 focused reasoning, storage and integration tests passed. At `c8a871c`, whole
Pyright and Ruff checks passed; at `cbd3937`, 159 combined focused tests passed. A whole-suite,
build and desktop gate on the latest integrated code has not yet been reported.

No real Windows fault was injected or independently diagnosed, no matched heldout accuracy or
speed comparison is complete, and no training-admissible corpus, trained search policy, signed
or clean-machine-qualified installer, production cloud route, or verified repair is claimed. The
earlier consented VM qualification remains blocked by guest access and an independent
affected-task outcome protocol; [build history](BUILD_HISTORY.md) retains the specific failed and
rejected attempts.
