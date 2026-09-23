# Project status

Status is based on the current working tree, not on the proposed handoff alone.

## Working checkpoint

- Branch `codex/windows-investigator` was developed from `812f00e72223`; the
  [build record](APPLICATION_BUILD.md) lists the verified local checkpoint.
- Earlier interface-only checkpoint: **447 tests passed** with live Windows
  collection enabled, including optional MCP integration. Ruff lint/format,
  full and core-only Pyright, and distribution build passed.
- A clean wheel environment without MCP or AnyIO ran passive capture and an
  investigation using its history: 102 passive observations, four coverage records,
  seven case observations, 19 explicit graph edges, SQLite integrity `ok`, and
  verified per-case audit chains (four passive / seven investigation executions).
  These are collection/integration checks, not diagnostic-quality measurements.
- Browser acceptance verified start, progressive results, citation navigation,
  recording start/stop, and readable evidence. API/integration tests additionally
  cover cancellation, resume, restart recovery, bounded export, and concurrent reads.
- The deterministic benchmark remains fixture-only. The resource benchmark is a
  component measurement, not evidence of diagnostic accuracy or end-to-end value.

The active two-brain pass supersedes that earlier checkpoint. It runs pinned CUDA
Laya and standard Qwen3.8 27B locally, with real tokenizer/context accounting and
memory admission. A live endpoint-owner case finished in 52.72 seconds with all
model responses admitted and a deterministic cited answer. A broader GPU case
ended with explicit uncertainty, not a fabricated diagnosis. Resource/context
failures discovered during those runs are retained as failures in the build record.
See [current verification and remaining gates](APPLICATION_BUILD.md).

Current read-only desktop retest: opt-in Laya/Qwen prewarming took 23.28 seconds
before the loopback server opened; both providers then participated without
degrading in one 45.06-second, two-round low-FPS report. The case correctly
remained unresolved because the game was not running and no frame time was
measured. An earlier warmup omitted the requested context and left inadequate
VRAM for deep reasoning; this was corrected to load the pinned Qwen artifact at
the configured 8K context. One successful co-residency run is not laptop fit,
diagnostic accuracy, or a supported root cause. A disposable Windows VM clone
booted but is blocked at a password-expired prompt; no independent fault or
repair trial ran. See [the active goal record](ACTIVE_GOAL.md).
The fast-brain input was then changed from hundreds of serialized raw-page
fragments to bounded, omission-counted page previews. In one follow-up
45-second case, Laya considered 54 of 54 previews in its first evidence pass,
while the prior similar run considered 20 of 413 raw fragments. The two runs
are not a controlled speed comparison and preview coverage is not full-fact
coverage. The case again ended with justified uncertainty, not a fix.

The core-only wheel was also installed outside the checkout: CLI/doctor, bundled
graph, SQLite integrity, passive fixture persistence and optional-adapter behavior
passed with MCP, PyTorch and tokenizers absent. Installing only the local-models
extra added tokenizers but not PyTorch or MCP. This establishes packaging isolation,
not model or collector quality.

## Implemented

- Python 3.12 package with 17 typed, bounded Windows probes, including process/service,
  device/driver and storage topology, network configuration/listeners, recent events,
  passive resource pressure and GPU telemetry.
- Provenance-rich evidence, inventory, coverage, redaction, retention, artifacts,
  SQLite persistence, and hash-linked audit records with a transactional per-case
  head that rejects stale/forked appends.
- Separate source `observed_at`, local `captured_at`, and execution/audit times in
  probe and storage contracts. Case creation is not an observation timestamp.
- One-shot worker boundaries for all 17 registered probes, deadline outcomes,
  output/record limits, circuit breakers, bounded Event Log capture, and case-scoped
  record bookmarks with high-water reset checks. Event Log queries use a fixed
  isolated worker and five-second hard deadline; the initial query is a bounded
  newest tail reordered ascending, with older history explicitly excluded.
  Custom trusted in-process handlers can delay return while their threads drain;
  the shipped Windows collection path does not use them.
- `TaskGraph` and `BoundedScheduler` with dependency checks, cancellation, stale
  state-version handling, deduplication, deadlines, and global plus per-resource
  limits, integrated with the current probe runtime and persisted attempt journal.
- A durable bounded investigator with persisted rounds, hypothesis history,
  completed-probe tracking, interruption recovery, no-progress detection, and
  explicit terminal outcomes.
- Immutable typed decision/reasoning contracts carrying bounded redacted evidence
  content and graph relationships. The default path combines the deterministic
  keyword baseline with reviewed deterministic reasoning.
- Optional pinned Laya attention and Ollama reasoning providers with fixed local
  transport, artifact/tokenizer verification, explicit GPU choice, bounded time/body sizes, and
  deterministic degraded fallback. No model is downloaded and no Ollama runtime is
  started. Explicitly enabled requests can load a configured installed model.
- Typed temporal evidence relationships with durable SQLite storage, provenance,
  validity, applicability, bounded traversal, explicit projection rules, passive
  history, and bounded current/opted-in historical retrieval.
- Separate shared reference knowledge: 79 nodes, 116 conditional mechanisms and
  26 primary sources; bounded runtime lookup over 3,116 Windows error codes on this host.
- Exact hypothesis fact retention, complete-row detail requests, deep-brain redirects,
  graph-guided focus and conservative completion of narrowly observed questions.
- A loopback application and readable browser UI supporting case start, progress,
  inspect, cancel, resume, bounded export, and explicit bounded passive recording.
  Shutdown cancels active case and recording workers.
- A measured episode recorder plus five real-coordinator synthetic journeys. The
  artifact records failures and unknown review labels and is not a quality result.
- Exact-scope action proposals, human-consent authorization, and a fake-tested
  WinINet proxy runner/native adapter. The runner journals separate measured
  affected, direct-control and after evidence; the isolated WinINet transports
  and narrow read-only policy gate remain unqualified. No real repair is exposed
  through the app: its trusted approval route, owned endpoint and Windows VM
  fault trial are missing.
- Focused and full automated tests for the inherited evidence core and the
  integrated scheduler/provider boundaries.

## In progress or incomplete

- Deterministic reasoning contains a small reviewed rule set, not a general Windows
  diagnostician. Its findings remain observations or unresolved possibilities.
- Passive history capture is bounded and isolated, but broad long-duration host
  qualification and recurrence evaluation remain pending.
- Windows coverage is broad but not complete. ETW/WPR capture, richer application
  failures, vendor-specific storage counters, CPU thermals and domain applicability
  need further measured qualification.
- MCP is a separate optional stdio adapter over the neutral application workspace.
  Installing the `mcp` extra is optional; it is not a core architecture or
  acceptance gate.
- Application repair/experiment execution and independent field outcome
  verification remain future work. The isolated WinINet runner has a fake-tested
  journal and rollback path, not an enabled or VM-qualified repair feature.
- Cloud inference, tenant/security policy, and remote advisory providers are not
  implemented. Remote Ollama aliases are rejected rather than used as fallback.
- No measured diagnostic-performance result exists. The reviewed-Windows
  scorecard is a calculation and admission contract, not a real run.

## Next capability gates

1. Run matched reviewed local episodes comparing keyword baseline, deterministic routing,
   retrieval-only, and provider-assisted investigation under the same evidence and
   resource budgets.
2. Qualify diagnostic action quality beyond the completed local runtime/protocol checks,
   without treating synthetic fixtures as real incident accuracy.
3. Add a small reviewed repair/experiment catalog only after explicit consent,
   target binding, preconditions, journal, and independent verification exist.
4. Expand Windows collection and long-running recurrence evidence under measured
   host-impact limits.

## Evaluation truth

The checked-in scenarios under `benchmarks/scenarios` are labelled
`engineering_fixture`. Their reports validate schemas, arithmetic, and quality
gates. They are not measured model performance, diagnostic accuracy, or AI savings.
Measured claims require recorded episodes, held-out cases, fixed provider/model
versions, evidence and coverage traces, failures in denominators, and host-impact
measurements.
