# SystemSense

SystemSense is evolving into a local-first, graph-guided Windows investigator. It
collects bounded read-only evidence, preserves provenance and coverage gaps, and
gives decision and reasoning providers a constrained case view. The system does
not treat a model response as authority to change Windows.

The product goal is a fast, simple path from “my Wi-Fi is broken” or “my game is
running at 12 FPS” to a measured explanation and, where safe software repair is
possible, a verified recovery. The present build investigates and cites evidence;
it cannot yet apply a repair or claim general diagnostic accuracy. See the
[product roadmap](docs/PRODUCT_ROADMAP.md) and [outcome benchmark
protocol](docs/BENCHMARK_PROTOCOL.md) for the steps toward that goal.
For the prioritized delivery and model/deployment decisions, see
[next steps](docs/NEXT_STEPS.md).

The current repository contains an active local two-brain application: a durable,
bounded investigation loop, a loopback case interface, Windows probe packs,
redaction, SQLite evidence and relationship persistence, passive-history
capture, bounded retrieval, and replaceable decision/reasoning providers. The
default install is deterministic and performs no model inference. An explicitly
enabled profile can run pinned Laya attention with a pinned local Qwen3.8 27B
reasoner; both providers must pass local availability and resource admission.

## Product boundary

The intended invariant is:

> The evidence graph supplies relationships, the fast provider directs attention,
> the reasoning provider investigates explanations, and measured evidence plus
> explicit authority determine what happens next.

Collection is read-only toward Windows, applications, devices, services, drivers,
registries, repositories, and networks. Missing, denied, stale, unsupported,
failed, and truncated evidence remain visible. Repairs and disruptive diagnostic
experiments are future, separately permission-controlled capabilities. No model,
local or remote, can mint permission or execute arbitrary commands.

The handoff describes the North Star and proposed replaceable choices. It does not
establish a production diagnosis model, a cloud service, a repair executor, or a
measured diagnostic-performance claim.

## Implemented foundation

- Versioned evidence, inventory, coverage, provenance, redaction, retention, and
  hash-linked audit records.
- UTC-only source observation and local capture timestamps. A case opening time is
  not used as an observation time.
- Typed Windows probes with fixed manifests, bounded output, deadlines, circuit
  breakers, and one-shot worker isolation for all 17 registered collectors and
  passive Event Log queries. Custom trusted in-process handlers must cooperate
  with cancellation; they are not a hard-kill boundary.
- Broad read-only collection across core resources, processes/services, devices,
  network configuration and listener ownership, storage, servicing, local AI,
  power, security and recent events. Follow-up probes sample resource pressure
  and GPU clocks/power/thermal telemetry. Unsupported counters and omitted rows
  remain explicit, not assumed healthy.
- A targeted connectivity probe samples WLAN association, bounded adapter
  addressing/routes, WinINet proxy state, and recent fixed-channel WLAN failures
  without contacting a network endpoint. It exposes a bounded stage/timestamp
  preview to inference while retaining the full redacted snapshot for scoped
  detail retrieval. Configuration is not a reachability test.
- `TaskGraph` and `BoundedScheduler` for dependency-aware, cancellation-aware,
  resource-bounded read-only work, integrated with probe execution and persisted
  attempt outcomes. Distinct target/window instances of one probe have separate
  task and audit identities; target handles must resolve to registered parameters.
- `FastDecisionProvider` and `ReasoningProvider` contracts with state-version,
  case, correlation, deadline, evidence, and typed probe-capability binding.
- `ProviderBackedPlanner` with `KeywordBaselineDecisionProvider` as the
  deterministic baseline/fallback. It is not a learned Windows diagnostician.
- A durable coordinator with hypothesis history, attempt-aware probe tracking,
  a conservative freshness/stagnation signal, interruption recovery, and
  explicit terminal outcomes. A typed diagnostic-progress ledger exists but is
  not yet wired to independently verified test predicates.
- In the opt-in Laya profile, persisted observations can trigger bounded
  asynchronous follow-up decisions while unrelated probes continue. A child
  result can trigger another decision in the same case. The registered catalog,
  frozen request, exact parent/presented-evidence digests, case budget, and
  admission/outcome links remain deterministic; uncertain or unverifiable work
  is not replayed. The opt-in mixed frontier is now mounted for ranking and
  retrieving already-stored case evidence: the selected ID is rechecked against
  its persisted record and case generation before delivery. A separate,
  target-only slow-PDF slice ranks registered process measurements and sends
  one through frozen snapshot, admission, and worker claim. That slice rejects
  unverified semantic evidence packets until exact source projection is bound;
  it is not yet a general evidence-rich mixed policy. The bounded store-free deep worker and
  cross-process inference lease are likewise integration seams, not claims of
  simultaneous reasoning or automatic GPU admission. This is not a measured
  diagnostic-speed improvement.
- A first candidate-ID path lets the fast brain distinguish multiple processes
  of the same registered pressure probe after a slow-PDF inventory snapshot.
  Immutable source/target bindings, a frozen decision, a one-shot budget
  reservation and worker claim, and a transactionally linked execution keep
  advisory ranking separate from Windows authority. Unlinked intents are
  uncertain and non-replayable; see [candidate routing](docs/architecture/candidate-routing.md).
- Repeated fast-brain attention, two-hop evidence expansion, deep-brain redirects,
  bounded case-scoped catalog paging and exact detail searches, and durable
  facts behind hypothesis citations. Catalog summaries guide discovery but
  cannot support a diagnosis until the exact record is retrieved. Catalog page
  cursors reset on a transactional per-case evidence generation change, including
  retention deletes.
  When Laya is explicitly enabled, a separate bounded metadata-attention lane
  can select omitted case evidence IDs across catalog pages. The coordinator
  rechecks the case generation and retrieves persisted observations before
  forwarding them to either brain; malformed, stale, or undeliverable rankings
  degrade without granting facts or machine authority. This is integrated
  routing, not measured Windows diagnostic performance.
  When the fast provider offers no probe, the coordinator may follow an eligible
  distinguishing probe from a relevant reference relation; it does not scan the
  cheapest unrelated collector merely to spend the remaining budget.
- Deterministic reviewed reasoning rules that cite observations while retaining
  an unknown cause. Fresh passive connectivity facts can yield unresolved WLAN,
  addressing, route, DNS and proxy-stage hypotheses; they cannot establish
  gateway, DNS, endpoint or affected-application reachability. A collector failure
  remains an observability gap.
- Typed, provenance-rich temporal evidence relationships with SQLite persistence,
  bounded traversal, explicit projection rules, and opt-in historical retrieval.
- A separate sourced, versioned reference graph of conditional relationships.
  Installed Windows error definitions are retrieved on explicit code/symbol requests;
  neither documentation nor graph connectivity establishes a machine fault.
- A loopback-only local web application for start, inspect, cancel, resume, and
  bounded JSON export. The browser receives no shell or arbitrary query surface.
- Optional local dual-brain inference: pinned Laya ranks evidence and registered
  probes, while a separately pinned loopback Ollama model reasons over focused
  evidence. It is disabled by default, has deterministic fallbacks, and never
  pulls a model, starts Ollama, or selects a cloud alias at runtime.
- Exact-scope action proposal and consent contracts, plus a fail-closed,
  fake-tested WinINet proxy repair runner and native adapter. The native adapter
  checks active interactive-session, token identity and known policy restrictions.
  A fixed-descriptor lab oracle and separate isolated WinINet PRECONFIG/DIRECT
  transports are implemented. The runner requires failed affected-path, passing
  direct-control, and passing post-change affected-path evidence, bound to its
  case and authorization in a durable journal. The owned external HTTPS endpoint,
  full policy/scope qualification, mounted/VM-qualified interactive approval
  route and real Windows fault trial are still absent. An unmounted local prompt
  and one-use witness are fake-tested; they do not enable a host write. No repair
  is exposed through the application, and no
  experiment executor is shipped.

## Install and run local checks

Python 3.12 or newer and [uv](https://docs.astral.sh/uv/getting-started/installation/)
are required.

```powershell
uv sync --frozen
.\.venv\Scripts\systemsense.exe doctor
.\.venv\Scripts\systemsense.exe investigate "why did this application stop?"
.\.venv\Scripts\systemsense.exe record --cycles 1 --interval-seconds 30
.\.venv\Scripts\systemsense.exe serve --port 18765
.\.venv\Scripts\python.exe -m pytest -m "not mcp" --ignore=tests/integration/mcp --ignore=tests/security/test_mcp_boundaries.py
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\pyright.exe --project pyright.core.json
```

Evidence is stored at `%LOCALAPPDATA%\SystemSense\systemsense.db` by default. Set
`SYSTEMSENSE_DATA_DIR` to an absolute directory for an isolated store.

`investigate` runs one durable read-only case and prints its cited report. `record`
performs an explicitly bounded foreground passive-recording session and installs no
service. `serve` opens the loopback application at `http://127.0.0.1:18765`;
inference stays off unless explicitly enabled. See
[Local application](docs/application.md) and [Testing](docs/testing.md).

The optional local-model profile also requires the locked tokenizer extra:

```powershell
uv sync --frozen --extra local-models
```

## Optional adapters

MCP is an optional transport adapter for exposing the same bounded application
surface to an external assistant. Install the optional `mcp` extra to use it. It
is not the source of truth, a core readiness gate, or an architectural
constraint. The local investigator must remain useful without an MCP client. See
[Optional MCP adapter](docs/mcp.md).

Optional local inference uses the same advisory interfaces. The admitted profile
uses an isolated, offline Laya subprocess for ordinal attention and a pinned
Ollama model on a fixed loopback API for reasoning. Locality is checked with
artifact manifests and Ollama metadata; missing, ambiguous, remote, over-budget,
or invalid providers degrade explicitly. There is no automatic paid or cloud
fallback. For an explicitly enabled local profile, `serve --prewarm-laya --prewarm-reasoning`
performs bounded opt-in startup checks so cold model loads
do not consume the first case's budget. Startup readiness is historical evidence,
not a promise that an idle model remains resident. See
[Laya runtime qualification](docs/LAYA_QUALIFICATION.md) for the
reproducible install, measured resource envelope, and unproven quality boundary.
The [local-teacher distillation plan](docs/LAYA_TRAINING_PLAN.md) defines the
review, privacy, parity, and ordinary-laptop gates; no student training has
started.

The opt-in [semantic-packet throughput benchmark](benchmarks/laya_semantic_throughput.py)
measures the exact pinned Laya worker on synthetic packets with explicit
coverage and resource samples. Its desktop result is a runtime measurement,
not a diagnostic-quality or everyday-laptop result. The
[adaptive search architecture](docs/architecture/adaptive-search.md) separates
the mounted paths from the proposed full frontier and cloud-both design.

## Evaluation honesty

The checked-in JSON scenarios are engineering fixtures. A separate local episode
runner now records actual coordinator runtime, probe/provider calls, coverage,
terminal outcomes, and failures for five clearly synthetic journeys. Those
episodes validate measurement plumbing only. They do not establish diagnostic
accuracy, model quality, production qualification, or real AI savings. See
[Benchmarking](docs/benchmarking.md).

The [deterministic simulated pilot](docs/SIMULATED_PILOT.md) adds hidden-oracle
Wi-Fi, PDF, and game contract cases with explicit unknown unrun alternatives.
Its scripted outcomes are not training labels or diagnostic-performance evidence.

A separate VM-lab admission contract now checks proposed clean-checkpoint,
fault-injection, oracle, arm-identity and reset records. It is protocol-only:
there is no rig controller or measured Windows VM fault run yet. The next
qualification step is a controlled, owned external HTTPS fault with separate
WinINet and direct-path checks, followed by an approval-safe repair journey and
blinded A/B/C comparisons. Passing a fake transport test or a direct-path check
does not prove that the affected request traversed a proxy. See the
[benchmark protocol](docs/BENCHMARK_PROTOCOL.md).

## Design documents

- [Architecture](docs/architecture/overview.md)
- [Active two-brain architecture](docs/architecture/local-two-brain.md)
- [Adaptive search architecture and current limits](docs/architecture/adaptive-search.md)
- [Local application](docs/application.md)
- [Laya runtime qualification](docs/LAYA_QUALIFICATION.md)
- [Laya fine-tuning decision and data gates](docs/LAYA_FINETUNING.md)
- [Local model selection and limits](docs/LOCAL_MODELS.md)
- [Project status](docs/STATUS.md)
- [Product roadmap and laptop/cloud model plan](docs/PRODUCT_ROADMAP.md)
- [Repeatable diagnostic and repair benchmark](docs/BENCHMARK_PROTOCOL.md)
- [Acceptance matrix](docs/acceptance.md)
- [Evidence packs](docs/packs.md)
- [Performance boundaries](docs/performance.md)
- [Threat model](docs/threat-model.md)
- [Security policy](SECURITY.md)

SystemSense is licensed under the [MIT License](LICENSE).
