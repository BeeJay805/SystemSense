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

The current repository contains an active local two-brain application: a durable,
bounded investigation loop, a loopback case interface, Windows probe packs,
redaction, SQLite evidence and relationship persistence, passive-history
capture, bounded retrieval, and replaceable decision/reasoning providers. The
default install is deterministic and performs no model inference. An explicitly
enabled profile runs pinned Laya attention and standard Qwen3.8 27B side by side.

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
  breakers, and one-shot worker isolation for all 15 registered collectors and
  passive Event Log queries. Custom trusted in-process handlers must cooperate
  with cancellation; they are not a hard-kill boundary.
- Broad read-only collection across core resources, processes/services, devices,
  network configuration and listener ownership, storage, servicing, local AI,
  power, security and recent events. Follow-up probes sample resource pressure
  and GPU clocks/power/thermal telemetry. Unsupported counters and omitted rows
  remain explicit, not assumed healthy.
- `TaskGraph` and `BoundedScheduler` for dependency-aware, cancellation-aware,
  resource-bounded read-only work, integrated with probe execution and persisted
  attempt outcomes.
- `FastDecisionProvider` and `ReasoningProvider` contracts with state-version,
  case, correlation, deadline, evidence, and typed probe-capability binding.
- `ProviderBackedPlanner` with `KeywordBaselineDecisionProvider` as the
  deterministic baseline/fallback. It is not a learned Windows diagnostician.
- A durable coordinator with hypothesis history, completed-probe tracking,
  no-progress detection, interruption recovery, and explicit terminal outcomes.
- Repeated fast-brain attention, two-hop evidence expansion, deep-brain redirects,
  bounded detail searches, and durable exact facts behind hypothesis citations.
- Deterministic reviewed reasoning rules that cite observations while retaining
  an unknown cause. A collector failure remains an observability gap.
- Typed, provenance-rich temporal evidence relationships with SQLite persistence,
  bounded traversal, explicit projection rules, and opt-in historical retrieval.
- A separate sourced reference graph of 66 nodes and 102 conditional relationships.
  Installed Windows error definitions are retrieved on explicit code/symbol requests;
  neither documentation nor graph connectivity establishes a machine fault.
- A loopback-only local web application for start, inspect, cancel, resume, and
  bounded JSON export. The browser receives no shell or arbitrary query surface.
- Optional local dual-brain inference: pinned Laya ranks evidence and registered
  probes, while a separately pinned loopback Ollama model reasons over focused
  evidence. It is disabled by default, has deterministic fallbacks, and never
  pulls a model, starts Ollama, or selects a cloud alias at runtime.
- Exact-scope action proposal, consent, and authorization contracts. No repair
  or experiment executor is shipped.

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
fallback. See [Laya runtime qualification](docs/LAYA_QUALIFICATION.md) for the
reproducible install, measured resource envelope, and unproven quality boundary.

## Evaluation honesty

The checked-in JSON scenarios are engineering fixtures. A separate local episode
runner now records actual coordinator runtime, probe/provider calls, coverage,
terminal outcomes, and failures for five clearly synthetic journeys. Those
episodes validate measurement plumbing only. They do not establish diagnostic
accuracy, model quality, production qualification, or real AI savings. See
[Benchmarking](docs/benchmarking.md).

## Design documents

- [Architecture](docs/architecture/overview.md)
- [Active two-brain architecture](docs/architecture/local-two-brain.md)
- [Local application](docs/application.md)
- [Laya runtime qualification](docs/LAYA_QUALIFICATION.md)
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
