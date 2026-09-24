# Testing

Tests protect the evidence boundary first, then the integrated scheduler/provider
boundaries.
Live Windows checks are opt-in because they inspect the host.

## Local gates

```powershell
uv sync --frozen
.\.venv\Scripts\ruff.exe format --check .
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\pyright.exe --project pyright.core.json
.\.venv\Scripts\python.exe -m pytest -m "not mcp" --ignore=tests/integration/mcp --ignore=tests/security/test_mcp_boundaries.py
.\.venv\Scripts\python.exe -m benchmarks.runner
.\.venv\Scripts\python.exe -m benchmarks.local_episodes
```

The fixture benchmark checks report contracts only. The local episode runner uses
the real coordinator with deterministic synthetic probe handlers and actual wall
clock timing. Neither is a diagnostic-performance run.

The optional MCP adapter has a separate non-blocking CI lane. To test it locally,
run `uv sync --frozen --extra mcp`, the full `pyright` check, and the focused MCP
integration/security tests. Core wheel smoke tests install no MCP or AnyIO package.

## Required behavior

### Evidence and security

- fixed typed probes only; no arbitrary commands, paths, URLs, registry paths, SQL,
  XPath, or active network tests;
- denied, stale, failed, unsupported, missing, and truncated evidence remains
  explicit;
- source observation time, local capture time, and execution/audit time remain
  distinct;
- redaction occurs before persistence/export and evidence remains case-owned;
- symptom and captured text remain data, never instructions;
- worker, output, record, queue, pagination, and brief limits hold under failure.

### Scheduler

- independent tasks overlap within global and per-resource limits;
- dependency cycles and missing dependencies are rejected;
- deadlines and cancellation produce explicit task outcomes;
- duplicate work is deduplicated;
- stale state versions cannot execute or silently overwrite newer state;
- blocked prerequisites do not appear successful.

### Providers

- requests/responses are immutable, versioned, bounded, and bound to case,
  correlation, deadline, redacted evidence content, evidence-grounded relationships,
  and state version;
- proposals can reference only known read-only probes with bounded cost,
  diagnostic purpose, resource class, and dedupe key;
- duplicate/unknown/over-budget/unsupported proposals are rejected;
- the keyword baseline is deterministic and explicitly labelled;
- reasoning preserves support, contradiction, missing evidence, alternatives, and
  unresolved/unavailable states;
- provider failure leaves deterministic evidence operation available.
- Ollama endpoints are fixed loopback routes with proxies and redirects disabled;
  `/api/tags` and `/api/show` metadata must prove a local artifact before chat;
- inference defaults to disabled and CPU-only, with bounded bodies, responses,
  keep-alive, and one monotonic total timeout across locality checks and chat;
- fixed-length, chunked, oversized-body, oversized-header, redirect, and slow-trickle
  transport behavior remains covered without invoking a model.

## Live Windows checks

Set `SYSTEMSENSE_LIVE_WINDOWS=1` only when host inspection is intended. Run the
focused Windows integration tests for capabilities, core resources, devices,
network, application, servicing, local-AI metadata, and Event Log parsing. Record
Windows build, permissions, collector versions, limitations, and timestamps with
the result. A fixture pass does not substitute for a live collector check.
The controlled host pass exercised all 15 registered probes, bounded
passive capture, stop behavior, and cited case rendering. These are runtime and
safety checks, not diagnostic-performance evidence.

## Episode measurement

`benchmarks.local_episodes` records five synthetic real-coordinator journeys with
matched catalogs and budgets, actual runtime, probe/provider calls, coverage,
terminal outcomes, model IDs, and failure denominators. Quality remains `unknown`
until a named reviewer assigns a separate label. Diagnostic evaluation still needs
held-out live cases, accepted labels, and host overhead; no paid-model A/B run is a
current acceptance requirement.
