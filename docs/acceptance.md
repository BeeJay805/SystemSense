# Acceptance matrix

This matrix distinguishes verified foundations from capability gates that are not
yet complete.

| Capability | Acceptance evidence | Status |
|---|---|---|
| Read-only Windows boundary | Fixed probe catalog; no arbitrary command, path, URL, registry, SQL, or query inputs | Implemented for current probes |
| Typed probe execution | Versioned manifests, typed parameters, deadlines, output/record caps, isolated default collectors and passive Event Logs | Implemented; custom in-process handlers remain cooperative |
| Evidence integrity | Stable IDs, provenance, redaction, coverage states, retention, audit links | Implemented |
| Correct time semantics | Source observation time differs from local capture and execution/audit time; case start is not observation time | Implemented in core contracts/tests |
| Broad Windows coverage | 16 registered probes: baseline topology/configuration, staged passive connectivity, events, listeners, resource pressure and GPU telemetry | Implemented; unsupported and omitted sources remain explicit |
| Task scheduling | Acyclic dependencies, bounded concurrency, resource budgets, cancellation, deduplication, stale state handling | Implemented with per-round adaptive replanning over the registered catalog |
| Fast decision boundary | Immutable request/response, paged facts, graph context, known probe IDs, catalog costs, state/deadline binding | Actual pinned Laya runtime and deterministic fallback implemented |
| Reasoning boundary | Cited hypotheses, support/contradiction checks, unknown-cause preservation, distinguishing probes | Reviewed deterministic rules and optional local Ollama adapter implemented |
| Temporal dependency graph | Typed relationships with provenance, validity, applicability, observed/inferred status, retrieval | Durable SQLite relations, explicit projection, bounded traversal and retrieval implemented |
| Adaptive investigation loop | Durable hypothesis ledger, bounded rounds/budgets, no-progress detection, stale-result rejection | Implemented first local coordinator; broad diagnostic quality unqualified |
| Local application | Loopback case start/inspect/cancel/resume/export plus opt-in bounded passive recording; shutdown cancellation | Implemented first local interface |
| Local advisory inference | Pinned Laya and Qwen3.8 27B, local-only verification, real-token budgeting, memory admission, visible fallback | Live dual-brain cases exercised; general diagnostic quality remains unqualified |
| Shared reference knowledge | 79 nodes, 116 conditional relations, 26 primary sources; explicit runtime Windows error lookup | Implemented separately from machine evidence; game frame-time and active-refresh observations remain absent |
| Optional MCP | Adapter over neutral application API; no core dependency or tool-count gate | Implemented as an optional adapter/extra |
| Repair boundary | Explicit consent, target/precondition binding, journal, rollback limits, independent outcome verification | Fake-tested WinINet runner, journal, narrow policy gate and isolated transports; no owned endpoint, app approval route, real repair or qualified oracle |
| Cloud advisory | Minimized export, redaction, explicit consent, authenticated transport, local response validation | Not implemented |
| Diagnostic performance | Recorded, matched, held-out episodes with evidence quality and host-impact metrics | Reviewed-Windows scorecard contract exists, but no externally qualified real episode or general accuracy result |

## Evidence required for subsequent gates

- Scheduler integration must show independent probes overlap within declared global
  and resource limits and preserve per-task outcomes and timestamps.
- Graph/coordinator work must prove evidence citations, relationship provenance,
  state-version checks, competing hypotheses, and honest unresolved outcomes.
- A model comparison must use the same probe catalog, evidence access, budgets,
  scenarios, and failure denominators for every arm.
- Repair work must show explicit consent, exact target binding, precondition checks,
  before/after evidence, interruption handling, and independent verification.
- Any cloud or MCP adapter must be removable without changing local collection,
  storage, policy, or deterministic fallback behavior.
