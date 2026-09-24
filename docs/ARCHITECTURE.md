# Architecture

[North star](NORTH_STAR.md) defines the product. This page distinguishes the intended active loop from the capabilities at committed HEAD; [current state](CURRENT_STATE.md) is the implementation ledger.

## Ownership and data flow

1. A case receives a user symptom and a bounded parallel baseline of registered, typed, read-only Windows probes. Each result is persisted with stable identity, source-observation and capture times, provenance, redaction, quality, limitations, and coverage. Case-open and audit times are distinct.
2. The deterministic coordinator forms a changing frontier of existing evidence retrieval, case-evidence graph traversal, reference-mechanism branches, precise new measurements, and deep-reasoner escalation. Candidate identity binds kind, target, registered parameters, source and observation window. A later window may justify a repeat; an identical in-flight candidate must not be duplicated.
3. The fast advisory provider repeatedly ranks bounded structured batches from the affected frontier. Persistence invalidates only dependent candidates; microbatches avoid a full re-rank. Admission checks source generations, state, deadlines, budgets, resource classes, catalog costs, permissions, and durable one-shot identity. Unrelated probes and deep reasoning must not block an admitted follow-up.
4. The deep advisory provider receives a focused, cited evidence map, maintains competing hypotheses, requests distinguishing evidence, and can redirect the fast provider. It cannot turn its explanation into a fact or an executable command. Deterministic code decides whether a proposed diagnosis is supported or explicitly unresolved.
5. A separately approved repair executor, if qualified in the future, checks exact target and preconditions, journals the action, and verifies the affected task after the change. The current application does not expose automatic repair.

Steps 2–4 describe the **target primary loop**, not a claim that committed HEAD already runs it end to end. The existing durable mixed frontier and narrow event-attention path are partial implementations; some mixed decisions remain synchronous. The keyword planner is a deterministic baseline/fallback only.

## Separate graphs

- The **executable work graph** is an acyclic dependency/resource schedule. It says when registered read-only work may run, not what caused the fault.
- The **case evidence graph** contains temporal, provenance-backed relationships observed or carefully projected from this machine. Traversal and retrieval are bounded. An edge is not a diagnosis.
- The **reference graph** contains sourced, conditional IT mechanisms, distinguishing questions, and counterevidence. It may guide investigation but never supplies a missing machine observation. Category/diversity ranking is not a dependency graph.

## Authority and failure boundaries

All model requests are bounded, redacted, versioned, and tied to a case/state/deadline and registered capabilities. Responses are advisory and validated against the catalog; providers cannot specify arbitrary commands, executables, files, registry paths, URLs, queries, or permission tokens. Probe workers have deadlines, output limits, cancellation, and isolation where hard termination is needed. Coverage gaps, errors, timeouts, stale results, and contradictions are retained as data; they do not silently become healthy values.

Model residency and routing belong behind replaceable provider interfaces. The desired local primary profile keeps the fast brain warm while the deep brain works; sequential swapping is an explicit low-memory fallback, not the primary architecture. A resource lease must cover actual processes and measured RAM/VRAM, and model IDs must be verified at runtime. Future cloud providers remain optional advisory adapters behind explicit minimization/export consent. The loopback application and MCP transport call the same case service; neither owns policy or storage.

Untrusted symptoms, logs, documents, and model text cannot cross the authority boundary. Structured redaction is defense in depth, not a guarantee of no novel secrets. A same-user or administrator compromise and faulty Windows providers remain residual risks. Never infer a healthy device from absent telemetry, or a repair from an unverified action.
