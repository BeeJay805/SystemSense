# Windows Investigator contributor instructions

Read the five current documents in `docs/`: [NORTH_STAR.md](docs/NORTH_STAR.md), [ARCHITECTURE.md](docs/ARCHITECTURE.md), [CURRENT_STATE.md](docs/CURRENT_STATE.md), [TRAINING_PLAN.md](docs/TRAINING_PLAN.md), and [BENCHMARKS_AND_ACCEPTANCE.md](docs/BENCHMARKS_AND_ACCEPTANCE.md). They are the authoritative product hierarchy. `docs/archive/` preserves history, not active guidance; consult it only to investigate a prior decision. Do not infer that a target design is implemented.

## Non-negotiable engineering boundaries

- Deterministic code owns observations, timestamps, provenance, scheduling, machine interactions, permissions, and verification. Models are replaceable advisory providers only.
- Investigations are read-only toward Windows, applications, devices, services, drivers, registries, repositories, and networks. Experiments and repairs require a separately consented, exact-scope executor.
- Never introduce arbitrary command, shell, executable, filesystem, SQL, XPath, registry-path, or URL access. Do not let model output mint authority.
- Every observation needs stable identity, provenance, quality/limitations, and distinct source-observation, capture, case-open, and audit times. Missing, denied, stale, truncated, failed, and unsupported are data.
- The executable work graph, observed evidence graph, and sourced reference graph serve different purposes. A relationship or keyword rank is not causal proof. MCP is optional transport, not investigation policy.
- Keep the fast brain available for repeated mixed-frontier decisions while the deep brain works; sequential swapping is a low-memory fallback. Prove complete behavior and measured utility rather than mistaking components, fixtures, or call counts for diagnostic performance.

## Development

Use Python 3.12+. Follow red-green-refactor for behavior changes; keep schemas versioned and preserve unrelated edits. Run focused tests, non-MCP tests, typecheck, lint, format check, and build before delivery. Stage explicit paths only. Record actual model/runtime identities and report unverified gates honestly.
