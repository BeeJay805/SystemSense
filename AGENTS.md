# Windows Investigator contributor instructions

## Documentation hygiene

Keep the five canonical product documents authoritative and link to them instead of
creating parallel plans or status pages. `docs/CURRENT_STATE.md` describes the
committed, current behavior, not a chronological diary. Update affected documentation
and README links with behavior changes; identify the tested revision and separate
planned, built, exercised, and measured claims. Archives preserve prior decisions and
failures. Add a new document only when it has a distinct purpose.

Start with [NORTH_STAR.md](docs/NORTH_STAR.md) and [CURRENT_STATE.md](docs/CURRENT_STATE.md). Read the relevant parts of [ARCHITECTURE.md](docs/ARCHITECTURE.md), [TRAINING_PLAN.md](docs/TRAINING_PLAN.md), and [BENCHMARKS_AND_ACCEPTANCE.md](docs/BENCHMARKS_AND_ACCEPTANCE.md) when the task touches those contracts or claims. These five files remain the authoritative product hierarchy. `docs/archive/` preserves history, not active guidance; consult it only to investigate a prior decision. Do not infer that a target design is implemented.

## Non-negotiable engineering boundaries

- Deterministic code owns observations, timestamps, provenance, scheduling, machine interactions, permissions, and verification. Models are replaceable advisory providers only.
- Investigations are read-only toward Windows, applications, devices, services, drivers, registries, repositories, and networks. Experiments and repairs require a separately consented, exact-scope executor.
- Never introduce arbitrary command, shell, executable, filesystem, SQL, XPath, registry-path, or URL access. Do not let model output mint authority.
- Every observation needs stable identity, provenance, quality/limitations, and distinct source-observation, capture, case-open, and audit times. Missing, denied, stale, truncated, failed, and unsupported are data.
- The executable work graph, observed evidence graph, and sourced reference graph serve different purposes. A relationship or keyword rank is not causal proof. MCP is optional transport, not investigation policy.
- Keep the fast brain available for repeated mixed-frontier decisions while the deep brain works; sequential swapping is a low-memory fallback. Prove complete behavior and measured utility rather than mistaking components, fixtures, or call counts for diagnostic performance.

## Development

Use Python 3.12+. Follow red-green-refactor for behavior changes; keep schemas versioned and preserve unrelated edits. Run focused tests, non-MCP tests, typecheck, lint, format check, and build before delivery. Stage explicit paths only. Record actual model/runtime identities and report unverified gates honestly.

## Concurrent coding sessions

- Run `scripts/dev-context.ps1` before taking a lane. Its upstream SHA is the local tracking ref, not a fresh remote fetch. Recheck before integration.
- Use a separate Git worktree/branch per coding session. Name one integration owner for shared runtime contracts, serializers, migrations, and canonical docs; other lanes should agree on those interfaces before editing them.
- State the lane, expected touched paths, and integration owner in the Codex task/handoff. Worktree files and chat context do not synchronize automatically. GPU, model servers, VM, ports, and host case databases remain shared across worktrees; serialize their use with an explicit human-visible owner.
- `scripts/dev-context.ps1 -RefreshMap` generates an optional, ignored, revision-stamped local module/import JSON map; `scripts/code_map.py find` prints bounded matches. It is navigation help only: confirm call flow and behavior in source/tests before changing policy or reporting product capabilities. Do not load the whole map or benchmark history into every session.
