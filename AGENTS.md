# Windows Investigator contributor instructions

## Product boundary

- SystemSense is a local-first Windows investigator. Deterministic software owns
  collection, scheduling, provenance, policy, and every machine interaction.
- Decision and reasoning models are replaceable advisory providers. They may rank
  registered probes and propose explanations, but they never receive operating-system
  authority or mint permissions.
- Investigation is read-only toward Windows, applications, devices, services,
  drivers, registries, repositories, and networks. Any future experiment or repair
  belongs to a separate, specifically consented executor and verification boundary.
- Never add arbitrary command, shell, executable, filesystem, SQL, XPath,
  registry-path, or URL access.
- Every observation requires provenance, timestamps, limitations, and a stable ID.
- Case-open time, source observation time, collection time, and audit time are distinct.
- Missing, denied, stale, truncated, failed, and unsupported evidence are data.
- The executable work graph is dependency- and resource-aware. It is not the evidence
  relationship graph and is not evidence of causality.
- Keyword planning is a deterministic baseline/fallback, not the product architecture.
- MCP is an optional transport adapter. It must not own investigation policy, storage,
  scheduling, or model-provider behavior.
- Fixture benchmarks validate contracts and report math only. Diagnostic-performance
  claims require measured held-out investigations with recorded provenance.

## Development

- Python 3.12 or newer.
- Follow red-green-refactor for behavior changes.
- Keep changes surgical and schemas versioned.
- Run test, typecheck, lint, format check, and build before delivery.
- Stage explicit paths only.
