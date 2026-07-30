# SystemSense contributor instructions

## Product boundary

- SystemSense collects and organizes evidence. AI agents diagnose.
- The runtime is read-only toward Windows, applications, devices, services,
  drivers, registries, repositories, and networks.
- Never add arbitrary command, shell, executable, filesystem, SQL, XPath,
  registry-path, or URL access.
- Every observation requires provenance, timestamps, limitations, and a stable ID.
- Missing, denied, stale, truncated, failed, and unsupported evidence are data.

## Development

- Python 3.12 or newer.
- Follow red-green-refactor for behavior changes.
- Keep changes surgical and schemas versioned.
- Run test, typecheck, lint, format check, and build before delivery.
- Stage explicit paths only.

