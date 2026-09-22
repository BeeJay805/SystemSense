# Security policy

## Supported versions

SystemSense is pre-release. Security fixes apply to the latest commit on the
default branch; no older release line is supported.

## Report a vulnerability

Use GitHub's private **Security > Advisories > Report a vulnerability** workflow.
Do not open a public issue for a vulnerability that could expose private Windows
evidence, escape a case boundary, execute unregistered code, mutate target state,
or bypass output, scheduling, or retention limits.

Include the affected commit, minimal reproduction, expected and observed boundary,
whether secrets or personal evidence were exposed, and any workaround. Use
synthetic records and redacted paths. Never include real secrets, private event
logs, usernames, machine names, or customer evidence.

## Security boundary

SystemSense reads local Windows state and writes only its own evidence database,
artifact store, audit records, and bookmarks. Registered probes are typed,
bounded, read-only operations with deadlines, record limits, and byte limits.
Selected probes with known blocking risk run in one-shot child processes. The
remaining in-process probes receive deadlines and cancellation signals, but a
non-cooperative call can delay return while its thread drains; it is not forcibly
terminated.

The core application does not accept arbitrary shell, executable, filesystem path,
SQL, XPath, registry path, URL, or network-test input. Provider proposals can name
only known read-only probes and cannot mint permission. Evidence and pagination
remain case-scoped; redaction occurs before persistence/export where applicable.

MCP is an optional adapter (available through the optional `mcp` extra). Its
schemas must preserve the same application boundary, but MCP is not the security
source of truth. The repository contains typed action proposals and an exact-scope
consent gate, but no state-changing executor. A future cloud advisory adapter must
use explicit export consent, local minimization/redaction, authenticated
transport, and local response validation. No automatic paid or cloud fallback is
allowed.

The default runtime contains no application-level outbound network client or
active network probe. Local adapter and endpoint tables are read through operating-
system APIs.

The local database may contain sensitive system metadata. Protect its directory
with normal Windows account permissions. SystemSense is not a boundary against an
administrator, a same-user process, a compromised Python runtime/dependency, a
malicious driver/API provider, or a tampered installation.

See [Threat model](docs/threat-model.md) for assumptions and residual risks.
