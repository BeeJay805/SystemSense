# Security policy

## Supported versions

SystemSense is a pre-release MVP. Security fixes are applied to the latest commit
on the default branch. No older release line is currently supported.

## Report a vulnerability

Use GitHub's private **Security > Advisories > Report a vulnerability** workflow
for the repository. Do not open a public issue for a vulnerability that could
expose private Windows evidence, escape a case boundary, execute unregistered
code, mutate target state, or bypass an output or retention limit.

Include:

- the affected commit or version;
- a minimal reproduction;
- the expected and observed boundary;
- whether secrets or personally identifying evidence were exposed;
- any known workaround.

Do not include real secrets, private event logs, usernames, machine names, or
customer evidence. Use synthetic records and redacted paths.

## Security boundary

SystemSense reads local Windows state and writes only its own evidence database,
artifact store, audit records, and bookmarks. Registered probes are standard-user,
read-only operations with typed inputs, deadlines, record limits, and byte limits.
Potentially hanging WMI and package probes run in one-shot child processes.

The MCP surface has six fixed tools. It exposes no arbitrary shell, executable,
filesystem path, SQL, XPath, registry path, URL, or probe ID. Evidence and cursors
are case-scoped. Cursor integrity is authenticated.

SystemSense contains no application-level outbound network client or active network
probe. Local adapter and endpoint tables are read through operating-system APIs.

The local database can contain sensitive system metadata. Protect the selected data
directory with normal Windows account permissions. SystemSense is not a security
boundary against an administrator, a process already running as the same user, a
compromised Python runtime, or a tampered installation.

See [Threat model](docs/threat-model.md) for assumptions and residual risks.
