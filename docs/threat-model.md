# Threat model

## Goals

SystemSense must help an AI reason about Windows failures without creating a general
remote administration surface. It protects target state, evidence boundaries, model
context, and local resource availability.

## Assets

- integrity of Windows, applications, devices, services, registries, and networks;
- confidentiality and integrity of collected system metadata;
- case isolation between unrelated diagnostic sessions;
- integrity of provenance, bookmarks, audit links, and pagination cursors;
- bounded CPU, memory, disk, output, and model-context usage.

## Trust boundaries

1. Symptom text and MCP arguments are untrusted model or user input.
2. The MCP server and probe policy are the authority boundary.
3. Windows APIs, WMI, psutil, pywin32, and package metadata are external local data
   providers and may deny access, fail, hang, or return malformed data.
4. SQLite and the artifact directory are trusted only while protected by the local
   Windows account and an untampered installation.
5. The AI receives evidence, not authority to run arbitrary local operations through
   SystemSense.

## Threats and controls

| Threat | Control |
|---|---|
| Prompt injection in symptom text | Symptom text is data. It can match registered terms but cannot create a probe or parameterize commands. |
| Arbitrary command or query execution | Six fixed MCP tools, fixed probe IDs, typed inputs, fixed Event Log channels, and fixed registry sources. |
| Target-state mutation | Probe manifests accept only R1 read-only safety; mutation classes are rejected. Self-writes are limited to SystemSense evidence and audit state. |
| Cross-case evidence access | Evidence lookups verify case ownership. Artifact authority is a separate case relation. |
| Cursor tampering or reuse | Cursors are HMAC-authenticated and bound to operation, filters, and case. |
| Secret or identity leakage | Structured redaction runs before persistence; brief text is clipped and neutralized. Test only with synthetic data when reporting bugs. |
| Output or context exhaustion | Probe record and byte caps, MCP page limits, field clipping, and hard brief character budgets. |
| Hanging local APIs | WMI and package-heavy probes run in deadline-controlled one-shot workers. |
| Event storms or replay duplication | Bounded Event Log reads, stable source identity, atomic bookmark advancement, and idempotent inserts. |
| Disk exhaustion | Age and size retention policies, batch deletion, artifact reference checks, and orphan recovery. |
| False certainty from missing data | Explicit denied, stale, failed, truncated, unsupported, and missing coverage states. |
| Outbound data exfiltration | No HTTP client, DNS lookup, remote endpoint, active connectivity test, or application-level socket use. |
| AI-generated unsafe remediation | Briefs contain observations, citations, coverage, and limitations only. They intentionally omit causal and action declarations. |

## Residual risks

- A local administrator or process running as the same user can read or alter the
  database and installation.
- A compromised Python dependency can violate application-level assumptions.
- Windows APIs can expose local endpoint and machine metadata even without outbound
  traffic.
- Redaction is defense in depth, not a proof that all novel secret formats are
  recognized.
- A signed or installed driver is not necessarily safe. SystemSense records metadata
  and does not make a trust decision.
- The no-network test monkeypatches Python socket and URL entry points. It does not
  prove the internals of Windows COM, WMI, pywin32, psutil, or the kernel.

## Out of scope for the MVP

- remote host collection;
- remediation, repair, rollback, or configuration change;
- arbitrary files, commands, registry paths, event queries, SQL, or URLs;
- packet capture or active network probes;
- malware analysis or endpoint protection;
- protection from a compromised administrator, interpreter, dependency, or host.
