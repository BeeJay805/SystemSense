# Threat model

SystemSense protects Windows target state, evidence confidentiality/integrity,
case isolation, provenance, and local resource availability while helping an
assistant investigate failures.

## Trust boundaries

1. User objectives, symptoms, filenames, logs, documents, and provider output are
   untrusted data.
2. Typed probe manifests, catalog policy, scheduler validation, and local storage
   are application-controlled boundaries.
3. Windows APIs, WMI, psutil, pywin32, package metadata, and drivers are local
   providers that may deny, hang, fail, or return malformed data.
4. Optional MCP is an adapter boundary, not an authority boundary.
5. A future cloud provider is an advisory boundary after local minimization and
   explicit export consent.
6. Future repairs require a separate policy/executor boundary and are outside the
   read-only investigator.

## Controls

| Threat | Control |
|---|---|
| Prompt injection in symptom/evidence text | Text is data; baseline matching uses known terms and typed outputs cannot create probes or commands |
| Arbitrary local execution | Fixed catalog, typed parameter models, forbidden parameter names, no shell/path/URL/query inputs |
| Target-state mutation | Current probes declare no target-state effect and read-only safety; repairs are a separate future boundary |
| Stale model work | Case/state version, correlation ID, deadline, known capabilities, and response validation |
| Over-scheduling | DAG validation, global/per-resource limits, deadlines, cancellation, deduplication, and bounded output |
| Cross-case evidence access | Case-owned evidence lookups, stable IDs, bounded pagination, redaction, and artifact authority separation |
| False certainty from absent data | Explicit denied, stale, failed, unsupported, missing, and truncated coverage states |
| Timestamp confusion | Source observation, local capture, execution, and audit times are distinct |
| Secret or identity leakage | Structured redaction before persistence/export, bounded summaries, and sensitivity classification |
| Hanging local APIs | Selected isolated workers, deadline outcomes, circuit breakers; hard kill isolation remains incomplete for in-process probes |
| Event replay/duplication | Stable source identity, persisted bookmarks, bounded reads, and idempotent inserts |
| Resource exhaustion | Probe/task budgets, byte/record limits, queue bounds, retention, and cancellation |
| Outbound exfiltration | Default runtime has no HTTP/DNS/active connectivity path; cloud export is future and explicit |
| Unsafe model remediation | Providers return typed proposals and hypotheses, never permission tokens or executable operations |

## Residual risks

- A local administrator or compromised same-user process can read or alter local
  stores and installations.
- A compromised dependency, driver, Windows API, WMI provider, or kernel component
  can violate application-level assumptions.
- Redaction is defense in depth, not proof that every novel secret format is found.
- Local endpoint and machine metadata can be sensitive even without outbound traffic.
- A signed or installed driver is not necessarily safe; SystemSense records evidence
  rather than making a trust decision.
- The default no-network tests cover Python/application entry points, not every
  internal behavior of Windows COM, WMI, pywin32, psutil, or the kernel.
- Current graph relationships and evidence ranking do not establish causality.

## Explicitly out of scope for the current investigator

- arbitrary commands, remote hosts, packet capture, active network tests, malware
  analysis, or endpoint protection;
- automatic repair, rollback, elevation, firmware/voltage changes, broad cleanup,
  or destructive stress tests;
- cloud upload, automatic paid fallback, or model-training export;
- claims of complete system telemetry or measured diagnostic performance.
