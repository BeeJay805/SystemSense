# Windows evidence packs

Packs are reviewable, versioned descriptions of fixed read-only capabilities. A
pack may expose typed probes and normalization logic; it may not invent arbitrary
commands, paths, queries, URLs, or privilege escalation.

## Current registry

The working tree registers 15 bounded read-only probes:

| Domain | Current evidence shape | Status |
|---|---|---|
| Core | Windows identity, CPU, memory, and bounded resource facts | Available |
| Application | Process identities, service dependencies and startup metadata | Available within bounded Windows API coverage |
| Devices/audio | Device problem codes and signed-driver metadata | Isolated probe; coverage depends on host |
| Network | Adapters, routes, DNS/proxy configuration, local TCP listeners and owner identity | Available; no active connectivity test |
| Servicing | Installed updates and reboot-pending metadata | Isolated probe; coverage depends on host |
| Local AI | GPU, Python, package, and CUDA metadata | Isolated probe; coverage depends on host |
| Storage | Volume/partition/disk topology and exposed reliability counters | Unsupported counters are explicit |
| Power | Power scheme/source and exposed processor metadata | No inferred thermal values |
| Security | Security Center, firewall profiles and UAC configuration | Read-only status, not a security verdict |
| Incident events | Fixed-profile recent WHEA, storage, application, service and power events | Bounded recent tails, not a complete event history |
| Resource pressure | Three fixed-interval CPU/memory/disk/process samples | First deltas remain unknown; observer workload disclosed |
| GPU telemetry | Three NVIDIA utilization/VRAM/clock/power/thermal samples | Passive samples, not a load test |

Event Log capture is a separate bounded sentinel with persisted bookmarks and
source event timestamps. It is not a claim of continuous or complete telemetry.

## Pack contract

Each pack should declare:

- schema and implementation version;
- supported Windows/device/application versions;
- typed probe IDs and parameter models;
- permission and safety class, target-state effect, and outbound-network policy;
- deadline, output, record, and resource expectations;
- Event Log order currently uses case-scoped record positions plus source event time;
  a durable native Windows bookmark or explicit boot/log-generation identity remains
  future work;
- provenance, sensitivity, redaction, and limitation behavior;
- observation versus capture timestamp semantics;
- typed relationships and applicability conditions through the durable temporal
  evidence graph, with bounded adaptive retrieval;
- procedure/verifier compatibility only for future consent-bound changes.

Unsupported or denied sources become coverage records. They are not silently
replaced with zero values or treated as component failures.

## Coverage roadmap

System-wide breadth is the architectural goal, not the current implementation.
Future candidates include ETW/WPR bounded incident capture, wider vendor-specific
storage reliability, display/frame timing, CPU thermals and richer application
failure evidence. Existing WHEA events, GPU telemetry and service dependencies
cover only their documented bounded sources. Each expansion must
be added with overhead, privacy, loss, permission, and test evidence rather than
by broadening the access surface.
