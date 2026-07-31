# Evidence packs

The MVP has six diagnostic families implemented by seven registered probes. All
probes use the same typed manifest, policy, timing, output-limit, normalization,
coverage, and audit path.

| Family | Probe | Selection | Source and bounded content | Execution |
|---|---|---|---|---|
| Core | `core.system` | Every case, budget permitting | Windows build, architecture, boot and CPU identity | In process |
| Core | `core.resources` | Every case, budget permitting | CPU, memory, and disk resource snapshot | In process |
| Application | `application.snapshot` | App, crash, or service symptoms and traits | Up to 128 processes and four fixed Windows services | In process |
| Devices and audio | `devices.snapshot` | Audio, device, or driver symptoms and device traits | Up to 64 PnP devices and 64 signed drivers through WMI | One-shot worker |
| Network | `network.snapshot` | DNS, network, port, or proxy symptoms | Local adapters and up to 128 local endpoints, no active probe | In process |
| Servicing | `servicing.snapshot` | Servicing, update, or Windows Update symptoms | Up to 128 installed updates and fixed reboot-pending registry indicators | One-shot worker |
| Local AI | `local_ai.snapshot` | CUDA, GPU, Python, or Torch symptoms | Up to 8 GPUs, current Python metadata, and up to 256 package records | One-shot worker |

Each probe currently has a 15-second deadline and a 256 KiB serialized-output limit.
Record limits vary by family. The planner also enforces a case time estimate and a
maximum probe count. Three repeated failures open a five-minute per-probe cooldown
circuit. After cooldown, one half-open attempt determines whether the source has
recovered.

## Event Log sentinel

The sentinel is a separate bounded workflow for an existing case. It reads only
registered channels through the local Windows Event Log API. Application and System
are the CLI defaults.

For each channel it:

1. resumes after the persisted record bookmark;
2. reads at most the requested fixed limit;
3. parses XML into normalized evidence;
4. redacts event fields and rendered messages;
5. inserts by stable source identity;
6. advances the bookmark in the same transaction.

Denied or stale channels become coverage evidence. Replaying the same batch does not
duplicate evidence.

## Inventory behavior

Successful probes also write timestamped current inventory. A changed fact appends
history; identical state updates current context without adding change noise.
Optional probes with fresh inventory can be skipped in a later case. Core system and
resource probes remain live so the brief reflects the incident window.

## Adding a pack

A pack must provide:

- a versioned `ProbeManifest` with a fixed ID and implementation ID;
- an extra-forbid Pydantic input model;
- R1 read-only safety metadata;
- a fixed in-process handler or fixed one-shot worker registration;
- explicit deadline, byte, and record limits;
- normalized facts, summary, provenance, timestamps, and limitations;
- fixture, policy, failure, output-limit, and live Windows tests where applicable.

Do not add arbitrary path, command, query, registry, URL, or probe parameters to make
a pack generic. Add a narrowly registered evidence question instead.
