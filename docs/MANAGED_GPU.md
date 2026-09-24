# Managed local GPU inference

SystemSense's schema-v3 GPU profile runs pinned CUDA Laya as an advisory fast
provider. The current managed reasoning provider is deterministic. Local
Qwen3.8 27B remains a separately pinned research candidate; the application
does not admit it concurrently with managed Laya. No cloud provider is part of
this stage.

## What admission guarantees

The application binds the exact Laya worker process and creation time to a
same-user cross-process SQLite lease before allowing the child to load weights.
It checks a fresh, source-timed RAM and NVIDIA GPU sample against the profile's
GPU UUID, device index, peak demand, and free-memory reserves. A watchdog
renews the lease while the worker is idle, and every ranking call rechecks
ownership and available headroom. The lease is released only after that exact
worker exit is verified. Expiry or an uncertain shutdown quarantines capacity
instead of treating a still-live model as free memory.

The ledger path is fixed by the application at
`%LOCALAPPDATA%\SystemSense\host-gpu-lease-v3.sqlite3` on a normal Windows
account. It coordinates cooperating SystemSense processes in that account. It
is not a machine-wide arbiter across Windows users or independent programs,
and a resource sample cannot reserve memory used later by another application.
SystemSense therefore retains explicit headroom and degrades when admission
cannot be proven. These checks limit interference; they do not establish safety
while a GPU-heavy game or renderer is running.

## Profile states

| Profile | Effective behavior |
| --- | --- |
| No enabled profile | Deterministic decision and reasoning providers. |
| Legacy v1/v2 requesting either GPU provider | Deterministic providers with `legacy_gpu_profile_requires_v3`; the old file is preserved. |
| Schema v3, managed CUDA Laya | Laya attention after admission; deterministic reasoning. No Ollama server is started. |
| Schema v3, typed-feature decision provider | CPU typed-feature attention and deterministic reasoning; no GPU lease. |
| Legacy CPU-only local profile | Existing pinned local adapters remain available; they are not the managed GPU configuration. |

Configured mode and effective mode are reported separately. A missing,
stale, mismatched, or denied GPU sample is an admission failure, not evidence
that the computer is healthy or that a diagnosis succeeded. A successful
prewarm says the worker was ready at that moment only.

## Review a v3 candidate

`propose_managed_v3_payload` builds a validated candidate from an existing
legacy profile without modifying the installed file. For CUDA Laya, first read
the device UUID from the trusted local telemetry adapter, then pass a
`ManagedGpuResources` value with the selected device index and UUID. Save the
returned dictionary as a separate candidate JSON file for review. The builder
moves the old Qwen pin to `review_only_reasoning`; that field cannot activate
Qwen in v3. Review paths, device identity, memory floors, and the absence of
an active reasoner before manually selecting the candidate as the profile.
The builder does not overwrite or activate anything.

```python
from systemsense.inference.host_telemetry import read_host_telemetry
from systemsense.inference.profile import (
    ManagedGpuResources,
    load_inference_profile,
    propose_managed_v3_payload,
)

legacy = load_inference_profile()
sample = read_host_telemetry(gpu_device_index=legacy.laya.cuda_device_index)
candidate = propose_managed_v3_payload(
    legacy,
    decision_provider="laya",
    managed_resources=ManagedGpuResources(
        gpu_device_index=sample.gpu_device_index,
        gpu_uuid=sample.gpu_uuid,
    ),
)
# Review candidate and save it separately. This code does not activate it.
```

For a machine without qualified CUDA Laya, request
`decision_provider="typed-feature"` and omit `managed_resources`. The same
deterministic fallback remains available if the optional model is absent.

## Next admission gate

To run Laya and Qwen together under one GPU policy, SystemSense must own and
verify the complete Ollama server lifecycle, reserve both peak memory demands,
attribute requests to that owned server, reconcile crashes, and measure
interference with the affected task. The isolated desktop coexistence smoke
left only about 2.2 GiB free at its lowest sampled point on a 24 GiB RTX
4090. That is runtime-fit evidence, not a safe gaming envelope or measured
diagnostic benefit. Representative laptops need separate CPU/iGPU latency,
memory, power, and answer-quality evaluation before this profile can be
recommended for everyday computers.
