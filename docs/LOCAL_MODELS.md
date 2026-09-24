# Local model selection

The current managed GPU option is **pinned CUDA Laya with deterministic reasoning**
under a reviewed schema-v3 profile. Installed legacy v1/v2 GPU profiles now run
deterministically with `legacy_gpu_profile_requires_v3`; they are not rewritten.
Qwen3.8 27B remains a pinned, separately measured research candidate, but it is
not admitted alongside managed Laya. These providers are replaceable; no local
model has demonstrated general diagnostic quality. There is no cloud fallback,
paid API, automatic model download, or training job in the investigation path.
See [managed GPU inference](MANAGED_GPU.md) for profile and admission details.

## Historical Laya and Qwen research configuration

The user requested Qwen3.8 27B if it fits. The standard local artifact runs fully
on this RTX 4090 at an 8,192-token context, with approximately 17.30 GB of GPU
residency reported by Ollama. Its model identity was verified against the official
[Qwen3.8 model card](https://huggingface.co/Qwen/Qwen3.8-27B) and
[Ollama library entry](https://ollama.com/library/qwen3.8:27b). A shared underlying
GGUF architecture name is not the model's release identity. The community modified
model present elsewhere on the host is not the selected artifact.

The pinned Ollama digest is
`22130167c4c20e20c7b71454612966ca8e8171e9b3cc8ab6ce8aa6cbfec79643`.
The official tokenizer is pinned to revision
`1d4bf0f2ff6012fd82039f2fa52739d0dd7c60c0`, with file SHA-256
`0997f410c57a1f4e53b09e4be8f4a172d90edd9564368fb0847030937229b9f3`.

The measured research profile used an 8K context and 1,200 output-token ceiling.
Advertised maximum model context is not the right allocation for a shared 24 GB
GPU. Thinking was disabled in that structured-output profile; changing that
policy requires another latency/output qualification.
In that research path, input admission counted the actual tokenizer, schema and
framing reserve before HTTP. Output-length termination was rejected rather than
accepted as a complete answer.

The historical dual-brain research path supported opt-in prewarming of both
providers. The current schema-v3 GPU path can prewarm managed Laya only. It does
not start or prewarm Ollama. Prewarming consumes startup time and holds RAM/VRAM
while the service is idle; its benefit and cost require separate measurement.

Laya supplies repeated ordinal attention over exact fact pages and registered
probes. Its CPU broad-request latency was not suitable for the fast-brain role, so
the managed GPU option uses a separately pinned CUDA worker with bounded
batches. See [Laya qualification](LAYA_QUALIFICATION.md) for its artifact, precision,
resource envelope, token limits and domain-training limitations.

The earlier schema-2 research profile could select the deterministic CPU
typed-feature router while keeping the pinned local reasoner:

```json
{
  "schema_version": 2,
  "decision_provider": "typed-feature",
  "inference": {
    "enabled": true,
    "reasoning_model": "qwen3.8:27b",
    "reasoning_digest": "22130167c4c20e20c7b71454612966ca8e8171e9b3cc8ab6ce8aa6cbfec79643"
  }
}
```

Legacy GPU requests degrade deterministically. This historical schema-2 example
does not describe the managed v3 profile. The typed router is a replaceable
challenger, not a qualified product default or a proven diagnostic replacement for Laya.
It ranks registered read-only probes and at most 64 attention pages; its response
reports the full page denominator and how many pages were not ranked. Complete
observations remain in the redacted store. Qualify latency and useful-probe
quality on the same frozen requests and held-out incidents before promotion.

## Resource and trust boundaries

- The old Qwen3.5 runner was unloaded with the user's explicit authorization.
  No model weights or unrelated applications were removed.
- Historical Qwen admission checks preserved artifact-sized GPU headroom plus
  a 3 GiB reserve. An unambiguous already-resident pinned instance with exact identity,
  digest, context, expiry, and full GPU placement uses a 1 GiB free-VRAM floor
  for subsequent calls. CPU warm reuse applies the same pinned identity checks.
  This is an admission rule, not a GPU usage cap. Laya has a separate 5 GiB available-host-RAM gate before
  each cold worker start or restart, plus a CUDA free-VRAM check at model load.
  Unknown or insufficient capacity is declined instead of evicting another
  workload. These are admission floors, not hard running memory caps or claims
  about a warm worker under later resource pressure.
- Historical joint runs shared the measured host. Follow-up resource samples
  included model activity and were not an unloaded performance baseline.
- Model artifacts, endpoint locality, response schemas, known evidence/probe IDs,
  case/version/correlation and deadlines are checked independently of model text.
- Laya relevance is not a diagnostic probability. Qwen's prose and hypotheses
  remain advisory. Narrow deterministic observation checks do not prove general
  root cause or authorize a repair.

## What has actually been checked

Six synthetic scenarios used real Qwen inference to exercise schema compliance,
citations, uncertainty, contradictions and hostile captured text. They are model
protocol checks, not an accuracy benchmark. Earlier host investigations exercised
the pair, collection, resource pressure, details, persistence and UI.
Failures, including context rejection and low-VRAM fallback, remain part of the
record. Current acceptance results are in [the build record](APPLICATION_BUILD.md).

A read-only Windows case on 2026-09-23 with the explicit pinned Laya CUDA and
Qwen3.8 27B profile completed four ready Laya calls and six ready Qwen calls
over two rounds, without model fallback. The case took about 82.6 seconds and
ended `budget_exhausted` by its round limit with no measured game workload or
supported 12 FPS cause. This validates repeated local-provider wiring on this
desktop, not diagnostic accuracy or laptop suitability. The preceding live case
had exposed two runtime defects: an overstrict warm-GPU admission check and a
Qwen response citing the same evidence as support and contradiction. The
former now validates Ollama's resident allocation separately from artifact
bytes; the latter conservatively retains the citation only as contradiction.

General Windows diagnostic quality, Laya action-selection quality, calibration,
and fine-tuning labels still require reviewed held-out incidents. Neither upstream
benchmark claims nor successful local inference establish those properties.
