# Local model selection

The current pair is **Laya typed decisions 0.3.5 + standard Qwen3.8 27B Q4_K_M**.
These are replaceable adapters, not permanent architecture or diagnostic-quality
claims. There is no cloud fallback, paid API, automatic model download, or training
job in the investigation path.

## Why this pair and configuration

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

An 8K context and 1,200 output-token ceiling bound local latency and preserve room
for the fast brain. Advertised maximum model context is not the right allocation
for a shared 24 GB GPU. Thinking is disabled in this measured structured-output
profile; changing that policy requires another latency/output qualification.
Input admission counts the actual tokenizer, schema and framing reserve before
HTTP. Output-length termination is rejected, not accepted as a complete answer.

For a long-running, explicitly configured local edition,
`systemsense serve --prewarm-laya --prewarm-reasoning` warms both brains before accepting cases.
The reasoning warmup verifies the pinned local digest, current resource admission
and an [Ollama empty-message load response](https://github.com/ollama/ollama/blob/main/docs/api.md)
with a positive bounded `keep_alive`; it requests no generated diagnosis and
does not unload another model. Each startup result is reported independently as
ready or degraded, and the case path still falls back safely if a later request
misses its deadline. Prewarming is opt-in because it consumes startup time and
holds RAM/VRAM while the service is idle; its benefit and cost must be measured
separately from a warm case's end-to-end latency.

Laya supplies repeated ordinal attention over exact fact pages and registered
probes. Its CPU broad-request latency was not suitable for the fast-brain role, so
the selected host profile uses a separately pinned CUDA worker with bounded
batches. See [Laya qualification](LAYA_QUALIFICATION.md) for its artifact, precision,
resource envelope, token limits and domain-training limitations.

An optional schema-2 profile can instead select the deterministic CPU typed-feature
router while keeping the pinned local reasoner:

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

This profile starts no Laya worker. The typed router is a replaceable challenger,
not a qualified product default or a proven diagnostic replacement for Laya.
It ranks registered read-only probes and at most 64 attention pages; its response
reports the full page denominator and how many pages were not ranked. Complete
observations remain in the redacted store. Use `--prewarm-reasoning` alone if
reasoner prewarming is wanted for this profile. Qualify latency and useful-probe
quality on the same frozen requests and held-out incidents before promotion.

## Resource and trust boundaries

- The old Qwen3.5 runner was unloaded with the user's explicit authorization.
  No model weights or unrelated applications were removed.
- Runtime admission preserves a 2 GiB between-request GPU reserve and system RAM
  reserve for Ollama. Laya has a separate 5 GiB available-host-RAM gate before
  each cold worker start or restart, plus a CUDA free-VRAM check at model load.
  Unknown or insufficient capacity is declined instead of evicting another
  workload. These are admission floors, not hard running memory caps or claims
  about a warm worker under later resource pressure.
- Both brains share the measured host. Follow-up resource samples include their
  activity and are not an unloaded performance baseline.
- Model artifacts, endpoint locality, response schemas, known evidence/probe IDs,
  case/version/correlation and deadlines are checked independently of model text.
- Laya relevance is not a diagnostic probability. Qwen's prose and hypotheses
  remain advisory. Narrow deterministic observation checks do not prove general
  root cause or authorize a repair.

## What has actually been checked

Six synthetic scenarios used real Qwen inference to exercise schema compliance,
citations, uncertainty, contradictions and hostile captured text. They are model
protocol checks, not an accuracy benchmark. Real host investigations exercise
the complete pair, collection, resource pressure, details, persistence and UI.
Failures, including context rejection and low-VRAM fallback, remain part of the
record. Current acceptance results are in [the build record](APPLICATION_BUILD.md).

General Windows diagnostic quality, Laya action-selection quality, calibration,
and fine-tuning labels still require reviewed held-out incidents. Neither upstream
benchmark claims nor successful local inference establish those properties.
