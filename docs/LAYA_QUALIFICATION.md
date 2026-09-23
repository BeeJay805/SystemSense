# Laya local runtime qualification

SystemSense uses Laya only as a replaceable advisory attention ranker. Trusted
software supplies the registered probe catalog, permissions, costs, stable evidence
IDs, deadlines, and every response envelope. Laya cannot issue commands, choose an
arbitrary path or URL, or turn its scores into diagnostic confidence.

## Pinned source and artifact

- Package: `laya==0.3.5`, Apache-2.0.
- PyPI wheel SHA-256:
  `4c57f64cbaf893bb5c7b4affddc2bf21a819f55df51941689f11868583be2903`.
- Reviewed upstream source revision:
  `573e5b62696ba441230cd6be71d593331b5d23af`.
- Checkpoint: `convaiinnovations/laya-typed-decisions` at revision
  `f9ab0b228f0fc0f14d873dbc99038f135c2da1b2`.
- `model.safetensors`: 842,609,220 bytes, SHA-256
  `4fa56de72383a9d3efa9cfa78955733c81b9fc8067a587ca4beb82c78107a24e`.
- Complete selected checkpoint files: approximately 846 MB.
- Qualified CUDA runtime: Python 3.12, PyTorch `2.10.0+cu128`, Transformers
  `5.17.0`, CUDA 12.8. The CPU wheel is a separate explicit installation choice.

Primary references are the upstream [repository](https://github.com/NandhaKishorM/laya),
[benchmark report](https://github.com/NandhaKishorM/laya/blob/main/BENCHMARKS.md),
[package metadata](https://github.com/NandhaKishorM/laya/blob/main/pyproject.toml),
[license](https://github.com/NandhaKishorM/laya/blob/main/LICENSE), and
[typed-decisions model card](https://huggingface.co/convaiinnovations/laya-typed-decisions).

## Reproducible installation

Installation is a separate, explicit networked setup action. Runtime startup is
offline and never downloads or updates a package or model.

```powershell
uv sync --frozen --extra local-models
.\scripts\install-laya-runtime.ps1 `
  -PythonPath C:\path\to\python.exe `
  -Device cuda
```

The installer refuses to overwrite an existing target, uses an isolated virtual
environment under `%LOCALAPPDATA%\SystemSense\runtimes\laya-0.3.5`, pins the
package and CUDA wheel versions, downloads only the admitted checkpoint revision,
verifies weight size and SHA-256, and writes `INSTALL-MANIFEST.json`. Use
`-Device cpu` to install the official CPU PyTorch wheel instead. A profile may be
enabled only after its paths and manifest validate.

## Measured behavior on this host

Host measurements used an RTX 4090 and two CPU threads. They are runtime evidence,
not diagnostic-accuracy evidence.

| Placement and workload | Measured result |
| --- | --- |
| CPU, small cold load plus 1 evidence and 3 probes, before final hash gate | 29.378 s |
| CPU, same small request warm | 1.205 s |
| CPU, warm 100 evidence fragments plus 25 probes | 65.820 s |
| CPU broad peak process-tree working set | 2,717.6 MiB |
| CUDA, small cold load | 13.540 s |
| CUDA, warm 100 pages plus 25 probes, batch 4 | 1.063 s |
| CUDA, exact cached repeat | 0.00149 s |
| CUDA plus resident Qwen 27B 8K, cold broad request, before final hash gate | 14.815 s |
| Co-resident GPU baseline / peak / idle-after-request | 19,788 / 22,718 / 21,920 MiB used |
| Co-resident free VRAM at peak / idle-after-request | 1,846 / 2,219 MiB |
| Final pre-load 842 MB weight size and SHA-256 verification | 0.96 s |
| CUDA FP32-parameter mode, idle allocated / request peak allocated | 1,607 / 2,346 MiB |
| CUDA FP16-parameter mode, idle allocated / request peak allocated | 835 / 874 MiB |
| CUDA FP32 / FP16, warm 100-item ranking | 2.062 / 1.269 s |

The co-resident result passes the configured 2,048 MiB between-request admission
floor by only 171 MiB. It therefore supports the measured 8K reasoner profile, not
a 16K profile or an unrestricted concurrent workload. CUDA batch 4, explicit
free-VRAM admission, per-batch `torch.cuda.empty_cache()`, cancellation, and owned
worker shutdown are part of the admitted configuration. Final cold startup also
rehashes the weight file before deserialization; the separately measured 0.96 s
integrity check is not folded into the earlier cold figures. CPU remains a correct
fallback but is not a practical wide-attention fast path.

Cold worker starts and restarts now also require at least 5 GiB of available host
RAM, whether placement is CPU or CUDA. This rounds the observed 2.72 GiB CPU
process-tree peak plus a 2 GiB host reserve upward. An unknown reading fails
closed; the decision provider labels its deterministic fallback. This is a
conservative start gate, not a hard memory limit, a warm-request check, or a
measurement on an ordinary laptop.

The checkpoint stores all 206 tensors as FP16, but upstream constructs the model
in FP32 before copying those tensors and uses BF16 autocast only for CUDA forward
passes. SystemSense therefore offers an explicit CUDA-only `precision: "float16"`
profile mode; `float32` remains the default. On a fixed 100-item, 25-batch ranking
A/B, FP16 reduced idle allocated VRAM by 772 MiB and request peak allocation by
1,472 MiB. Mean absolute score drift was 0.000904 and the maximum was 0.0043;
there were no pairwise order reversals where the FP32 score gap was at least 0.005.
The 60-of-64 top-set overlap reflects changes among smaller near-ties, so this is
resource and ordinal-parity evidence, not Windows attention-accuracy evidence.
A real isolated FP16 worker then covered 100 of 100 pages in 25 of 25 batches in
17.431 seconds cold, including integrity verification and model load, with zero
instruction or state truncation. Its warm model pass measured 1.269 seconds.

## Coverage and token semantics

All supplied evidence fragments are attempted in bounded batches until the
attention-phase deadline. Results report fragments considered, complete and partial
pages, cache hits, omitted state fields/items, and whether deadline coverage was
limited. Unchanged pages are cached by goal, hypotheses, reference mechanisms, and
relationships grounded by that evidence ID; unrelated new edges do not invalidate
them.

Laya's checkpoint has a 1,024-token sequence limit and retains the beginning of
state. The worker therefore uses the actual pinned tokenizer to:

1. split long evidence instructions into complete internal questions with no token
   clipping;
2. fit state before inference, requiring the full bounded goal, preferred probes,
   best fact, one complete graph relation, and one prior hypothesis;
3. admit optional graph/context items only while the serialized state fits; and
4. report original/presented token counts and explicit omission counts.

An actual dense check presented a 701-character JSON fragment in three complete
instruction chunks with zero clipped instructions. A separate oversized 4,128-token
state presented 763 tokens with zero state truncation, while explicitly reporting
one omitted field and ten omitted list items.

## Qualification boundary

The typed checkpoint was trained on four synthetic workflow families, not Windows
investigations. Upstream reports 0.766 accuracy on that specialist benchmark but an
expected calibration error of 0.213; the base typed model is below the benchmark's
majority baseline. The model card warns that behavior outside the four workflows may
match or underperform the base model. Scores are therefore ordinal attention signals,
never probabilities of a diagnosis.

This qualification establishes artifact identity, offline/local execution, bounded
protocol behavior, coverage accounting, cancellation, token visibility, lifecycle,
and measured host resource fit. It does **not** establish Windows evidence-ranking
accuracy, causal reasoning quality, diagnostic calibration, or production readiness.
Those require held-out investigations with recorded provenance and deterministic
baseline comparisons.
