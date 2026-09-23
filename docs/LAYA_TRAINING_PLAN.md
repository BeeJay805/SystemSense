# Local-teacher distillation plan for Laya

Status on 2026-09-23: **stop before training**. No real, independently reviewed
Windows next-probe labels have been admitted, no trainable export exists, and no
student checkpoint is qualified. This document is an execution plan, not approval
to collect private data, start a teacher or trainer, use the active GPU, or deploy
a model. [The existing fine-tuning decision](LAYA_FINETUNING.md) contains the
research rationale; this page names the gates and artifacts for a future run.

## Outcome and boundary

The proposed student ranks registered, read-only next measurements from the
frozen information visible at decision time. It cannot diagnose a root cause,
choose an arbitrary command, authorize a probe, or repair Windows. The
deterministic coordinator continues to own candidate eligibility, budgets,
permissions, deadlines, provenance, and fallback. The first question is whether
learning improves useful-probe selection on real reviewed cases at an acceptable
laptop cost, not whether a model can produce a plausible explanation.

The external architecture audit's F27 and F30 findings identify the relevant gap:
synthetic coordinator episodes exercise contracts but do not establish diagnostic
superiority (F27), and persisted history is not yet verified experience or a
trained Windows test-selection policy (F30). Keep diagnosis correctness distinct
from recovery and from ranking utility throughout the study.

## What exists now

- `DecisionSnapshotRepository` freezes a typed request before probe execution,
  stores its exact request and preworker Laya projection digests, and can link
  later executions. Links prove that a probe ran after a snapshot, not that it
  was useful or chosen by Laya.
- [`attention_labels.py`](../src/systemsense/evaluation/attention_labels.py)
  defines version-2, non-synthetic expert labels with observed outcomes and
  pseudonymous split keys. It is a schema, not an admitted corpus.
- [`teacher_drafts.py`](../src/systemsense/evaluation/teacher_drafts.py) permits
  exact-model local Ollama drafts only after review of the exact prompt. It
  requires an exact permutation of up to 20 candidate IDs per window and keeps
  drafts in a `local_model_weak` lane. Windows are separate; no global ranking
  across them is implied.
- [`training_admission.py`](../src/systemsense/evaluation/training_admission.py)
  checks persisted labels, linked outcomes, group splits, reviewer and consent
  receipts, retention, and exact plaintext privacy review. Its examples contain
  only preworker inputs and explicitly remain `trainable=false`. A corpus digest
  binds the complete reviewed export and receipt metadata; it is not proof of
  reviewer identity or token parity.
- The pinned runtime profile is `laya==0.3.5`, a specific model revision and
  weight digest in [`laya_runtime.py`](../src/systemsense/inference/laya_runtime.py).
  The runtime admits CPU float32 and separately gated CUDA float16, batches at
  most 20 candidates, and records hash-only worker presentations and cache
  origins. The [upstream Laya model card](https://huggingface.co/convaiinnovations/laya-typed-decisions)
  describes the typed-decisions checkpoint; its results do not qualify Windows
  cases. The hashes do not expose or verify the model's actual token tensor.

## Gate sequence and reviewable artifacts

1. **Register cases and outcomes.** Freeze the request before selection. Keep
   source observation time, case-open time, collection time, and review time
   distinct. Record each registered probe's actual post-snapshot result,
   failures, denials, truncation and limitations. A reviewer may label only an
   observed successful result useful or uninformative; an unrun probe remains
   unknown. Preserve abstention and disagreement. Independently verify fault
   injection or affected-task outcome; a model explanation and a probe return
   code are not ground truth. Artifact: case-scoped request, execution/evidence
   links, independent outcome record, and immutable review history.
2. **Authenticate and protect the corpus.** Use a real local reviewer registry,
   an independently checked review receipt for the exact label, per-case consent
   for local training/export and retention, and human review of the exact
   plaintext teacher prompt and final example. Redact secrets, personal paths,
   identifiers and source text before any teacher call. Keep private payloads on
   the approved local host with access controls and deletion records. The
   deterministic secret detector is supplementary. Artifact: receipts bound to
   payload digests, retention decision, and content-addressed export manifest;
   no public or cloud export.
3. **Freeze groups before generating drafts.** Assign train, development and a
   sealed final test by entire case, machine, application/version and fault
   family. Deduplicate paraphrases, repeated snapshots, VM clones and
   near-identical injected faults across groups. Include healthy, external,
   denied, ambiguous and multi-fault cases. Re-run split-overlap and origin
   checks after every refresh. Artifact: versioned split manifest, source and
   family counts, adjudicated-candidate coverage, and a list of excluded cases.
   The final test stays unread during teacher selection and tuning.
4. **Qualify a local weak teacher on training groups only.** Prefer the pinned
   [Qwen3.8-27B](https://huggingface.co/Qwen/Qwen3.8-27B), already selected for
   the local deep-brain profile, if its measured memory, throughput, and
   interference fit the approved host. The repo's
   [Qwen3.5-4B](https://huggingface.co/Qwen/Qwen3.5-4B) format pilot is a
   cheap comparison, not a reason to default to the older model; evaluate a
   smaller teacher only if 27B fails the resource gate or a reviewed comparison
   shows equivalent label utility. Bind each artifact digest, quantization,
   runtime, prompt version, generation setting and privacy receipt. Measure
   exact-ID format validity, useful-probe agreement, false negative claims,
   abstention, disagreement with reviewers, throughput, peak RAM/VRAM and
   prompt leakage on real reviewed training/development examples. Model cards
   establish availability, not Windows ranking quality. Drafts can prioritize human
   review; they never become expert labels or held-out targets. Artifact:
   complete draft/reviewer comparison with failures and all windows retained.
5. **Prove exact student input parity.** Before changing any export to trainable,
   bind its corpus digest to the pinned Laya package, model source, tokenizer,
   config, SystemSense adapter/worker versions, and every exact example. Compare
   the exported training serializer against the actual installed Laya sequence
   builder for input IDs, attention masks, marker positions/masks, question
   type/order, state fitting, all truncation branches and cache origins. Test
   long text, candidate-window boundaries, missing evidence, and cached and
   uncached paths. A changed source hash, incomplete coverage or one mismatch
   rejects the whole candidate export. The existing three synthetic-case parity
   check and hash-only trace are useful probes of plumbing, not this proof.
   Artifact: per-example comparison result and corpus-bound parity report with
   source hashes; keep sensitive tensors local.
6. **Pre-register the experiment.** Freeze split IDs, primary metric, safety
   floor, non-inferiority margin, uncertainty method, seeds, optimizer and
   loss, stopping rule, source/runtime hashes and resource ceiling before any
   fit. Compare keyword, typed-feature and unchanged pinned Laya baselines on
   identical frozen requests. If and only if gates 1-5 pass, the first student
   candidate is a frozen encoder with the actual Laya custom head/scorer;
   pairwise useful-over-observed-uninformative loss masks unknown candidates.
   Teacher soft targets may be tried on training data as a separate ablation
   after teacher bias review. Try encoder LoRA plus the custom head only if
   head-only is safe but misses the utility floor. A compact typed-feature or
   learned ranker remains the laptop challenger. Do not substitute a generic
   sequence-classification head for Laya's custom decision head.
7. **Evaluate before any promotion.** Use
   [`evaluate_attention_replay`](../src/systemsense/evaluation/attention_replay.py)
   for useful-probe recall@1/@3, negative-control top-k selection, unsupported
   IDs, abstention, adjudicated coverage and truncation, with case-group
   uncertainty intervals. Never score unknown candidates as negatives or claim
   replayed probe time is a counterfactual saving. Independently scored matched
   fault episodes must measure supported diagnosis, time to useful evidence,
   false confidence, healthy/external controls and all failed runs. Hold out
   whole incidents, machines, versions and fault families; use the sealed test
   once for the final candidate and report denominators. Qualify rollback and
   side-by-side shadow evaluation before a live selector is considered.

## Speed, quality and resource floors

The proposed ordinary-laptop gate is a complete warm attention cycle at p95
at most **3 seconds** on representative 8 GiB CPU and 16 GiB iGPU laptops,
without silently dropping evidence or candidates. Measure cold startup, warm
p50/p95, peak RAM/VRAM, power, foreground interference, failures, deadline
fallback, and coverage on the same frozen requests. This is a target, not an
observed laptop result. The repo's desktop rehearsal took about 106 seconds
for a 54-preview/17-probe warm CPU request and about 3.03 GiB peak owned
process-tree RSS; its CUDA FP16 4090 measurement is not a laptop substitute.

Quality must be at least non-inferior to both deterministic features and pinned
Laya on the preregistered held-out metric and margin, without increased unsafe
or overconfident answers. Report each fault family and healthy, external and
denied cohorts so pooled gains cannot conceal misses. If the reviewed corpus is
too small or narrow to estimate these comparisons, record **not qualified**.
The deterministic provider remains the fallback when a model misses a deadline,
fails, is unavailable, or exceeds memory admission.

The existing resource envelope is only a planning hypothesis for roughly
30,000 *genuinely reviewed* question instances, four FP16 epochs, sequence
length at most 1,024 and microbatches of 1-4 on an otherwise idle RTX 4090:
frozen encoder plus custom head **6-12 GiB and 2-8 hours**; selected encoder
LoRA plus head **12-22 GiB and 4-16 hours**. These are not measured training
results or promised throughput. A permitted future 100-step pilot must measure
actual VRAM, throughput, finite loss, checkpoint/reload parity and device
interference before a full run. Do not interrupt unrelated GPU work.

## Stop conditions now

No trainer is to start under this plan. The immediate useful work is reviewed
real-case collection, authenticated consent/privacy providers, exact
corpus-bound worker-token parity, teacher-versus-reviewer audit, split
qualification, and independent outcome oracles. Any missing receipt, stale or
truncated input, unauthenticated source, split overlap, unverifiable worker
sequence, unsupported probe, or insufficient held-out evidence stops admission.
Training, checkpoint promotion and deployment require a separate decision after
these artifacts exist and are inspected.
