# Local-teacher distillation plan for Laya

Status on 2026-09-23: **stop before training**. No real, independently reviewed
Windows next-probe labels have been admitted, no trainable export exists, and no
student checkpoint is qualified. This document is an execution plan, not approval
to collect private data, start a teacher or trainer, use the active GPU, or deploy
a model. [The existing fine-tuning decision](LAYA_FINETUNING.md) contains the
research rationale; this page names the gates and artifacts for a future run.

## Decision for the first student experiment

Keep the pinned Laya 0.3.5 checkpoint as the reproducible fast-brain baseline.
The first trained candidate, once the gates below pass, will keep its encoder
frozen and fit Laya's **actual option-scoring head** to rank registered,
case-bound investigation references. The training objective is masked
pairwise preference between *observed useful* and *observed uninformative*
choices under the same pre-result state; an unrun or failed choice has no
utility target. Calibrate on a separate development split. Try encoder LoRA
only if this smaller fit passes safety checks but misses the predeclared
utility floor. A typed-feature ranker remains a laptop-size challenger, and
no student replaces the deterministic admission policy.

Use a local Qwen teacher to propose questions, candidate permutations, and
disagreement examples **only on consented training groups**. The teacher's
answers remain weak drafts. The user's preferred primary teacher candidate is
the pinned, standard Qwen3.8-27B artifact, run separately from Laya training;
Qwen3.5-4B is only a cost/latency challenger, not an automatic downgrade. Compare
both with deterministic/unchanged-Laya baselines on the same frozen decisions;
admit bulk drafts only after reviewer agreement, format validity, coverage,
abstention, latency, and resource cost are measured. The configured Qwen3.8
endpoint was unavailable during the September 24 preflight, and the default
Ollama inventory contains abliterated 27B variants; neither is silently
substituted for a qualified teacher. No local teacher has been selected or
run on a real case.

The [upstream model card](https://huggingface.co/convaiinnovations/laya/blob/main/README.md)
now describes Laya 0.3.20 runtime fixes, including CUDA fast-path concurrency
and fallback changes; it says the checkpoints are unchanged. The earlier
0.3.18 finding is historical. The newer runtime is a migration candidate,
not an automatic dependency upgrade or Windows-quality evidence.
The pinned 0.3.5 runtime remains the reproducible baseline until the newer
runtime passes compatibility, actual worker-input/output parity, resource,
and matched workload checks. Before any fit, pin the exact source, tokenizer,
weight, and worker-input versions. See the
[upstream training documentation](https://github.com/NandhaKishorM/laya#fine-tuning).

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
  pseudonymous split keys. It is a schema, not an admitted corpus. Its
  `RegisteredProbe` and replay scorer identify one candidate per probe ID;
  neither can label which target or incident window of that probe was better.
- [`candidate_attention_labels.py`](../src/systemsense/evaluation/candidate_attention_labels.py)
  adds a separate version-3 *non-admitting* review shape keyed by opaque
  candidate ID. It preserves the offered target/window manifest, a pre-result
  discriminating question, observed utility, and unrun-as-unknown. Its
  reviewer and consent receipts remain unauthenticated claims and every record
  is `trainable=false`; it does not upgrade historical probe-ID labels.
- [`teacher_drafts.py`](../src/systemsense/evaluation/teacher_drafts.py) permits
  exact-model local Ollama drafts only after review of the exact prompt. It
  requires an exact permutation of up to 20 candidate IDs per window and keeps
  drafts in a `local_model_weak` lane. Windows are separate; no global ranking
  across them is implied.
- [`teacher_queue.py`](../src/systemsense/evaluation/teacher_queue.py) pages
  arbitrarily many draft windows, claims one job at a time without locking the
  database during inference, records safe failure/retry state, and persists only
  ID/hash metadata and weak drafts. It requires an external exact-prompt privacy
  and case-consent authorizer; none is supplied by this module. No real teacher
  run or reviewed corpus follows from its fixture tests.
- [`training_admission.py`](../src/systemsense/evaluation/training_admission.py)
  checks persisted labels, linked outcomes, group splits, reviewer and consent
  receipts, retention, and exact plaintext privacy review. Its examples contain
  only preworker inputs and explicitly remain `trainable=false`. A corpus digest
  binds the complete reviewed export and receipt metadata; it is not proof of
  reviewer identity or token parity.
- [`split_ledger.py`](../src/systemsense/evaluation/split_ledger.py) keeps
  versioned case, machine, application/version, and fault-family split-group
  assignments across separate 500-label shards. Its full manifest digest is
  metadata-only; it does not authenticate labels, supply consent, or turn the
  non-trainable exports into training examples. A future corpus assembler must
  require this ledger and verify its manifest after every shard.
- The pinned runtime profile is `laya==0.3.5`, a specific model revision and
  weight digest in [`laya_runtime.py`](../src/systemsense/inference/laya_runtime.py).
  The runtime admits CPU float32 and separately gated CUDA float16, batches at
  most 20 candidates, and records hash-only worker presentations and cache
  origins. The [upstream Laya model card](https://huggingface.co/convaiinnovations/laya-typed-decisions)
  describes the typed-decisions checkpoint; its results do not qualify Windows
  cases. The hashes do not expose or verify the model's actual token tensor.

The current managed GPU profile admits pinned CUDA Laya with deterministic
reasoning; it does not concurrently admit Qwen. A legacy pinned Laya and
Qwen3.8-27B pair exists for review, but its GPU request degrades to the
deterministic mode under the current resource policy. Neither profile
qualifies Windows diagnostic quality or everyday-laptop use. The standard
Qwen3.8-27B artifact is the preferred *weak-teacher candidate* for later
reviewed comparison; Qwen3.5-4B is a smaller cost challenger, not a gold-label
source.
No student or compact laptop fast brain has been selected. Keep these roles
separate when comparing latency, VRAM, and useful-probe quality.

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
   A future versioned label or linked review record must capture each proposed
   test's pre-result question, target/window, expected discriminating outcomes,
   and permissible read-only probe. After execution, a blinded expert reviews
   whether the *observed* result distinguished competing hypotheses or changed
   the next justified action. Merely returning new facts is insufficient.
   Unrun choices remain unknown, never negative. Observational logs cannot
   establish what an unchosen test would have shown. If multiple safe
   alternatives must be compared, use a separately consented, randomized lab
   protocol with the same pre-result state and independent oracle.
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
   Before training target/window routing, complete the partially implemented
   [case-scoped candidate identity](architecture/candidate-identity-f01.md)
   through frozen requests, labels, outcomes, replay, worker traces and split
   manifests. The initial process-target routing slice does not establish
   target/window training parity. Existing probe-ID labels may benchmark
   probe-ID routing only; never infer a target/window label or merge the two
   schemas by probe ID.
4. **Qualify a local weak teacher on training groups only.** Start the reviewed
   comparison with the pinned standard
   [Qwen3.8-27B](https://huggingface.co/Qwen/Qwen3.8-27B), the user's preferred
   large local teacher, and the smaller
   [Qwen3.5-4B](https://huggingface.co/Qwen/Qwen3.5-4B) as a cost challenger.
   The earlier synthetic format pilot showed 4B used less VRAM, but did not
   establish which model selects useful Windows tests. Neither the pilot
   nor model size establishes ranking quality, so no bulk teacher is selected
   until a reviewed training/development comparison passes. Bind each artifact
   digest, quantization,
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

   The opt-in [`laya_exact_batch_parity.py`](../benchmarks/laya_exact_batch_parity.py)
   checks one explicitly supplied, privacy-reviewed *worker-boundary* probe
   batch against the pinned installed builder. It compares exact token IDs,
   masks, marker positions, order and truncation, and emits only digests and
   mismatch names with `trainable=false`. The current snapshot stores only
   preworker inputs, so it cannot supply this payload yet. Cached batches fail
   closed until a durable, exact origin is linked; a receipt digest is bound
   but its authorization is not authenticated by this offline check. The
   supplied trace and snapshot identifiers are checked for internal consistency,
   not independently read back from the case store. A passing single-batch
   report is not corpus parity or training admission.

   The version-1 [training loader](../benchmarks/laya_training_loader.py)
   additionally requires a complete ordered capture manifest bound to a
   reviewed-export corpus digest. It rejects missing/reordered candidates,
   checks every supplied batch through the exact parity verifier, and
   reconstructs tensor-ready inputs with `trainable=false`. Its synthetic
   tests validate loader wiring; there is no authenticated real worker-capture
   corpus, so no corpus parity or training admission has passed.
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
For each laptop cohort, preserve CPU/iGPU and driver identity, RAM, OS build,
power mode, AC/battery state, thermal state and competing workload. Measure
cold load and first decision separately from sustained warm decisions. Run
the frozen 54-preview/17-probe *synthetic coverage stress* plus smaller
representative real cases with identical candidate visibility across Laya,
deterministic and compact challengers. Include parallel deep-brain activity
where that deployment is possible; report model residency, process-tree peak
memory, energy or battery drain, and foreground application latency. Missing
coverage or an evicted workload is a failed run, not a faster result.

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
