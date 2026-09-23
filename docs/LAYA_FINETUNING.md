# Laya fine-tuning decision and admission plan

Status: **proposed experiment design; training and deployment not yet
qualified** (2026-09-23). The current product should continue to use the
deterministic decision provider when local attention cannot meet its deadline.
The fast brain chooses where to look next; it does not diagnose, authorize a
probe, or repair Windows.

Implemented: live next-probe requests are frozen before the fast
provider runs and persisted after its call, before any probes execute, as
private, case-scoped `decision_snapshots` rows. They include the
canonical typed request digest, ordered manifest references and digests, and a
versioned Laya *preworker* projection of state, evidence previews, and eligible
candidate order. A separate optional, hash-only worker trace records the
fitted `agent.predict` arguments and inferred token budgets per microbatch,
including cache origins. It is not a byte-for-byte dump of the upstream model's
internal token tensors and does not by itself establish that an example is
trainable. Capture failures warn
but do not stop an investigation, the optional database write has a short lock
wait, and attention-only refreshes are excluded. The replaceable decision
provider receives a deep copy, so its mutation cannot rewrite the frozen input.
`teacher_drafts` can ask a pinned local Ollama model for a bounded ranking on
that preworker view. It records only IDs/hashes and weak-label provenance;
every generation requires a privacy review bound to the exact prompt, including
synthetic exercises. The
deterministic detector catches common secrets but is not exhaustive. No draft
has been promoted to an expert label, no training set exists, and the current
snapshot retention/export policy remains a release gate.

Each persisted post-decision probe execution is now linked to its snapshot
atomically with the execution and evidence. This is an observed-run link,
**not** evidence that Laya selected the probe or that it was informative.
Unrun candidates remain unknown, including for negative labels. The guarded
training-export preparation checks persisted label/outcome consistency, split
separation, reviewer authentication receipts, per-case local-training consent,
retention, and plaintext privacy review of the exact final example. It has no
allow-all authorizer and currently emits `trainable=false` preworker inputs.
The capture and hashes cannot authenticate a reviewer or an injected fault.

A SystemSense-owned copy of the pinned standard Qwen3.8-27B Q4_K_M artifact was
hash-verified and invoked on one synthetic two-probe smoke case through an
isolated loopback Ollama server. The final privacy-bound smoke returned a
schema-valid weak ranking in 6.2 seconds. The server was stopped after the test. This checks local teacher
plumbing only, not ranking quality or end-to-end diagnosis latency.

An isolated pilot compared official Qwen3.5-4B Q4_K_M with the owned 27B.
On one two-candidate synthetic prompt, 4B omitted a candidate under the broad
JSON schema. An exact-count, exact-ID, unique-item schema made three warm 4B
calls format-valid at 0.383–0.408 seconds; three warm 27B calls were valid at
0.555–0.561 seconds. Sampled GPU use peaked around 5.2 GiB for 4B versus
19.3 GiB for 27B. These tiny, order-sensitive tests establish neither ranking
quality nor production latency. Both isolated servers were stopped. Weak
teacher drafts now use exact candidate schemas and disjoint 20-candidate
windows, each with its own prompt digest and privacy review; no cross-window
global order is inferred.

The 4B blob SHA-256 in the isolated store is
`81fb60c7daa80fc1123380b98970b320ae233409f0f71a72ed7b9b0d62f40490`;
the tested portable Ollama 0.32.15 archive was checksum-verified. The local
teacher always requires the exact configured model ID and digest. The measured
latencies were `think=false`, temperature zero, 4,096-token context, 256-token
output cap, one approximately 468-token prompt, and an RTX 4090; they must not
be extrapolated to a 20-probe/20-evidence production request or an ordinary
laptop. The 4B cold load was about 22.6 seconds in the initial pilot, so an
always-cold teacher is not a fast bulk path.

A separate installed-profile CUDA Laya smoke on synthetic input returned one
considered evidence page, two considered probe candidates, and two hash-only
worker presentations. An initial live attempt exposed a false token-count
assumption: removing a serialized field can change tokenizer merges and add a
token. The corrected contract passed the same live call. This validates basic
trace plumbing, not upstream tensor parity or ranking quality.

An opt-in, read-only pinned-Laya serializer comparison then passed on three
synthetic worker cases (nine questions) and two direct truncation boundary
vectors. It compared input IDs, attention masks, marker positions and masks,
question type and order against installed Laya 0.3.5; six deliberate mutations
were detected. The report contains hashes and counts, not case text or weights.
This is sampled parity against the local installation, **not** universal parity,
an independent source-authenticity proof, reviewer authorization, or permission
to flip `training_admissible` to true.

## Decision

Train an *experimental* Windows next-investigation ranker only after collecting
real, independently reviewed probe outcomes. Use local Qwen3.5-4B as the first
bulk weak-draft **candidate** because its warm format-valid pilot used far less
VRAM; compare Qwen3.5-9B if 4B misses quality gates and use Qwen3.8-27B for
sampled disagreement review. None creates ground truth. First compare the
existing keyword and typed-feature providers,
unchanged pinned Laya, and a frozen-encoder/new-head candidate. Try encoder LoRA
only if the head cannot meet the pre-registered quality gate. Keep a smaller
typed-feature or compact learned ranker in contention for ordinary laptops.
Neither a model's parameter count nor its upstream benchmark makes it the right
fast brain for Windows.

This is a ranking problem over trusted, registered read-only probes and redacted
evidence pages, not open-ended command generation. The deterministic layer
continues to validate candidate IDs, budgets, permissions, provenance, evidence
coverage, and deadlines. The deep reasoner is separate and may redirect
investigation. No cloud teacher or inference path is part of this stage.

## Why this order

The pinned `laya==0.3.5` typed-decisions checkpoint is a 421M-parameter
ModernBERT-large encoder plus a **custom** two-layer Transformer decision head,
type embedding, marker scorer, and action head. It was tuned for four synthetic,
non-Windows workflows. Its [model card](https://huggingface.co/convaiinnovations/laya-typed-decisions)
warns about out-of-domain behavior and uncalibrated probabilities. The actual
SystemSense [adapter](../src/systemsense/decision/laya.py) and
[worker](../src/systemsense/inference/laya_worker.py) serialize bounded evidence
previews and score typed relevance questions. Training must reproduce that exact
model-visible representation; generic `AutoModelForSequenceClassification`
recipes would omit Laya's decision head and marker semantics. The pinned
[upstream model implementation](https://raw.githubusercontent.com/NandhaKishorM/laya/573e5b62696ba441230cd6be71d593331b5d23af/laya/common.py)
defines the head.

Existing [qualification](LAYA_QUALIFICATION.md) establishes runtime identity
and coverage, **not** Windows decision quality. On this desktop, a complete
54-preview/17-probe warm CPU pass took about 106 seconds and about 3.03 GiB
sampled peak process-tree memory. A CUDA FP16 warm 100-item pass took 1.269
seconds on an RTX 4090. Neither result measures an everyday laptop; CPU Laya
currently misses the proposed three-second attention-cycle target by a wide
margin. Co-resident 27B reasoning also leaves narrow 4090 VRAM headroom. Run
teacher labeling and student training sequentially, never assume both fit during
training, and leave unrelated GPU workloads untouched.

The [expert-label contract](../src/systemsense/evaluation/attention_labels.py)
is presently a collection schema, not a dataset: **no admitted real reviewed
labels exist**. Its version 2 records bind a state, exact visible evidence,
candidate catalog and context digests, redaction review, observed probe outcomes,
and pseudonymous split keys. These hashes establish consistency, not reviewer
authenticity. The [replay evaluator](../src/systemsense/evaluation/attention_replay.py)
requires real human-expert labels and treats unexecuted probes as unknown, not
negative. Fixture journeys and synthetic benchmark cases cannot establish
diagnostic performance.

## Dataset and teacher protocol

1. Capture the `DecisionRequest` **before** choosing a probe. Freeze its schema,
   serializer/tokenizer versions, exact `visible_evidence_sha256`, exact
   `candidate_context_sha256`, registered catalog manifest digests, timestamps,
   evidence IDs, graph references, redaction attestation, and case origin. Store
   the redacted model-visible request separately from the identifier-only label.
   A later probe result must never leak into the earlier request.
2. Run authorized read-only probes, record their actual post-snapshot evidence,
   failure/denial/timeout outcomes, and limitations. Blinded IT reviewers judge
   which **observed** probes were informative and which observed probes were
   uninformative. Preserve abstention and disagreements. An unrun candidate is
   unknown. Authenticate reviewer identity before treating a label as admitted.
3. On **training-pool snapshots only**, first test a verified, unmodified local
   [Qwen3.5-4B](https://huggingface.co/Qwen/Qwen3.5-4B) against real reviewed
   outcomes, with sampled [Qwen3.8-27B](https://huggingface.co/Qwen/Qwen3.8-27B)
   disagreement checks. Ask the admitted teacher to return a bounded
   ranking of the registered candidate IDs, reasons citing visible evidence
   IDs, and an explicit abstain/uncertainty option. Pin the exact teacher
   artifact, quantization, runtime, prompt, generation settings, request hash,
   output, and parse/validation status. Reject invented IDs, post-snapshot facts,
   or unsupported claims. Keep this in a separate `teacher_suggestion` provenance
   lane; it must never be cast to `ExpertAttentionLabel` or enter held-out labels.
   The teacher may help prioritize reviewer effort and supply soft targets only
   on training examples after a separate audit of teacher bias and disagreement.
4. Assign train/development/final-test groups before teacher generation or
   model tuning. Enforce disjoint case, machine, application and version, and
   fault-family groups using `validate_group_splits`; deduplicate paraphrases,
   repeated snapshots, VM clones, and near-identical injected faults. Keep one
   final test sealed. Version the assignment and audit overlap after every data
   refresh. Report each domain and missing/denied/healthy case, not only pooled
   accuracy.

The selected Qwen model cards and Laya's card list Apache-2.0, but each downloaded
artifact, training source, and redistributed derivative still needs a pinned
license/revision review. Do not ship raw case text, credentials, device IDs, or
customer data in a checkpoint or example corpus. Run local redaction and human
privacy review before teacher inference or training; use access-controlled local
exports with retention/deletion records. A local model is not a privacy control
by itself. Do not send case content to cloud inference or public datasets.

## Reproducible candidate sequence

Pre-register data manifest, seeds, splits, optimizer/loss, stopping rule, and
primary metric before a training run. Record source commit, Python/CUDA/library
versions, teacher and student hashes, checkpoint hashes, hardware, wall time,
power if available, and every failed attempt. Do not select a winner by the
sealed final-test result and then retest that same set as if untouched.

| Candidate | Training action | Reason to continue |
| --- | --- | --- |
| Keyword and typed-feature | No fitting; replay the same frozen requests. | Transparent latency and quality floors. |
| Pinned Laya | No fitting; current serializer and worker. | Measures whether tuning is necessary. |
| Frozen-encoder Laya | Freeze ModernBERT, train the custom head/scorer on reviewer-observed pairwise useful-over-uninformative probes; mask unknown candidates. Compare teacher-soft-target regularization only as a separate ablation. | Cheapest way to adapt ranking without moving 421M encoder weights. |
| Laya LoRA + head | If head-only passes safety but misses utility, adapt only the encoder attention `Wqkv` and `Wo` projections plus the custom head, with the same masked objective and early stopping. Validate exact module names and trainable parameter list against the pinned runtime first. | More capacity, but greater overfit and device cost. |
| Compact challenger | Train or select a smaller ranker on the same redacted request and reviewer labels. | Ordinary-laptop path if 421M Laya cannot satisfy latency/RAM without reducing useful coverage. |

ModernBERT's pinned
[attention implementation](https://raw.githubusercontent.com/huggingface/transformers/v5.17.0/src/transformers/models/modernbert/modeling_modernbert.py)
names the encoder projections `Wqkv` and `Wo`; [PEFT's LoRA API](https://huggingface.co/docs/peft/v0.21.0/package_reference/lora)
supports explicit target modules. Because Laya wraps its encoder in a custom
`DecisionModel`, the experiment must assert the matched projection count,
frozen/trainable parameter list, saved adapter **and** saved custom head, and
reload parity before any result is accepted. Do not silently train a generic
sequence-classification head or accidentally adapt the MLP's separate `Wo`
projection. Treat Laya scores as ordinal, never calibrated
root-cause probabilities.

## Evaluation and promotion gates

Evaluate every candidate on **identical** frozen requests with the existing
`evaluate_attention_replay` binding. Report useful-probe recall@1/@3 and
negative-control top-k selections with explicit denominators, unsupported IDs,
adjudicated-candidate fraction, abstain behavior, coverage/truncation, and
case-group uncertainty intervals. Replay records matched *observed* probe
outcome times; it cannot estimate the counterfactual time a different ranking
would have saved. Add prospective, independently scored VM episodes to measure
supported diagnosis, time-to-supported-evidence, false confidence, and safety.

The current disposable VM is not a performance benchmark: a powered-off,
network-disconnected clean snapshot now exists and one boot confirmed Guest
Additions 7.2.14, but guest login, snapshot restore/readback, and an independent
affected-task oracle remain unverified. First qualify
those prerequisites, then use [the episode plan](NEXT_STEPS.md) with frozen
versions, randomized matched trials, negative controls, and all failed runs in
the denominator. Physical Wi-Fi and gaming need separate rigs and oracles; VM
results cannot qualify those claims.

Promotion requires all of the following, with thresholds and statistical
method fixed **before** viewing the sealed test:

- No unsupported probe execution, policy bypass, provenance loss, or increase
  in unsafe/overconfident answers; deterministic fallback still works after
  model failure, timeout, cancellation, and low-memory admission.
- Useful-probe selection and supported diagnosis are at least non-inferior to
  both deterministic features and pinned Laya on held-out case groups, with an
  explicitly chosen margin and uncertainty interval. Improvement in one family
  may not hide regressions in healthy/external/denied cases. Report reviewer
  coverage; do not score unknown candidates as negatives.
- On representative 8 GiB CPU and 16 GiB iGPU laptops, measure cold startup,
  warm p50/p95 full-request latency, RAM/VRAM, power, and foreground-task
  interference. The proposed fast-attention target is warm p95 at most three
  seconds **without** dropping evidence or candidates. If Laya fails, prefer the
  qualified smaller ranker or deterministic provider; a 4090 result is not a
  laptop claim.
- Versioned artifact and manifest verification, rollback to the previous
  provider, and side-by-side shadow evaluation before live selection. Preserve
  redacted request/evidence hashes and outcome provenance in every comparison.

If there are too few diverse reviewed labels to estimate the gate, the result is
**not yet qualified**, not a permissive pass. A trained checkpoint remains in
quarantine until these gates pass. Retraining needs a fresh held-out assignment
or a new sealed test; regression triggers rollback, not weaker criteria.

## Training resource envelope, not a performance promise

If a genuinely reviewed corpus later reaches about 30,000 question instances,
the following is only a planning range for four FP16 epochs with sequences at
most 1,024 tokens and microbatches of 1–4 on an otherwise idle RTX 4090. It is
**not** a measured run or a commitment to train on synthetic labels.

| Experiment | Planning peak VRAM | Planning wall time | Stop rule |
| --- | --- | --- | --- |
| Frozen encoder, custom head | 6–12 GiB | 2–8 hours | Stop if a 100-step pilot exceeds the verified memory/throughput budget or misses quality gates. |
| LoRA rank 8/16 on selected encoder attention projections plus custom head | 12–22 GiB | 4–16 hours | Try only if head-only is safe but misses held-out utility; require activation checkpointing and reload parity. |

These broad ranges are architectural estimates, not results. The 100-step
pilot must measure peak allocated VRAM, throughput, loss stability, and
checkpoint/reload equality before allocating a full run. The exact pinned
Laya `DecisionModel` input sequence (token IDs, marker positions, masks,
question order and truncation) must match the worker's reported construction
on representative examples; hashes of self-reported metadata cannot prove
that parity. Training belongs on the desktop or a qualified training host,
while 8/16 GiB laptops need separate *inference* qualification. With zero
admitted real Windows labels, expected diagnostic improvement is unknown.

## Immediate work order

1. Extend the sampled worker-token parity check to the exact exported training
   serializer, cache origin, every truncation branch, and verified installed
   source identity before making any example trainable. The hash-only trace and
   preworker projection remain provenance, not proof of arbitrary-case token IDs.
   Bind an authenticated reviewer registry and per-case consent provider to the
   existing fail-closed export preparation; never replace them with a fixture.
2. Keep local teacher drafts quarantined from expert labels. Audit 4B, 9B, and
   sampled 27B suggestions against genuinely reviewed outcomes before choosing
   a bulk teacher; reject prompt leakage and unrun-candidate negatives.
3. Qualify VM guest access, snapshot restore/readback, and the independent
   affected-task oracle, then collect diverse real
   reviewed investigation episodes before starting a model fit.
4. Run baseline, frozen-head, LoRA, and compact-ranker experiments in that
   order, stopping candidates that fail a safety/quality/resource gate. Publish
   complete scorecards including failures and limits, not a single accuracy
   number.
