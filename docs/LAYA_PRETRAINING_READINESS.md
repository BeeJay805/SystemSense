# Laya frozen-head pretraining preflight (v1)

This is a **blocked experiment configuration**, not a trainer, training
authorization, quality result, or model recommendation. The executable preflight
is `systemsense.evaluation.laya_training_readiness`. It reads only a caller-supplied
local JSON manifest and six pinned local files; it does not import a trainer,
open model weights, start inference, change a case, or write an artifact.

First freeze and record the manifest digest outside this tool. Later, run the
exact local file with that previously recorded digest (do not recompute it in
the same preflight invocation, because that would hide intervening edits):

```powershell
.venv\Scripts\python.exe -m systemsense.evaluation.laya_training_readiness --manifest C:\path\to\experiment.json --manifest-sha256 "<previously-recorded-lowercase-sha256>"
```

Exit 1 and JSON `status=BLOCKED` mean the manifest is valid but training is
unavailable. Exit 2 and `status=ERROR` mean its exact identity or schema could
not be validated. There is no `READY` state in v1. This prevents an arbitrary
JSON `training_admissible=true` from authorizing training.

## Required versioned manifest

`schema_version` must be `1` and `experiment` must be
`laya_frozen_encoder_custom_head`. The six `artifacts` are `corpus`,
`split_ledger`, `parity_report`, `reviewer_oracle`, `model_install`, and
`serializer_source`. Each has an **absolute local** `path` and a lowercase
64-character `sha256` digest. All fields are required and unknown fields are
rejected. The preflight caps the manifest at 64 KiB, corpus at 16 MiB, metadata
files at 1 MiB, and serializer Python source at 2 MiB. Symlink and non-file
paths are rejected. No URL or model-weight path is an artifact type.

The `model` identity is pinned to Laya package wheel
`4c57f64cbaf893bb5c7b4affddc2bf21a819f55df51941689f11868583be2903`,
repository `convaiinnovations/laya-typed-decisions`, revision
`f9ab0b228f0fc0f14d873dbc99038f135c2da1b2`, and documented weight digest
`4fa56de72383a9d3efa9cfa78955733c81b9fc8067a587ca4beb82c78107a24e`.
The model-install JSON must echo these identifiers to avoid silent substitution,
but this CLI **does not independently hash weights** and reports that limit.

`objective` fixes `masked_pairwise_logistic`, `custom_head_only`, positives as
`observed_informative`, negatives as `observed_uninformative`,
`unknown_masked=true`, and `teacher_drafts_as_gold=false`. Unknown or unrun
alternatives never become negatives. `evaluation` preregisters
`useful_probe_recall_at_1` as the primary metric, useful recall@3, negative
control top-3 rate, unsupported ID rate, abstention, adjudicated fraction,
coverage/truncation, all three keyword/typed-feature/pinned-Laya baselines,
case-group bootstrap 95% uncertainty, a noninferiority margin of 0–5 percentage
points, an adjudicated fraction floor of at least 0.95, an unsupported-ID
ceiling of zero, a negative-control top-3 ceiling at most 0.05, and warm p95
attention-cycle ceiling at most 3000 ms. These numbers are experiment gates,
**not measured results**.

`splits` fixes distinct train, development, and sealed-test roles; calibration
uses only development, and incident, machine, version, and fault-family groups
are held out. `seeds` requires at least three unique nonnegative integers.
`resources` caps the initial pilot at 100 steps, 4 epochs, 1024 tokens,
microbatch 4, 12 GiB VRAM, 32 GiB RAM, and 480 wall minutes. These are upper
bounds for a future authorized idle-device pilot, not a reservation or promise
that the model will fit. `stop_rules` must include nonfinite loss, OOM, parity
mismatch, unknown-mask leakage, unsafe proposals, held-out regression, and
resource-cap breach.

## Why it is blocked today

The current `PilotCorpus` is a fixture-custody artifact with unknown candidate
utility, `training_admissible=false`, and no authentic independent reviewer
labels. The existing split ledger is metadata-only; parity checks are synthetic
or limited worker-boundary probes rather than complete corpus/worker parity.
The CLI cannot authenticate reviewer independence, sealed split custody, or
model-weight identity from self-asserted local JSON. There is no approved trainer
or fit executor. Each deficiency is a named `BLOCKED` reason. The next change
must add independent, auditable admission evidence and tests before any state
could transition to `READY`; do not change this tool merely to suppress a
reason. Follow [LAYA_TRAINING_PLAN.md](LAYA_TRAINING_PLAN.md) for the gates and
held-out evaluation sequence.
