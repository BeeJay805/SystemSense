"""Offline, read-only preflight for a proposed Laya frozen-head experiment.

This is not training admission. It intentionally imports no inference or trainer
module and cannot mark a candidate ready while independent gates are absent.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Literal, TypedDict, cast

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_ARTIFACT_LIMITS = {
    "corpus": (".json", 16 * 1024 * 1024),
    "split_ledger": (".json", 1024 * 1024),
    "parity_report": (".json", 1024 * 1024),
    "reviewer_oracle": (".json", 1024 * 1024),
    "model_install": (".json", 1024 * 1024),
    "serializer_source": (".py", 2 * 1024 * 1024),
}
_MODEL_REPOSITORY = "convaiinnovations/laya-typed-decisions"
_MODEL_REVISION = "f9ab0b228f0fc0f14d873dbc99038f135c2da1b2"
_WHEEL_SHA256 = "4c57f64cbaf893bb5c7b4affddc2bf21a819f55df51941689f11868583be2903"
_WEIGHT_SHA256 = "4fa56de72383a9d3efa9cfa78955733c81b9fc8067a587ca4beb82c78107a24e"
_REQUIRED_STOPS = frozenset(
    {
        "nonfinite_loss",
        "out_of_memory",
        "parity_mismatch",
        "unknown_mask_leak",
        "unsafe_proposal",
        "heldout_regression",
        "resource_cap_exceeded",
    }
)


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ArtifactPinV1(_Strict):
    path: str
    sha256: str

    @model_validator(mode="after")
    def validate_pin(self) -> ArtifactPinV1:
        if not Path(self.path).is_absolute() or not _SHA256.fullmatch(self.sha256):
            raise ValueError("artifact_requires_absolute_local_path_and_sha256")
        return self


class ArtifactSetV1(_Strict):
    corpus: ArtifactPinV1
    split_ledger: ArtifactPinV1
    parity_report: ArtifactPinV1
    reviewer_oracle: ArtifactPinV1
    model_install: ArtifactPinV1
    serializer_source: ArtifactPinV1


class ModelIdentityV1(_Strict):
    repository: Literal["convaiinnovations/laya-typed-decisions"]
    revision: Literal["f9ab0b228f0fc0f14d873dbc99038f135c2da1b2"]
    wheel_sha256: Literal["4c57f64cbaf893bb5c7b4affddc2bf21a819f55df51941689f11868583be2903"]
    weight_sha256: Literal["4fa56de72383a9d3efa9cfa78955733c81b9fc8067a587ca4beb82c78107a24e"]


class ObjectiveV1(_Strict):
    loss: Literal["masked_pairwise_logistic"]
    trainable: Literal["custom_head_only"]
    positive: Literal["observed_informative"]
    negative: Literal["observed_uninformative"]
    unknown_masked: Literal[True]
    teacher_drafts_as_gold: Literal[False]


class EvaluationV1(_Strict):
    primary_metric: Literal["useful_probe_recall_at_1"]
    secondary_metrics: tuple[str, ...]
    baseline_ids: tuple[str, ...]
    noninferiority_margin_pp: float = Field(ge=0, le=5)
    minimum_adjudicated_fraction: float = Field(ge=0.95, le=1)
    maximum_unsupported_id_rate: float = Field(ge=0, le=0)
    maximum_negative_control_top3_rate: float = Field(ge=0, le=0.05)
    warm_p95_ms: int = Field(gt=0, le=3000)
    uncertainty: Literal["case_group_bootstrap_95pct"]

    @model_validator(mode="after")
    def require_baselines(self) -> EvaluationV1:
        if set(self.baseline_ids) != {"keyword", "typed_feature", "pinned_laya"}:
            raise ValueError("all_three_baselines_required")
        if set(self.secondary_metrics) != {
            "useful_probe_recall_at_3",
            "negative_control_top3_rate",
            "unsupported_id_rate",
            "abstention_rate",
            "adjudicated_fraction",
            "coverage_and_truncation",
        }:
            raise ValueError("required_secondary_metrics_missing")
        return self


class SplitsV1(_Strict):
    train: Literal["train"]
    development: Literal["development"]
    calibration: Literal["development"]
    sealed_test: Literal["sealed_test"]
    holdout_groups: tuple[str, ...]

    @model_validator(mode="after")
    def require_group_holds(self) -> SplitsV1:
        if set(self.holdout_groups) != {"incident", "machine", "version", "fault_family"}:
            raise ValueError("incident_machine_version_family_holdouts_required")
        return self


class ResourcesV1(_Strict):
    pilot_steps: Literal[100]
    maximum_epochs: int = Field(gt=0, le=4)
    maximum_sequence_tokens: int = Field(gt=0, le=1024)
    maximum_microbatch: int = Field(gt=0, le=4)
    maximum_peak_vram_gib: float = Field(gt=0, le=12)
    maximum_peak_ram_gib: float = Field(gt=0, le=32)
    maximum_wall_minutes: int = Field(gt=0, le=480)


class PretrainingManifestV1(_Strict):
    schema_version: Literal[1]
    experiment: Literal["laya_frozen_encoder_custom_head"]
    artifacts: ArtifactSetV1
    model: ModelIdentityV1
    objective: ObjectiveV1
    evaluation: EvaluationV1
    splits: SplitsV1
    seeds: tuple[int, ...]
    resources: ResourcesV1
    stop_rules: tuple[str, ...]

    @model_validator(mode="after")
    def require_complete_registration(self) -> PretrainingManifestV1:
        if (
            len(self.seeds) < 3
            or len(set(self.seeds)) != len(self.seeds)
            or any(seed < 0 for seed in self.seeds)
        ):
            raise ValueError("at_least_three_unique_nonnegative_seeds_required")
        if frozenset(self.stop_rules) != _REQUIRED_STOPS:
            raise ValueError("complete_stop_rules_required")
        return self


def _read_exact(path: Path, maximum_bytes: int) -> bytes:
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise ValueError("not_a_regular_local_file")
    with path.open("rb") as stream:
        data = stream.read(maximum_bytes + 1)
    if len(data) > maximum_bytes:
        raise ValueError("file_size_cap_exceeded")
    return data


def _metadata(data: bytes) -> dict[str, object] | None:
    try:
        value: object = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict):
        return None
    mapping = cast("dict[object, object]", value)
    if not all(isinstance(key, str) for key in mapping):
        return None
    return cast("dict[str, object]", mapping)


class ReadinessReportV1(TypedDict):
    schema_version: int
    status: Literal["BLOCKED"]
    manifest_sha256: str
    reasons: list[str]


def assess_manifest(path: Path, expected_sha256: str) -> ReadinessReportV1:
    """Validate exact local inputs; never authorize a fit or read model weights."""

    if not _SHA256.fullmatch(expected_sha256):
        raise ValueError("invalid_manifest_sha256")
    raw = _read_exact(path, 64 * 1024)
    actual = hashlib.sha256(raw).hexdigest()
    if actual != expected_sha256:
        raise ValueError("manifest_digest_mismatch")
    try:
        manifest = PretrainingManifestV1.model_validate_json(raw)
    except ValidationError as exc:
        raise ValueError("invalid_pretraining_manifest") from exc

    reasons: set[str] = {"trainer_not_implemented", "independent_training_admission_missing"}
    payloads: dict[str, bytes] = {}
    for kind, (suffix, maximum) in _ARTIFACT_LIMITS.items():
        pin = getattr(manifest.artifacts, kind)
        artifact = Path(pin.path)
        if artifact.suffix.lower() != suffix:
            reasons.add(f"{kind}_invalid_file_type")
            continue
        try:
            data = _read_exact(artifact, maximum)
        except (OSError, ValueError):
            reasons.add(f"{kind}_missing_or_unreadable")
            continue
        if hashlib.sha256(data).hexdigest() != pin.sha256:
            reasons.add(f"{kind}_digest_mismatch")
            continue
        payloads[kind] = data

    corpus = _metadata(payloads["corpus"]) if "corpus" in payloads else None
    if corpus is None:
        reasons.add("corpus_schema_unverified")
    else:
        if corpus.get("classification") == "candidate_custody_pilot_only":
            reasons.add("fixture_only")
        if corpus.get("training_admissible") is not True:
            reasons.add("corpus_not_trainable")
        # A self-asserted true bit would not constitute independent admission.
        reasons.add("corpus_review_provenance_not_independently_verified")

    split = _metadata(payloads["split_ledger"]) if "split_ledger" in payloads else None
    if split is None or split.get("training_admissible") is not True:
        reasons.add("split_ledger_not_training_admissible")
    reasons.add("sealed_split_identity_not_independently_verified")

    parity = _metadata(payloads["parity_report"]) if "parity_report" in payloads else None
    if parity is None or parity.get("qualification_scope") != "complete_corpus_worker_parity":
        reasons.add("worker_parity_not_proven")
    reasons.add("worker_parity_not_independently_verified")

    # A pinned local JSON file alone cannot authenticate an independent reviewer.
    reasons.add("independent_reviewer_oracle_not_verified")
    # The install metadata is hashed, but this CLI does not open the model weights.
    reasons.add("model_weight_bytes_not_verified_by_preflight")
    install = _metadata(payloads["model_install"]) if "model_install" in payloads else None
    if install is None or any(
        install.get(key) != expected
        for key, expected in (
            ("repository", _MODEL_REPOSITORY),
            ("revision", _MODEL_REVISION),
            ("wheel_sha256", _WHEEL_SHA256),
            ("weight_sha256", _WEIGHT_SHA256),
        )
    ):
        reasons.add("model_install_metadata_not_verified")

    return {
        "schema_version": 1,
        "status": "BLOCKED",
        "manifest_sha256": actual,
        "reasons": sorted(reasons),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline Laya training preflight; never trains")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        report = assess_manifest(args.manifest, args.manifest_sha256)
    except (OSError, ValueError) as exc:
        print(json.dumps({"schema_version": 1, "status": "ERROR", "reason": str(exc)}))
        return 2
    print(json.dumps(report, sort_keys=True))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
