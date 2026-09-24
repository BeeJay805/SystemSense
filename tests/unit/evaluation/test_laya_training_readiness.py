"""Fail-closed preflight for the proposed frozen-encoder Laya experiment."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from systemsense.evaluation.laya_training_readiness import assess_manifest, main
from systemsense.evaluation.pilot_fixture import write_fixture_corpus


def _pin(path: Path) -> dict[str, str]:
    return {"path": str(path.resolve()), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def _manifest(tmp_path: Path) -> Path:
    pilot = tmp_path / "pilot"
    write_fixture_corpus(pilot)
    pins: dict[str, dict[str, str]] = {}
    for name, payload in {
        "split_ledger": {"schema_version": 1, "training_admissible": False},
        "parity_report": {"qualification_scope": "synthetic_serializer_parity_only"},
        "reviewer_oracle": {"verified": False},
        "model_install": {"verification": "metadata_only"},
    }.items():
        path = tmp_path / f"{name}.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        pins[name] = _pin(path)
    serializer = tmp_path / "serializer.py"
    serializer.write_text("# synthetic serializer fixture\n", encoding="utf-8")
    pins["serializer_source"] = _pin(serializer)
    pins["corpus"] = _pin(pilot / "corpus.json")
    spec = {
        "schema_version": 1,
        "experiment": "laya_frozen_encoder_custom_head",
        "artifacts": pins,
        "model": {
            "repository": "convaiinnovations/laya-typed-decisions",
            "revision": "f9ab0b228f0fc0f14d873dbc99038f135c2da1b2",
            "wheel_sha256": "4c57f64cbaf893bb5c7b4affddc2bf21a819f55df51941689f11868583be2903",
            "weight_sha256": "4fa56de72383a9d3efa9cfa78955733c81b9fc8067a587ca4beb82c78107a24e",
        },
        "objective": {
            "loss": "masked_pairwise_logistic",
            "trainable": "custom_head_only",
            "positive": "observed_informative",
            "negative": "observed_uninformative",
            "unknown_masked": True,
            "teacher_drafts_as_gold": False,
        },
        "evaluation": {
            "primary_metric": "useful_probe_recall_at_1",
            "secondary_metrics": [
                "useful_probe_recall_at_3",
                "negative_control_top3_rate",
                "unsupported_id_rate",
                "abstention_rate",
                "adjudicated_fraction",
                "coverage_and_truncation",
            ],
            "baseline_ids": ["keyword", "typed_feature", "pinned_laya"],
            "noninferiority_margin_pp": 2.0,
            "minimum_adjudicated_fraction": 0.95,
            "maximum_unsupported_id_rate": 0.0,
            "maximum_negative_control_top3_rate": 0.01,
            "warm_p95_ms": 3000,
            "uncertainty": "case_group_bootstrap_95pct",
        },
        "splits": {
            "train": "train",
            "development": "development",
            "calibration": "development",
            "sealed_test": "sealed_test",
            "holdout_groups": ["incident", "machine", "version", "fault_family"],
        },
        "seeds": [11, 23, 37],
        "resources": {
            "pilot_steps": 100,
            "maximum_epochs": 4,
            "maximum_sequence_tokens": 1024,
            "maximum_microbatch": 4,
            "maximum_peak_vram_gib": 12,
            "maximum_peak_ram_gib": 32,
            "maximum_wall_minutes": 480,
        },
        "stop_rules": [
            "nonfinite_loss",
            "out_of_memory",
            "parity_mismatch",
            "unknown_mask_leak",
            "unsafe_proposal",
            "heldout_regression",
            "resource_cap_exceeded",
        ],
    }
    path = tmp_path / "experiment.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    return path


def test_fixture_corpus_remains_blocked_without_loading_models(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    report = assess_manifest(manifest, _pin(manifest)["sha256"])
    assert report["status"] == "BLOCKED"
    assert {"fixture_only", "corpus_not_trainable", "worker_parity_not_proven"} <= set(
        report["reasons"]
    )
    assert "independent_reviewer_oracle_not_verified" in report["reasons"]
    assert "trainer_not_implemented" in report["reasons"]


def test_artifact_tamper_is_blocked(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    digest = _pin(manifest)["sha256"]
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    Path(payload["artifacts"]["serializer_source"]["path"]).write_text("tampered")
    report = assess_manifest(manifest, digest)
    assert "serializer_source_digest_mismatch" in report["reasons"]


def test_exact_manifest_digest_required(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    with pytest.raises(ValueError, match="manifest_digest_mismatch"):
        assess_manifest(manifest, "0" * 64)


def test_missing_pinned_artifact_is_blocked(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    digest = _pin(manifest)["sha256"]
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    Path(payload["artifacts"]["parity_report"]["path"]).unlink()
    assert "parity_report_missing_or_unreadable" in assess_manifest(manifest, digest)["reasons"]


@pytest.mark.parametrize(
    ("section", "key", "value"),
    [
        ("objective", "unknown_masked", False),
        ("objective", "trainable", "encoder_and_head"),
        ("model", "revision", "unreviewed-revision"),
        ("splits", "calibration", "sealed_test"),
        ("evaluation", "maximum_unsupported_id_rate", 0.1),
        ("evaluation", "secondary_metrics", ["abstention_rate"]),
        ("resources", "maximum_peak_vram_gib", 24),
        (None, "seeds", [11, 11, 37]),
    ],
)
def test_unsafe_pre_registration_rejected(
    tmp_path: Path, section: str | None, key: str, value: object
) -> None:
    manifest = _manifest(tmp_path)
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    target = payload if section is None else payload[section]
    target[key] = value
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="invalid_pretraining_manifest"):
        assess_manifest(manifest, _pin(manifest)["sha256"])


def test_cli_outputs_blocked_json_and_nonzero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest = _manifest(tmp_path)
    code = main(["--manifest", str(manifest), "--manifest-sha256", _pin(manifest)["sha256"]])
    report = json.loads(capsys.readouterr().out)
    assert code == 1
    assert report["status"] == "BLOCKED"
    assert "artifacts" not in report
